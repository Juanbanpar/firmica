#[cfg(target_os = "macos")]
use crate::macos::SupervisedChild as Child;
use crate::{wire, WorkerError};
use rustix::{
    event::{poll, PollFd, PollFlags, Timespec},
    fs::{fcntl_getfl, fcntl_setfl, OFlags},
};
use secrecy::{ExposeSecret, SecretBox};
#[cfg(target_os = "linux")]
use std::process::Child;
use std::{
    io::{Read, Write},
    os::fd::AsFd,
    path::Path,
    process::{ChildStdin, ChildStdout, Command, Stdio},
    time::{Duration, Instant},
};

pub(crate) struct Process {
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
}

impl Process {
    pub(crate) fn spawn(executable: &Path) -> Result<Self, WorkerError> {
        let mut child = Command::new(executable)
            .arg("--stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| WorkerError::Unavailable)?;
        let input = child.stdin.take();
        let output = child.stdout.take();
        #[cfg(target_os = "macos")]
        let child = Child::new(child)?;
        let process = Self {
            child: Some(child),
            input,
            output,
        };
        let result = (|| {
            nonblocking(process.input.as_ref().ok_or(WorkerError::Unavailable)?)?;
            nonblocking(process.output.as_ref().ok_or(WorkerError::Unavailable)?)
        })();
        match result {
            Ok(()) => Ok(process),
            Err(error) => Err(process.abort(error)),
        }
    }

    pub(crate) fn send(
        &mut self,
        frame: &SecretBox<Vec<u8>>,
        deadline: Instant,
    ) -> Result<(), WorkerError> {
        self.check_controls()?;
        let input = self.input.as_mut().ok_or(WorkerError::Unavailable)?;
        let payload = frame.expose_secret();
        let length = u32::try_from(payload.len()).map_err(|_| WorkerError::InvalidInput)?;
        write_all(input, &length.to_be_bytes(), deadline)?;
        write_all(input, payload, deadline)?;
        self.check_controls()
    }

    pub(crate) fn receive(&mut self, deadline: Instant) -> Result<SecretBox<Vec<u8>>, WorkerError> {
        self.check_controls()?;
        let output = self.output.as_mut().ok_or(WorkerError::Unavailable)?;
        let mut length = [0; 4];
        read_exact(output, &mut length, deadline)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > wire::MAX_REPLY_BYTES {
            return Err(WorkerError::Protocol);
        }
        let mut payload = SecretBox::new(Box::new(vec![0; length]));
        read_exact(
            output,
            secrecy::ExposeSecretMut::expose_secret_mut(&mut payload),
            deadline,
        )?;
        self.check_controls()?;
        Ok(payload)
    }

    pub(crate) fn finish(&mut self, deadline: Instant) -> Result<(), WorkerError> {
        self.input.take();
        self.output.take();
        loop {
            self.check_controls()?;
            let child = self.child.as_mut().ok_or(WorkerError::Unavailable)?;
            if let Some(status) = child.try_wait().map_err(|_| WorkerError::CleanupFailed)? {
                self.check_controls()?;
                self.child.take();
                return if status.success() {
                    Ok(())
                } else {
                    Err(WorkerError::Unavailable)
                };
            }
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(WorkerError::TimedOut)?;
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
        }
    }

    fn check_controls(&self) -> Result<(), WorkerError> {
        #[cfg(target_os = "macos")]
        self.child
            .as_ref()
            .ok_or(WorkerError::Unavailable)?
            .check()?;
        Ok(())
    }

    pub(crate) fn abort(mut self, original: WorkerError) -> WorkerError {
        if self.terminate().is_err() {
            WorkerError::CleanupFailed
        } else {
            original
        }
    }

    fn terminate(&mut self) -> Result<(), WorkerError> {
        self.input.take();
        self.output.take();
        if let Some(child) = self.child.as_mut() {
            if child
                .try_wait()
                .map_err(|_| WorkerError::CleanupFailed)?
                .is_none()
            {
                // kill alone does not reap the child. Do not wait indefinitely if kill failed.
                if child.kill().is_err() && child.try_wait().ok().flatten().is_none() {
                    return Err(WorkerError::CleanupFailed);
                }
                let deadline = Instant::now() + crate::OPERATION_TIMEOUT;
                while child
                    .try_wait()
                    .map_err(|_| WorkerError::CleanupFailed)?
                    .is_none()
                {
                    if Instant::now() >= deadline {
                        return Err(WorkerError::CleanupFailed);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            self.child.take();
        }
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

fn nonblocking(fd: &impl AsFd) -> Result<(), WorkerError> {
    let flags = fcntl_getfl(fd).map_err(|_| WorkerError::Unavailable)?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK).map_err(|_| WorkerError::Unavailable)
}

fn wait(fd: &impl AsFd, events: PollFlags, deadline: Instant) -> Result<(), WorkerError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(WorkerError::TimedOut)?;
        let timeout = Timespec::try_from(remaining).map_err(|_| WorkerError::Unavailable)?;
        let mut descriptors = [PollFd::new(fd, events)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => return Err(WorkerError::TimedOut),
            Ok(_) => return Ok(()), // The next read/write diagnoses EOF, HUP or pipe errors.
            Err(rustix::io::Errno::INTR) => continue,
            Err(_) => return Err(WorkerError::Unavailable),
        }
    }
}

fn read_exact(
    input: &mut (impl Read + AsFd),
    mut buffer: &mut [u8],
    deadline: Instant,
) -> Result<(), WorkerError> {
    while !buffer.is_empty() {
        if Instant::now() >= deadline {
            return Err(WorkerError::TimedOut);
        }
        match input.read(buffer) {
            Ok(0) => return Err(WorkerError::Unavailable),
            Ok(count) => buffer = &mut buffer[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait(input, PollFlags::IN, deadline)?
            }
            Err(_) => return Err(WorkerError::Unavailable),
        }
    }
    Ok(())
}

fn write_all(
    output: &mut (impl Write + AsFd),
    mut buffer: &[u8],
    deadline: Instant,
) -> Result<(), WorkerError> {
    while !buffer.is_empty() {
        if Instant::now() >= deadline {
            return Err(WorkerError::TimedOut);
        }
        match output.write(buffer) {
            Ok(0) => return Err(WorkerError::Unavailable),
            Ok(count) => buffer = &buffer[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait(output, PollFlags::OUT, deadline)?
            }
            Err(_) => return Err(WorkerError::Unavailable),
        }
    }
    Ok(())
}
