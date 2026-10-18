//! Windows process/handle ownership. Unsafe calls stay inside this adapter.
use crate::{wire, WorkerError, MAX_COMMITTED_MEMORY_BYTES, MAX_CPU_SECONDS, OPERATION_TIMEOUT};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox};
use std::{
    fs::File,
    io::{Read, Write},
    mem::{size_of, size_of_val, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
    System::{
        ErrorReporting::{
            WerGetFlags, WerSetFlags, WER_FAULT_REPORTING_FLAG_NOHEAP, WER_FAULT_REPORTING_NO_UI,
        },
        JobObjects::*,
        Pipes::CreatePipe,
        Threading::*,
    },
};

const LIMITS: u32 = JOB_OBJECT_LIMIT_PROCESS_MEMORY
    | JOB_OBJECT_LIMIT_PROCESS_TIME
    | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
    | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
type Frame = SecretBox<Vec<u8>>;
type Completion = (File, Result<Option<Frame>, WorkerError>);

pub(crate) struct Process {
    child: Option<OwnedHandle>,
    job: OwnedHandle,
    input: Option<File>,
    output: Option<File>,
    pending: Option<JoinHandle<Completion>>,
}

fn required_limits() -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
            PerProcessUserTimeLimit: (MAX_CPU_SECONDS * 10_000_000) as i64,
            LimitFlags: LIMITS,
            ActiveProcessLimit: 1,
            ..Default::default()
        },
        ProcessMemoryLimit: MAX_COMMITTED_MEMORY_BYTES as usize,
        ..Default::default()
    }
}

fn owned(handle: HANDLE) -> Result<OwnedHandle, WorkerError> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(WorkerError::Unavailable);
    }
    // SAFETY: only freshly created, exclusively owned Win32 handles reach here.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn checked(result: i32) -> Result<(), WorkerError> {
    if result == 0 {
        Err(WorkerError::Unavailable)
    } else {
        Ok(())
    }
}

fn pipe(attributes: &SECURITY_ATTRIBUTES) -> Result<(OwnedHandle, OwnedHandle), WorkerError> {
    let (mut read, mut write) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: writable outputs and a live security-attributes structure.
    checked(unsafe { CreatePipe(&mut read, &mut write, attributes, 0) })?;
    Ok((owned(read)?, owned(write)?))
}

struct Attributes(Vec<usize>);
impl Attributes {
    fn new(handles: &[HANDLE]) -> Result<Self, WorkerError> {
        let mut bytes = 0;
        // SAFETY: the first call only obtains the allocation size.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut bytes) };
        if bytes == 0 || bytes > 64 * 1024 {
            return Err(WorkerError::Unavailable);
        }
        let mut buffer = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        // SAFETY: aligned, stable storage covers the queried byte count.
        checked(unsafe {
            InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), 1, 0, &mut bytes)
        })?;
        let mut this = Self(buffer);
        // SAFETY: the handles array is kept alive through CreateProcess and the
        // attribute-list destruction; Windows does not take ownership of it.
        checked(unsafe {
            UpdateProcThreadAttribute(
                this.0.as_mut_ptr().cast(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                size_of_val(handles),
                ptr::null_mut(),
                ptr::null(),
            )
        })?;
        Ok(this)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: initialized once above, destroyed once before storage is freed.
        unsafe { DeleteProcThreadAttributeList(self.0.as_mut_ptr().cast()) };
    }
}

impl Process {
    pub(crate) fn spawn(executable: &Path) -> Result<Self, WorkerError> {
        let mut image = executable.as_os_str().encode_wide().collect::<Vec<_>>();
        if image.contains(&0) {
            return Err(WorkerError::InvalidInput);
        }
        image.push(0);
        let mut command = "firmica-key-worker --stdio\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        // SAFETY: unnamed, non-inheritable job; no externally selectable object.
        let job = owned(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })?;
        let limits = required_limits();
        // SAFETY: a valid job handle and correctly sized input structure.
        checked(unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of_val(&limits) as u32,
            )
        })?;
        let security = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: 1,
        };
        let (child_input, input) = pipe(&security)?;
        let (output, child_output) = pipe(&security)?;
        for handle in [&input, &output] {
            // SAFETY: these parent pipe ends must not survive in the child.
            checked(unsafe {
                SetHandleInformation(handle.as_raw_handle(), HANDLE_FLAG_INHERIT, 0)
            })?;
        }
        let null_name = "NUL\0".encode_utf16().collect::<Vec<_>>();
        // SAFETY: fixed NUL device, writable security attributes, no template.
        let error = owned(unsafe {
            CreateFileW(
                null_name.as_ptr(),
                0x40000000,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &security,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        })?;
        let handles = [
            child_input.as_raw_handle(),
            child_output.as_raw_handle(),
            error.as_raw_handle(),
        ];
        let mut attributes = Attributes::new(&handles)?;
        // SAFETY: Win32 startup/process structures permit zero initialization.
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
        startup.lpAttributeList = attributes.0.as_mut_ptr().cast();
        let mut information: PROCESS_INFORMATION = unsafe { zeroed() };
        // SAFETY: the application path and fixed command are terminated UTF-16;
        // startup, attribute list and exactly three inherited handles stay live.
        checked(unsafe {
            CreateProcessW(
                image.as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
                ptr::null(),
                ptr::null(),
                &startup.StartupInfo,
                &mut information,
            )
        })?;
        let child = owned(information.hProcess)?;
        let thread = owned(information.hThread)?;
        let process = Self {
            child: Some(child),
            job,
            input: Some(input.into()),
            output: Some(output.into()),
            pending: None,
        };
        let result = (|| {
            // SAFETY: the child cannot execute until its primary thread resumes.
            // Job assignment failure is fatal, including incompatible outer jobs.
            checked(unsafe {
                AssignProcessToJobObject(process.job.as_raw_handle(), process.child_handle()?)
            })?;
            if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
                return Err(WorkerError::Unavailable);
            }
            Ok(())
        })();
        drop(thread);
        // These inherited copies must close in the parent before any pipe I/O.
        drop(child_input);
        drop(child_output);
        drop(error);
        drop(attributes);
        match result {
            Ok(()) => Ok(process),
            Err(error) => Err(process.abort(error)),
        }
    }

    fn child_handle(&self) -> Result<HANDLE, WorkerError> {
        self.child
            .as_ref()
            .map(AsRawHandle::as_raw_handle)
            .ok_or(WorkerError::Unavailable)
    }

    pub(crate) fn send(&mut self, frame: &Frame, deadline: Instant) -> Result<(), WorkerError> {
        let mut input = self.input.take().ok_or(WorkerError::Unavailable)?;
        let frame = SecretBox::new(Box::new(frame.expose_secret().to_vec()));
        self.pending = Some(
            thread::Builder::new()
                .spawn(move || {
                    let payload = frame.expose_secret();
                    let result = u32::try_from(payload.len())
                        .map_err(|_| WorkerError::InvalidInput)
                        .and_then(|length| {
                            input
                                .write_all(&length.to_be_bytes())
                                .and_then(|_| input.write_all(payload))
                                .map_err(|_| WorkerError::Unavailable)
                        });
                    (input, result.map(|_| None))
                })
                .map_err(|_| WorkerError::Unavailable)?,
        );
        let (input, result) = self.complete(deadline)?;
        self.input = Some(input);
        result.map(|_| ())
    }

    pub(crate) fn receive(&mut self, deadline: Instant) -> Result<Frame, WorkerError> {
        let mut output = self.output.take().ok_or(WorkerError::Unavailable)?;
        self.pending = Some(
            thread::Builder::new()
                .spawn(move || {
                    let result = (|| {
                        let mut length = [0; 4];
                        output
                            .read_exact(&mut length)
                            .map_err(|_| WorkerError::Unavailable)?;
                        let length = u32::from_be_bytes(length) as usize;
                        if length == 0 || length > wire::MAX_REPLY_BYTES {
                            return Err(WorkerError::Protocol);
                        }
                        let mut payload = SecretBox::new(Box::new(vec![0; length]));
                        output
                            .read_exact(payload.expose_secret_mut())
                            .map_err(|_| WorkerError::Unavailable)?;
                        Ok(Some(payload))
                    })();
                    (output, result)
                })
                .map_err(|_| WorkerError::Unavailable)?,
        );
        let (output, result) = self.complete(deadline)?;
        self.output = Some(output);
        result?.ok_or(WorkerError::Protocol)
    }

    fn complete(&mut self, deadline: Instant) -> Result<Completion, WorkerError> {
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(WorkerError::TimedOut)?;
            if self
                .pending
                .as_ref()
                .ok_or(WorkerError::Unavailable)?
                .is_finished()
            {
                break;
            }
            thread::sleep(remaining.min(Duration::from_millis(5)));
        }
        self.pending
            .take()
            .ok_or(WorkerError::Unavailable)?
            .join()
            .map_err(|_| WorkerError::Unavailable)
    }

    fn wait(&self, deadline: Instant) -> Result<(), WorkerError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(WorkerError::TimedOut)?;
        let milliseconds = remaining
            .as_millis()
            .saturating_add(1)
            .min(u32::MAX as u128 - 1) as u32;
        // SAFETY: wait uses a live owned process handle and a finite timeout.
        match unsafe { WaitForSingleObject(self.child_handle()?, milliseconds) } {
            WAIT_OBJECT_0 => Ok(()),
            windows_sys::Win32::Foundation::WAIT_TIMEOUT => Err(WorkerError::TimedOut),
            _ => Err(WorkerError::CleanupFailed),
        }
    }

    pub(crate) fn finish(&mut self, deadline: Instant) -> Result<(), WorkerError> {
        self.input.take();
        self.output.take();
        self.wait(deadline)?;
        let mut status = 0;
        // SAFETY: the process has exited, and status is a writable DWORD.
        checked(unsafe { GetExitCodeProcess(self.child_handle()?, &mut status) })?;
        self.child.take();
        if status == 0 {
            Ok(())
        } else {
            Err(WorkerError::Unavailable)
        }
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
        if self.child.is_some() {
            // Terminate the process directly as well: job assignment may have
            // failed during suspended startup. Job close is the final safety net.
            unsafe {
                TerminateJobObject(self.job.as_raw_handle(), 1);
                TerminateProcess(self.child_handle()?, 1);
            }
            let deadline = Instant::now() + OPERATION_TIMEOUT;
            self.wait(deadline)
                .map_err(|_| WorkerError::CleanupFailed)?;
            self.child.take();
            if self.pending.is_some() {
                // Only the child inherited the opposite pipe ends, and the job
                // forbids descendants. Its death releases blocked native pipe I/O.
                drop(
                    self.complete(deadline)
                        .map_err(|_| WorkerError::CleanupFailed)?,
                );
            }
        }
        Ok(())
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

pub(crate) fn verify_controls() -> Result<(), WorkerError> {
    let mut actual = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    // SAFETY: NULL selects this process's immediate job; the output buffer is
    // correctly sized. A standalone or insufficiently controlled worker fails.
    checked(unsafe {
        QueryInformationJobObject(
            ptr::null_mut(),
            JobObjectExtendedLimitInformation,
            (&mut actual as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of_val(&actual) as u32,
            ptr::null_mut(),
        )
    })?;
    let expected = required_limits();
    if actual.BasicLimitInformation.LimitFlags & LIMITS != LIMITS
        || actual.BasicLimitInformation.LimitFlags
            & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
            != 0
        || actual.BasicLimitInformation.ActiveProcessLimit != 1
        || actual.BasicLimitInformation.PerProcessUserTimeLimit
            != expected.BasicLimitInformation.PerProcessUserTimeLimit
        || actual.ProcessMemoryLimit != expected.ProcessMemoryLimit
    {
        return Err(WorkerError::Unavailable);
    }
    let flags = WER_FAULT_REPORTING_FLAG_NOHEAP | WER_FAULT_REPORTING_NO_UI;
    // SAFETY: this dedicated worker changes only its own WER flags. These
    // requests do not override privileged debugging or machine dump policies.
    if unsafe { WerSetFlags(flags) } < 0 {
        return Err(WorkerError::Unavailable);
    }
    let mut actual = 0;
    if unsafe { WerGetFlags(GetCurrentProcess(), &mut actual) } < 0 || actual & flags != flags {
        return Err(WorkerError::Unavailable);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        process::{Command, Stdio},
    };
    use windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER;

    fn fixture(mode: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let source = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("examples/worker-fixture.exe");
        let executable = directory.path().join(format!("{mode}.exe"));
        fs::copy(&source, &executable)
            .expect("build the worker-fixture example before Windows worker tests");
        (directory, executable)
    }

    fn deadline() -> Instant {
        Instant::now() + OPERATION_TIMEOUT
    }

    fn exited(handle: &OwnedHandle) {
        // SAFETY: the duplicated handle remains valid even after process cleanup.
        assert_eq!(
            unsafe { WaitForSingleObject(handle.as_raw_handle(), 2000) },
            WAIT_OBJECT_0
        );
    }

    #[test]
    fn limits_precede_input_and_the_os_rejects_memory_and_descendants() {
        for mode in ["limits", "memory", "descendant"] {
            let (_directory, path) = fixture(mode);
            let mut process = Process::spawn(&path).unwrap();
            let response = process.receive(deadline()).unwrap();
            process.finish(deadline()).unwrap();
            match mode {
                "limits" => {
                    let data = response.expose_secret();
                    assert_eq!(data.len(), 24);
                    assert_eq!(
                        u64::from_be_bytes(data[..8].try_into().unwrap()),
                        256 * 1024 * 1024
                    );
                    assert_eq!(
                        i64::from_be_bytes(data[8..16].try_into().unwrap()),
                        50_000_000
                    );
                    assert_eq!(u32::from_be_bytes(data[16..20].try_into().unwrap()), 1);
                    assert_eq!(
                        u32::from_be_bytes(data[20..].try_into().unwrap()) & LIMITS,
                        LIMITS
                    );
                }
                "memory" => assert_eq!(response.expose_secret(), b"memory-denied"),
                "descendant" => assert_eq!(response.expose_secret(), b"descendant-denied"),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn deadlines_cover_silent_startup_and_blocked_writes_and_join_io() {
        for mode in ["silent", "blocked"] {
            let (_directory, path) = fixture(mode);
            let mut process = Process::spawn(&path).unwrap();
            let handle = process.child.as_ref().unwrap().try_clone().unwrap();
            let result = if mode == "silent" {
                process
                    .receive(Instant::now() + Duration::from_millis(150))
                    .map(|_| ())
            } else {
                assert_eq!(
                    process.receive(deadline()).unwrap().expose_secret(),
                    b"FRMKEY\x01"
                );
                process.send(
                    &SecretBox::new(Box::new(vec![0; 8 * 1024 * 1024])),
                    Instant::now() + Duration::from_millis(150),
                )
            };
            assert_eq!(result, Err(WorkerError::TimedOut));
            assert_eq!(process.abort(result.unwrap_err()), WorkerError::TimedOut);
            exited(&handle);
        }
    }

    #[test]
    fn malformed_replies_nonzero_exit_and_worker_loss_fail_closed() {
        for mode in ["malformed", "nonzero", "silent"] {
            let (_directory, path) = fixture(mode);
            let mut process = Process::spawn(&path).unwrap();
            let handle = process.child.as_ref().unwrap().try_clone().unwrap();
            let error = match mode {
                "malformed" => process.receive(deadline()).err().unwrap(),
                "nonzero" => {
                    assert_eq!(
                        process.receive(deadline()).unwrap().expose_secret(),
                        b"FRMKEY\x01"
                    );
                    process.finish(deadline()).unwrap_err()
                }
                "silent" => {
                    // SAFETY: terminate only our explicitly selected fixture.
                    assert_ne!(unsafe { TerminateProcess(handle.as_raw_handle(), 1) }, 0);
                    process.receive(deadline()).err().unwrap()
                }
                _ => unreachable!(),
            };
            let expected = if mode == "malformed" {
                WorkerError::Protocol
            } else {
                WorkerError::Unavailable
            };
            assert_eq!(process.abort(error), expected);
            exited(&handle);
        }
    }

    #[test]
    fn drop_and_cpu_exhaustion_terminate_the_native_process() {
        for mode in ["silent", "cpu"] {
            let (_directory, path) = fixture(mode);
            let process = Process::spawn(&path).unwrap();
            let handle = process.child.as_ref().unwrap().try_clone().unwrap();
            if mode == "cpu" {
                // No I/O deadline or explicit termination triggers this exit:
                // the kernel enforces the cumulative user CPU limit.
                process
                    .wait(Instant::now() + Duration::from_secs(20))
                    .unwrap();
                let mut status = 0;
                assert_ne!(
                    unsafe { GetExitCodeProcess(handle.as_raw_handle(), &mut status) },
                    0
                );
                assert_ne!(status, 0);
            }
            drop(process);
            exited(&handle);
        }
    }

    #[test]
    fn abandon_fixture() {
        let Ok(report) = std::env::var("FIRMICA_TEST_ABANDON_REPORT") else {
            return;
        };
        let executable = std::env::var_os("FIRMICA_TEST_ABANDON_WORKER").unwrap();
        let process = Process::spawn(Path::new(&executable)).unwrap();
        let pid = unsafe { GetProcessId(process.child_handle().unwrap()) };
        assert_ne!(pid, 0);
        fs::write(report, pid.to_string()).unwrap();
        // Intentionally bypass Rust Drop: only the OS job ownership remains.
        std::process::exit(0);
    }

    #[test]
    fn abrupt_parent_exit_closes_its_job_and_kills_the_worker() {
        let (directory, path) = fixture("silent");
        let report = directory.path().join("pid");
        let mut parent = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "process::tests::abandon_fixture", "--nocapture"])
            .env("FIRMICA_TEST_ABANDON_REPORT", &report)
            .env("FIRMICA_TEST_ABANDON_WORKER", path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let end = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = parent.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if Instant::now() >= end {
                parent.kill().unwrap();
                parent.wait().unwrap();
                panic!("parent fixture stalled");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let pid = fs::read_to_string(report).unwrap().parse().unwrap();
        let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
        if handle.is_null() {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(ERROR_INVALID_PARAMETER as i32)
            );
        } else {
            exited(&owned(handle).unwrap());
        }
    }
}
