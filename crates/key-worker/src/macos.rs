//! Darwin resource controls and parent-owned lifetime supervision.
use crate::{WorkerError, MAX_CPU_SECONDS, MAX_PHYSICAL_FOOTPRINT_BYTES};
use std::{
    io,
    process::{Child, ExitStatus},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc, Arc, Mutex, MutexGuard,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const INTERVAL: Duration = Duration::from_millis(50);
// Zero means healthy; other values record the violating footprint or this sentinel.
const ACCOUNTING_FAILURE: u64 = u64::MAX;

pub(crate) fn install_controls() -> Result<(), WorkerError> {
    use rustix::process::{setrlimit, Resource, Rlimit};
    for (resource, value) in [(Resource::Core, 0), (Resource::Cpu, MAX_CPU_SECONDS)] {
        setrlimit(
            resource,
            Rlimit {
                current: Some(value),
                maximum: Some(value),
            },
        )
        .map_err(|_| WorkerError::Unavailable)?;
    }
    // SAFETY: PT_DENY_ATTACH acts on the calling worker; the remaining arguments
    // are ignored by Darwin. This runs before credentials or imported keys exist.
    if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) } == -1 {
        return Err(WorkerError::Unavailable);
    }
    Ok(())
}

fn footprint(pid: u32) -> io::Result<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage_info_v0>::zeroed();
    // SAFETY: flavor V0 writes exactly rusage_info_v0 into this aligned buffer.
    let result = unsafe {
        libc::proc_pid_rusage(pid as i32, libc::RUSAGE_INFO_V0, usage.as_mut_ptr().cast())
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful query initialized the complete V0 result.
    Ok(unsafe { usage.assume_init() }.ri_phys_footprint)
}

pub(crate) struct SupervisedChild {
    child: Arc<Mutex<Child>>,
    failed: Arc<AtomicU64>,
    stop: mpsc::Sender<()>,
    monitor: Option<JoinHandle<()>>,
}

impl SupervisedChild {
    pub(crate) fn new(child: Child) -> Result<Self, WorkerError> {
        let child = Arc::new(Mutex::new(child));
        let failed = Arc::new(AtomicU64::new(0));
        let (stop, stopped) = mpsc::channel();
        let mut supervised = Self {
            child: child.clone(),
            failed: failed.clone(),
            stop,
            monitor: None,
        };
        // Confirm native accounting is available before the parent sends credentials.
        footprint(
            supervised
                .lock()
                .map_err(|_| WorkerError::Unavailable)?
                .id(),
        )
        .map_err(|_| WorkerError::Unavailable)?;
        supervised.monitor = Some(thread::Builder::new().name("key-worker-memory".into()).spawn(move || {
            loop {
                {
                    let Ok(mut child) = child.lock() else {
                        failed.store(ACCOUNTING_FAILURE, Ordering::Release);
                        return;
                    };
                    match child.try_wait() {
                        Ok(Some(_)) => return,
                        Ok(None) => {
                            let usage = if failed.load(Ordering::Acquire) != 0 { Err(io::Error::other("worker limit exceeded")) } else { footprint(child.id()) };
                            if usage.is_err() && matches!(child.try_wait(), Ok(Some(_))) { return; }
                            if !matches!(usage.as_ref(), Ok(bytes) if *bytes <= MAX_PHYSICAL_FOOTPRINT_BYTES) {
                                let _ = failed.compare_exchange(0, usage.unwrap_or(ACCOUNTING_FAILURE), Ordering::AcqRel, Ordering::Acquire);
                                // The Child remains owned and unreaped until termination, so
                                // its PID cannot be recycled underneath the accounting query.
                                let _ = child.kill();
                                // Reap on the next iteration without holding the mutex
                                // across a wait. Parent teardown can proceed concurrently.

                            }
                        }
                        Err(_) => {
                            failed.store(ACCOUNTING_FAILURE, Ordering::Release);
                            let _ = child.kill();
                            return;
                        }
                    }
                }
                match stopped.recv_timeout(INTERVAL) {
                    Err(mpsc::RecvTimeoutError::Timeout) => {},
                    _ => return,
                }
            }
        }).map_err(|_| WorkerError::Unavailable)?);
        Ok(supervised)
    }

    fn lock(&self) -> io::Result<MutexGuard<'_, Child>> {
        self.child
            .lock()
            .map_err(|_| io::Error::other("worker supervision failed"))
    }
    pub(crate) fn check(&self) -> Result<(), WorkerError> {
        if self.failed.load(Ordering::Acquire) != 0 {
            Err(WorkerError::Unavailable)
        } else {
            Ok(())
        }
    }
    pub(crate) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.lock()?.try_wait()
    }
    pub(crate) fn kill(&mut self) -> io::Result<()> {
        self.lock()?.kill()
    }
}

impl Drop for SupervisedChild {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(monitor) = self.monitor.take() {
            let _ = monitor.join();
        }
        if let Ok(mut child) = self.lock() {
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
                let deadline = std::time::Instant::now() + crate::OPERATION_TIMEOUT;
                while matches!(child.try_wait(), Ok(None)) && std::time::Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        process::{Command, Stdio},
        time::Instant,
    };

    #[test]
    fn control_probe() {
        let Ok(mode) = std::env::var("FIRMICA_WORKER_CONTROL_PROBE") else {
            return;
        };
        install_controls().unwrap();
        use rustix::process::{getrlimit, Resource};
        assert_eq!(getrlimit(Resource::Core).maximum, Some(0));
        assert_eq!(getrlimit(Resource::Cpu).maximum, Some(MAX_CPU_SECONDS));
        match mode.as_str() {
            "memory" => {
                let mut allocation = Vec::new();
                let mut block = vec![0u8; 1024 * 1024];
                for _ in 0..1024 {
                    // Virtual allocation size is not the supervised metric. Grow
                    // bounded, incompressible chunks until the watchdog kills us.
                    openssl::rand::rand_bytes(&mut block).unwrap();
                    allocation.extend_from_slice(&block);
                    std::hint::black_box(&allocation);
                    thread::sleep(Duration::from_millis(2));
                }
                thread::sleep(Duration::from_secs(30));
            }
            "cpu" => loop {
                std::hint::black_box(7u64.wrapping_mul(std::hint::black_box(9)));
            },
            "idle" => thread::sleep(Duration::from_secs(30)),
            "limits" => {}
            _ => panic!("unknown control probe"),
        }
    }

    fn probe(mode: &str) -> SupervisedChild {
        SupervisedChild::new(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "macos::tests::control_probe", "--nocapture"])
                .env("FIRMICA_WORKER_CONTROL_PROBE", mode)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn native_cpu_and_memory_controls_terminate_excess_use() {
        for mode in ["limits", "memory", "cpu"] {
            let mut child = probe(mode);
            let deadline = Instant::now() + crate::OPERATION_TIMEOUT;
            let mut peak = 0;
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if let Ok(bytes) = footprint(child.lock().unwrap().id()) {
                    peak = peak.max(bytes);
                }
                assert!(
                    Instant::now() < deadline,
                    "worker exceeded termination deadline: {mode}, peak footprint {peak} bytes"
                );
                thread::sleep(INTERVAL);
            };
            assert_eq!(status.success(), mode == "limits");
            if mode == "memory" {
                let violation = child.failed.load(Ordering::Acquire);
                assert!(
                    violation > MAX_PHYSICAL_FOOTPRINT_BYTES && violation != ACCOUNTING_FAILURE,
                    "expected a measured footprint violation, got {violation}"
                );
            } else {
                child.check().unwrap();
            }
        }
    }

    #[test]
    fn abandonment_reaps_an_idle_child_and_stops_supervision() {
        let child = probe("idle");
        thread::sleep(INTERVAL * 4);
        child
            .check()
            .expect("accounting must remain available after PT_DENY_ATTACH");
        let pid = child.lock().unwrap().id();
        drop(child);
        // SAFETY: signal zero only checks process existence; no signal is delivered.
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }
}
