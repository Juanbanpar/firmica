#![allow(dead_code)]
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned()
}

pub fn output(command: &mut Command, seconds: u64) -> Output {
    try_output(command, seconds).unwrap_or_else(|error| panic!("{command:?}: {error}"))
}

pub fn try_output(command: &mut Command, seconds: u64) -> std::io::Result<Output> {
    eprintln!("+ {command:?}");
    let mut child = Process(
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let mut stdout = child.0.stdout.take().unwrap();
    let mut stderr = child.0.stderr.take().unwrap();
    let out = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes)?;
        Ok::<_, std::io::Error>(bytes)
    });
    let err = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes)?;
        Ok::<_, std::io::Error>(bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("timed out after {seconds}s"),
            ));
        }
        thread::sleep(Duration::from_millis(50));
    };
    Ok(Output {
        status,
        stdout: out.join().unwrap()?,
        stderr: err.join().unwrap()?,
    })
}

pub fn checked(command: &mut Command, seconds: u64) -> String {
    let result = output(command, seconds);
    assert!(
        result.status.success(),
        "{command:?}: {}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

pub fn wait_for<T>(seconds: u64, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        if let Some(value) = check() {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "native invocation check timed out"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

pub struct Process(pub Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn sha256(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}

pub fn report(path: &Path, value: &serde_json::Value) {
    let report = serde_json::to_string_pretty(value).unwrap() + "\n";
    fs::write(path, &report).unwrap();
    println!("{report}");
}

pub struct FixtureServer {
    pub port: u16,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl FixtureServer {
    pub fn new(body: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        use std::{
            io::{BufRead, BufReader, Write},
            net::TcpListener,
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            },
        };
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let body = Arc::new(body);
        let worker = thread::spawn(move || {
            let mut connections = Vec::new();
            for stream in listener.incoming() {
                if stopping.load(Ordering::Relaxed) {
                    break;
                }
                let mut stream = stream.unwrap();
                let body = body.clone();
                connections.push(thread::spawn(move || {
                    stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                    let mut reader = BufReader::new(&mut stream).take(16 * 1024);
                    let mut first = String::new();
                    if reader.read_line(&mut first).is_err() { return; }
                    loop {
                        let mut header = String::new();
                        match reader.read_line(&mut header) {
                            Ok(0) | Err(_) => return,
                            Ok(_) if header == "\r\n" => break,
                            _ => {}
                        }
                    }
                    let route = first.split_whitespace().nth(1).unwrap_or("/");
                    let content_type = if route.ends_with(".js") { "application/javascript" } else { "text/html; charset=utf-8" };
                    let body = body(route);
                    let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", content_type, body.len(), body);
                }));
            }
            for connection in connections {
                connection.join().unwrap();
            }
        });
        Self {
            port,
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = std::net::TcpStream::connect(("127.0.0.1", self.port));
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
