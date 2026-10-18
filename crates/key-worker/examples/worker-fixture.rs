//! Windows process-control regression fixture. Select a mode by copying this
//! executable to `<mode>.exe`; no production worker or credential flow uses it.
#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() {
    use std::{
        io::{self, Write},
        process::Command,
        thread,
        time::Duration,
    };
    use windows_sys::Win32::System::{JobObjects::*, Memory::*};
    fn frame(bytes: &[u8]) {
        let mut output = io::stdout().lock();
        output
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        output.write_all(bytes).unwrap();
        output.flush().unwrap();
    }
    if std::env::args().any(|arg| arg == "--child") {
        return;
    }
    let executable = std::env::current_exe().unwrap();
    match executable.file_stem().unwrap().to_str().unwrap() {
        "silent" => thread::sleep(Duration::from_secs(60)),
        "blocked" => {
            frame(b"FRMKEY\x01");
            thread::sleep(Duration::from_secs(60));
        }
        "malformed" => {
            io::stdout().write_all(&u32::MAX.to_be_bytes()).unwrap();
            io::stdout().flush().unwrap();
            thread::sleep(Duration::from_secs(60));
        }
        "nonzero" => {
            frame(b"FRMKEY\x01");
            std::process::exit(1);
        }
        "cpu" => loop {
            std::hint::black_box(2u64.wrapping_mul(std::hint::black_box(7)));
        },
        "memory" => {
            // SAFETY: reserve+commit one inaccessible-to-Rust test allocation;
            // never dereference it, and release it if the OS unexpectedly allows it.
            let allocation = unsafe {
                VirtualAlloc(
                    std::ptr::null(),
                    300 * 1024 * 1024,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_READWRITE,
                )
            };
            if allocation.is_null() {
                frame(b"memory-denied");
            } else {
                unsafe {
                    VirtualFree(allocation, 0, MEM_RELEASE);
                }
                frame(b"memory-allowed");
            }
        }
        "descendant" => match Command::new(&executable).arg("--child").spawn() {
            Err(_) => frame(b"descendant-denied"),
            Ok(mut child) => {
                let _ = child.wait();
                frame(b"descendant-allowed");
            }
        },
        "limits" => {
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            // SAFETY: query our innermost job into a correctly sized output.
            assert_ne!(
                unsafe {
                    QueryInformationJobObject(
                        std::ptr::null_mut(),
                        JobObjectExtendedLimitInformation,
                        (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                        std::mem::size_of_val(&limits) as u32,
                        std::ptr::null_mut(),
                    )
                },
                0
            );
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&(limits.ProcessMemoryLimit as u64).to_be_bytes());
            bytes.extend_from_slice(
                &limits
                    .BasicLimitInformation
                    .PerProcessUserTimeLimit
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(
                &limits
                    .BasicLimitInformation
                    .ActiveProcessLimit
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&limits.BasicLimitInformation.LimitFlags.to_be_bytes());
            frame(&bytes);
        }
        _ => panic!("unknown Windows worker fixture"),
    }
}
