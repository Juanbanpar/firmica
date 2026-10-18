//! Private, bounded URI handoff within one Windows logon session.
//!
//! The logon SID restricts both the pipe namespace and its DACL. Before sending
//! a URI, the client checks the server process's logon SID. Same-session processes
//! can submit requests, but every URI remains untrusted and requires normal review.
use firmica_protocol::{ProtocolRequest, MAX_URI_BYTES};
use std::{
    io,
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions},
    sync::mpsc::Sender,
    task::JoinHandle,
    time::{sleep, timeout},
};
use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_BUSY},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        },
        GetTokenInformation, TokenLogonSid, SECURITY_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY,
    },
    System::{
        Pipes::GetNamedPipeServerProcessId,
        Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};

const IO_TIMEOUT: Duration = Duration::from_secs(2);
const ACCEPTED: u8 = 1;
const CONSUMED: u8 = 2;

pub(super) struct Instance(JoinHandle<()>);

impl Drop for Instance {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(super) async fn primary_or_forward(
    uri: Option<&str>,
    incoming: Sender<String>,
) -> io::Result<Option<Instance>> {
    let sid = logon_sid(std::process::id())?;
    let name = format!(r"\\.\pipe\firmica-invocation-v1-{sid}");
    establish(&name, &sid, uri, incoming).await
}

async fn establish(
    name: &str,
    sid: &str,
    uri: Option<&str>,
    incoming: Sender<String>,
) -> io::Result<Option<Instance>> {
    if let Some(uri) = uri {
        ProtocolRequest::parse(uri).map_err(|_| io::ErrorKind::InvalidInput)?;
    }
    match create_server(name, sid) {
        Ok(server) => Ok(Some(Instance(tokio::spawn(listen(server, incoming))))),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            // FIRST_PIPE_INSTANCE also returns access denied when another server
            // exists. Do not start a second UI or fall back to a public endpoint.
            timeout(IO_TIMEOUT, forward(name, sid, uri))
                .await
                .map_err(|_| io::ErrorKind::TimedOut)??;
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn create_server(name: &str, sid: &str) -> io::Result<NamedPipeServer> {
    let sddl = format!("D:P(A;;GA;;;{sid})\0")
        .encode_utf16()
        .collect::<Vec<_>>();
    let mut descriptor = ptr::null_mut();
    // SAFETY: NUL-terminated UTF-16 input and writable output. Windows allocates
    // the descriptor, whose lifetime below covers the pipe creation call.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalAllocation(descriptor);
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: attributes and its descriptor remain valid until CreateNamedPipe
    // returns; neither pointer is retained by Windows or Tokio.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .max_instances(1)
            .reject_remote_clients(true)
            .in_buffer_size(MAX_URI_BYTES as u32 + 4)
            .out_buffer_size(1)
            .create_with_security_attributes_raw(
                name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
    }
}

async fn listen(mut server: NamedPipeServer, incoming: Sender<String>) {
    while server.connect().await.is_ok() {
        let _ = timeout(IO_TIMEOUT, receive(&mut server, &incoming)).await;
        // Reuse the original handle: the exclusive name never disappears between
        // clients. A stalled or malformed client is disconnected after its deadline.
        if server.disconnect().is_err() {
            break;
        }
    }
}

async fn receive(server: &mut NamedPipeServer, incoming: &Sender<String>) -> io::Result<()> {
    let length = server.read_u32().await? as usize;
    if length > MAX_URI_BYTES {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; length];
    server.read_exact(&mut bytes).await?;
    let accepted = if length == 0 {
        true // Opening the app without a URI must not create another window.
    } else {
        String::from_utf8(bytes)
            .ok()
            .filter(|uri| ProtocolRequest::parse(uri).is_ok())
            .is_some_and(|uri| incoming.try_send(uri).is_ok())
    };
    server.write_u8(u8::from(accepted)).await?;
    // DisconnectNamedPipe discards unread output. Wait for proof that the client
    // read our acknowledgement before disconnecting; the same deadline applies.
    if server.read_u8().await? != CONSUMED {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}

async fn forward(name: &str, sid: &str, uri: Option<&str>) -> io::Result<()> {
    let mut client = loop {
        match ClientOptions::new().open(name) {
            Ok(client) => break client,
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                sleep(Duration::from_millis(20)).await;
            }
            Err(error) => return Err(error),
        }
    };
    let mut pid = 0;
    // SAFETY: the pipe handle is live and pid is writable. The kernel supplies
    // the peer PID; no identity information comes from the received payload.
    if unsafe { GetNamedPipeServerProcessId(client.as_raw_handle(), &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if logon_sid(pid)? != sid {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    // Tokio's default SECURITY_IDENTIFICATION prevents server impersonation.
    let bytes = uri.unwrap_or_default().as_bytes();
    client.write_u32(bytes.len() as u32).await?;
    client.write_all(bytes).await?;
    let acknowledgement = client.read_u8().await?;
    client.write_u8(CONSUMED).await?;
    if acknowledgement != ACCEPTED {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(())
}

struct LocalAllocation(*mut std::ffi::c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: allocated by a documented LocalAlloc-family Win32 API.
        unsafe { LocalFree(self.0) };
    }
}

fn logon_sid(pid: u32) -> io::Result<String> {
    // SAFETY: query-only access, no inherited handle; failures are checked before
    // transferring ownership of returned handles to OwnedHandle.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut needed = 0;
    // SAFETY: a zero-length query obtains the required buffer size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenLogonSid,
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || needed < size_of::<TOKEN_GROUPS>() as u32
        || needed > 64 * 1024
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // TOKEN_GROUPS contains pointers: allocate with pointer alignment, not Vec<u8>.
    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    // SAFETY: properly aligned storage covers the queried byte count. The token
    // remains open and the returned SID stays inside this allocation until copied.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenLogonSid,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let groups = unsafe { &*buffer.as_ptr().cast::<TOKEN_GROUPS>() };
    if groups.GroupCount != 1 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut text = ptr::null_mut();
    // SAFETY: SID is from the live TOKEN_GROUPS buffer and text is writable.
    if unsafe { ConvertSidToStringSidW(groups.Groups[0].Sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let allocation = LocalAllocation(text.cast());
    // SAFETY: the API returns a NUL-terminated SID string. Its documented syntax
    // contains at most 15 subauthorities, so this scan is finite for valid SIDs.
    let mut length = 0;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) })
        .map_err(|_| io::ErrorKind::InvalidData)?;
    drop(allocation);
    Ok(sid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    use tokio::{io::AsyncBufReadExt, process::Command, sync::mpsc};

    fn identity() -> (String, String) {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let sid = logon_sid(std::process::id()).unwrap();
        let name = format!(
            r"\\.\pipe\firmica-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        (name, sid)
    }

    const URI: &str = "afirma://sign?ver=4&format=CAdES&dat=w6E%3D";

    // Separate test processes exercise the real pipe without opening a Dioxus
    // window or changing the machine's URI handler/registration.
    fn child(name: &str, sid: &str, mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "invocation::windows::tests::child_process",
                "--nocapture",
            ])
            .env("FIRMICA_TEST_PIPE", name)
            .env("FIRMICA_TEST_SID", sid)
            .env("FIRMICA_TEST_MODE", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .kill_on_drop(true);
        command
    }

    #[tokio::test]
    async fn child_process() {
        let Ok(name) = std::env::var("FIRMICA_TEST_PIPE") else {
            return;
        };
        let sid = std::env::var("FIRMICA_TEST_SID").unwrap();
        let (sender, _receiver) = mpsc::channel(8);
        let instance = establish(&name, &sid, Some(URI), sender).await.unwrap();
        if std::env::var("FIRMICA_TEST_MODE").unwrap() == "primary" {
            assert!(instance.is_some());
            println!("FIRMICA_PIPE_READY");
            std::future::pending::<()>().await;
        } else {
            assert!(instance.is_none());
        }
    }

    #[tokio::test]
    async fn forwards_between_processes_and_rejects_a_full_queue() {
        let (name, sid) = identity();
        let (sender, mut receiver) = mpsc::channel(1);
        let instance = establish(&name, &sid, None, sender.clone()).await.unwrap();
        assert!(instance.is_some());
        let status = timeout(
            Duration::from_secs(10),
            child(&name, &sid, "forward").status(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(status.success());
        assert_eq!(receiver.recv().await.unwrap(), URI);
        sender.try_send("occupied".into()).unwrap();
        assert_eq!(
            establish(&name, &sid, Some(URI), sender.clone())
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(receiver.recv().await.unwrap(), "occupied");
        assert!(establish(&name, &sid, None, sender)
            .await
            .unwrap()
            .is_none());
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn malformed_and_stalled_clients_do_not_break_later_handoffs() {
        let (name, sid) = identity();
        let (sender, mut receiver) = mpsc::channel(8);
        let _instance = establish(&name, &sid, None, sender.clone()).await.unwrap();
        for payload in [
            vec![0xff],
            b"https://example.invalid".to_vec(),
            vec![b'a'; MAX_URI_BYTES + 1],
        ] {
            let mut client = open(&name).await;
            client.write_u32(payload.len() as u32).await.unwrap();
            if payload.len() <= MAX_URI_BYTES {
                client.write_all(&payload).await.unwrap();
                assert_eq!(client.read_u8().await.unwrap(), 0);
                client.write_u8(CONSUMED).await.unwrap();
            }
        }
        // Keep a connection open without supplying even a frame header.
        let stalled = open(&name).await;
        sleep(IO_TIMEOUT + Duration::from_millis(100)).await;
        drop(stalled);
        assert!(receiver.try_recv().is_err());
        assert!(establish(&name, &sid, Some(URI), sender)
            .await
            .unwrap()
            .is_none());
        assert_eq!(receiver.recv().await.unwrap(), URI);
    }

    async fn open(name: &str) -> tokio::net::windows::named_pipe::NamedPipeClient {
        timeout(Duration::from_secs(5), async {
            loop {
                match ClientOptions::new().open(name) {
                    Ok(client) => return client,
                    Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                        sleep(Duration::from_millis(10)).await
                    }
                    Err(error) => panic!("cannot open test pipe: {error}"),
                }
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_nonresponsive_server_cannot_stall_the_client() {
        let (name, sid) = identity();
        let _server = create_server(&name, &sid).unwrap();
        let (sender, _) = mpsc::channel(8);
        assert_eq!(
            establish(&name, &sid, Some(URI), sender)
                .await
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn crashed_primary_releases_the_name_for_a_new_process() {
        let (name, sid) = identity();
        let mut process = child(&name, &sid, "primary").spawn().unwrap();
        let stdout = process.stdout.take().unwrap();
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        timeout(Duration::from_secs(10), async {
            while let Some(line) = lines.next_line().await.unwrap() {
                if line == "FIRMICA_PIPE_READY" {
                    return;
                }
            }
            panic!("child exited before creating the pipe");
        })
        .await
        .unwrap();
        process.kill().await.unwrap();
        let (sender, _) = mpsc::channel(8);
        assert!(establish(&name, &sid, None, sender)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn wrong_logon_identity_is_rejected_before_uri_delivery() {
        let (name, sid) = identity();
        let (sender, mut receiver) = mpsc::channel(8);
        let _instance = establish(&name, &sid, None, sender).await.unwrap();
        assert_eq!(
            forward(&name, "S-1-5-5-0-0", Some(URI))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn pipe_acl_denies_a_token_without_the_logon_sid() {
        use windows_sys::Win32::{
            Security::{
                Authorization::ConvertStringSidToSidW, CreateRestrictedToken,
                ImpersonateLoggedOnUser, RevertToSelf, DISABLE_MAX_PRIVILEGE, SID_AND_ATTRIBUTES,
                TOKEN_DUPLICATE,
            },
            System::Threading::GetCurrentProcess,
        };
        let (name, sid) = identity();
        let _server = create_server(&name, &sid).unwrap();
        let text = format!("{sid}\0").encode_utf16().collect::<Vec<_>>();
        let mut sid = ptr::null_mut();
        let mut token = ptr::null_mut();
        let mut restricted = ptr::null_mut();
        // SAFETY: all pointers refer to initialized input or writable output;
        // successful allocations/handles are immediately given RAII ownership.
        unsafe {
            assert_ne!(ConvertStringSidToSidW(text.as_ptr(), &mut sid), 0);
            let sid = LocalAllocation(sid);
            assert_ne!(
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE,
                    &mut token
                ),
                0
            );
            let token = OwnedHandle::from_raw_handle(token);
            let disabled = SID_AND_ATTRIBUTES {
                Sid: sid.0,
                Attributes: 0,
            };
            assert_ne!(
                CreateRestrictedToken(
                    token.as_raw_handle(),
                    DISABLE_MAX_PRIVILEGE,
                    1,
                    &disabled,
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                    &mut restricted
                ),
                0
            );
            let restricted = OwnedHandle::from_raw_handle(restricted);
            assert_ne!(ImpersonateLoggedOnUser(restricted.as_raw_handle()), 0);
        }
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                // SAFETY: restores the current test thread's original identity.
                // Continuing with a restricted identity would invalidate the test.
                if unsafe { RevertToSelf() } == 0 {
                    std::process::abort();
                }
            }
        }
        let revert = Revert;
        // Do not await or migrate threads while impersonating. This open is the
        // actual kernel access check, not a comparison of the SDDL text.
        let result = ClientOptions::new().open(&name);
        drop(revert);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
}
