//! A fresh logon and HKCU hive, not a filtered administrator token.
use super::*;
use std::{
    ffi::OsStr,
    mem,
    os::windows::ffi::OsStrExt,
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0},
    NetworkManagement::NetManagement::{
        NetLocalGroupAddMembers, NetUserAdd, NetUserDel, LOCALGROUP_MEMBERS_INFO_0,
        UF_NORMAL_ACCOUNT, UF_SCRIPT, USER_INFO_1, USER_PRIV_USER,
    },
    Security::{
        Authorization::ConvertSidToStringSidW,
        CreateWellKnownSid,
        Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG},
        GetTokenInformation, LookupAccountNameW, LookupAccountSidW, TokenElevationType,
        TokenElevationTypeDefault, WinBuiltinUsersSid, TOKEN_QUERY,
    },
    System::Threading::{
        CreateProcessWithLogonW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken,
        TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, LOGON_WITH_PROFILE,
        PROCESS_INFORMATION, STARTUPINFOW,
    },
    UI::Shell::DeleteProfileW,
};

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

struct Account {
    name: Vec<u16>,
    sid: Option<Vec<u16>>,
    logged_on: bool,
}
impl Drop for Account {
    fn drop(&mut self) {
        let mut removed = !self.logged_on;
        if let Some(sid) = self.sid.as_ref().filter(|_| self.logged_on) {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if unsafe { DeleteProfileW(sid.as_ptr(), ptr::null(), ptr::null()) } != 0 {
                    removed = true;
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        let status = unsafe { NetUserDel(ptr::null(), self.name.as_ptr()) };
        if !std::thread::panicking() {
            assert!(removed, "could not remove the disposable user profile");
            assert_eq!(status, 0, "could not remove the disposable account");
        }
    }
}

fn account_sid(name: &[u16]) -> (Vec<u16>, [usize; 16]) {
    let mut sid = [0usize; 16];
    let mut size = mem::size_of_val(&sid) as u32;
    let mut domain = [0u16; 256];
    let mut domain_size = domain.len() as u32;
    let mut kind = 0;
    assert_ne!(
        unsafe {
            LookupAccountNameW(
                ptr::null(),
                name.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut size,
                domain.as_mut_ptr(),
                &mut domain_size,
                &mut kind,
            )
        },
        0
    );
    let mut text = ptr::null_mut();
    assert_ne!(
        unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut text) },
        0
    );
    let mut length = 0;
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
        let result = std::slice::from_raw_parts(text, length + 1).to_vec();
        LocalFree(text.cast());
        (result, sid)
    }
}

fn users_group() -> Vec<u16> {
    let mut sid = [0usize; 16];
    let mut size = mem::size_of_val(&sid) as u32;
    assert_ne!(
        unsafe {
            CreateWellKnownSid(
                WinBuiltinUsersSid,
                ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut size,
            )
        },
        0
    );
    let mut name = vec![0u16; 256];
    let mut name_size = name.len() as u32;
    let mut domain = [0u16; 256];
    let mut domain_size = domain.len() as u32;
    let mut kind = 0;
    assert_ne!(
        unsafe {
            LookupAccountSidW(
                ptr::null(),
                sid.as_mut_ptr().cast(),
                name.as_mut_ptr(),
                &mut name_size,
                domain.as_mut_ptr(),
                &mut domain_size,
                &mut kind,
            )
        },
        0
    );
    name.truncate(name_size as usize + 1);
    name
}

fn assert_standard_token() {
    assert_eq!(
        unsafe { IsUserAnAdmin() },
        0,
        "registration must run without administrator membership"
    );
    let mut token = ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) },
        0
    );
    let token = Handle(token);
    let mut elevation = 0i32;
    let mut size = 0;
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenElevationType,
                (&mut elevation as *mut i32).cast(),
                mem::size_of_val(&elevation) as u32,
                &mut size,
            )
        },
        0
    );
    assert_eq!(
        elevation, TokenElevationTypeDefault,
        "a filtered administrator token is not a standard account"
    );
    let denied = LOCAL_MACHINE
        .options()
        .write()
        .open(r"Software\Classes")
        .expect_err("standard account must not have machine registry write access");
    assert_eq!(denied.code().0 as u32, 0x80070005);
}

#[test]
#[ignore = "creates a disposable standard Windows account and loads its profile; requires an administrator test host"]
fn registration_under_standard_account() {
    let executable = std::env::current_exe().unwrap();
    let staged = executable.parent().unwrap();
    let child = staged.join("standard-account.fixture.exe").is_file();
    if child {
        let log = staged.join("child.log");
        std::panic::set_hook(Box::new(move |info| {
            let _ = fs::write(&log, format!("{info}\n"));
        }));
        assert_standard_token();
        registration_checks(
            &staged.join("handler.ps1"),
            Some(&staged.join("standard-account.fixture.exe")),
        );
        support::report(
            &staged.join("result.json"),
            &serde_json::json!({"passed":true,"administrator":false,"filtered_administrator":false,"machine_registry_write_denied":true,"registration":"install/status/uninstall, ownership, collisions and quoting"}),
        );
        return;
    }
    assert_ne!(
        unsafe { IsUserAnAdmin() },
        0,
        "account provisioning requires a disposable administrator test host"
    );
    let temporary = tempfile::Builder::new()
        .prefix("firmica-standard-")
        .tempdir_in(std::env::var_os("PUBLIC").expect("PUBLIC"))
        .unwrap();
    let nonce = temporary.path().file_name().unwrap().to_string_lossy();
    let name = format!("Firmica{}", nonce.trim_start_matches("firmica-standard-"));
    let mut random = [0u8; 32];
    assert_eq!(
        unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                random.as_mut_ptr(),
                random.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        },
        0
    );
    let mut password = wide(format!(
        "F!rmica9-{}",
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    let mut name_wide = wide(&name);
    let user = USER_INFO_1 {
        usri1_name: name_wide.as_mut_ptr(),
        usri1_password: password.as_mut_ptr(),
        usri1_priv: USER_PRIV_USER,
        usri1_flags: UF_SCRIPT | UF_NORMAL_ACCOUNT,
        ..Default::default()
    };
    assert_eq!(
        unsafe {
            NetUserAdd(
                ptr::null(),
                1,
                (&user as *const USER_INFO_1).cast(),
                ptr::null_mut(),
            )
        },
        0,
        "could not provision standard account"
    );
    let mut account = Account {
        name: name_wide,
        sid: None,
        logged_on: false,
    };
    let (sid_text, mut sid) = account_sid(&account.name);
    account.sid = Some(sid_text);
    let member = LOCALGROUP_MEMBERS_INFO_0 {
        lgrmi0_sid: sid.as_mut_ptr().cast(),
    };
    let status = unsafe {
        NetLocalGroupAddMembers(
            ptr::null(),
            users_group().as_ptr(),
            0,
            (&member as *const LOCALGROUP_MEMBERS_INFO_0).cast(),
            1,
        )
    };
    assert!(
        status == 0 || status == 1378,
        "could not add account to Users: {status}"
    );
    checked(
        Command::new("icacls.exe")
            .arg(temporary.path())
            .args(["/grant:r", &format!("{name}:(OI)(CI)F")]),
        15,
    );
    let application = temporary.path().join("registration-tests.exe");
    fs::copy(&executable, &application).unwrap();
    fs::copy(
        support::root().join("tools/windows/handler.ps1"),
        temporary.path().join("handler.ps1"),
    )
    .unwrap();
    compile_fixture(&temporary.path().join("standard-account.fixture.exe"));
    let application = wide(&application);
    let directory = wide(temporary.path());
    let mut command = wide(format!("\"{}\" --exact windows_standard_account::registration_under_standard_account --ignored --nocapture", temporary.path().join("registration-tests.exe").display()));
    let startup = STARTUPINFOW {
        cb: mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut process = PROCESS_INFORMATION::default();
    // A fresh logon with its own loaded HKCU and environment. No caller token or
    // environment block is reused; no password is passed on a command line.
    let created = unsafe {
        CreateProcessWithLogonW(
            account.name.as_ptr(),
            wide(".").as_ptr(),
            password.as_ptr(),
            LOGON_WITH_PROFILE,
            application.as_ptr(),
            command.as_mut_ptr(),
            CREATE_NO_WINDOW,
            ptr::null(),
            directory.as_ptr(),
            &startup,
            &mut process,
        )
    };
    password.fill(0);
    assert_ne!(
        created,
        0,
        "standard logon failed: {}",
        std::io::Error::last_os_error()
    );
    account.logged_on = true;
    let process_handle = Handle(process.hProcess);
    let thread_handle = Handle(process.hThread);
    let waited = unsafe { WaitForSingleObject(process_handle.0, 180_000) };
    if waited != WAIT_OBJECT_0 {
        unsafe {
            TerminateProcess(process_handle.0, 1);
            WaitForSingleObject(process_handle.0, 10_000);
        }
    }
    let evidence = support::root().join(".test-artifacts/windows-standard-account");
    fs::create_dir_all(&evidence).unwrap();
    for name in ["result.json", "child.log"] {
        if temporary.path().join(name).exists() {
            fs::copy(temporary.path().join(name), evidence.join(name)).unwrap();
        }
    }
    let mut exit = 1;
    assert_ne!(
        unsafe { GetExitCodeProcess(process_handle.0, &mut exit) },
        0
    );
    drop(thread_handle);
    drop(process_handle);
    assert_eq!(waited, WAIT_OBJECT_0, "standard-account test timed out");
    assert_eq!(
        exit, 0,
        "standard-account test failed; see .test-artifacts/windows-standard-account/child.log"
    );
    assert!(
        temporary.path().join("result.json").is_file(),
        "standard-account child did not run"
    );
    drop(account);
}
