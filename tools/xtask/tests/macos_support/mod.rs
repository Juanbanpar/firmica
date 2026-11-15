pub use super::signing_support::{decode, identities, verify, PASSWORD};
use super::*;
use std::{ffi::c_void, os::unix::ffi::OsStrExt};

pub fn workers(parent: u32, app: &Path) -> Vec<u32> {
    let companion = app.join("Contents/MacOS/firmica-key-worker");
    checked(
        Command::new("/bin/ps").args(["-axo", "pid=,ppid=,comm="]),
        10,
    )
    .lines()
    .filter_map(|line| {
        let mut fields = line.split_whitespace();
        let pid = fields.next()?.parse().ok()?;
        let owner: u32 = fields.next()?.parse().ok()?;
        (owner == parent && line.ends_with(companion.to_str().unwrap())).then_some(pid)
    })
    .collect()
}

pub struct Profile {
    pub path: PathBuf,
}
impl Profile {
    pub fn initialize(executable: &Path, origin: &str) -> Self {
        let parent = PathBuf::from(env::var_os("HOME").unwrap())
            .join("Library/Application Support/org.firmica.client");
        assert!(
            !parent.exists(),
            "requires an account without a Firmica configuration"
        );
        // Own cleanup before running provisioning so assertion failures also remove our profile.
        let profile = Self { path: parent };
        checked(
            Command::new(executable).args(["tls", "init", "--origin", origin]),
            30,
        );
        checked(Command::new(executable).args(["tls", "status"]), 30);
        profile
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

// LaunchServices has no command-line default-handler API. Keep the native FFI
// inside this disposable-runner test; the application never changes defaults.
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFStringCreateWithBytes(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
        encoding: u32,
        external: bool,
    ) -> *const c_void;
    fn CFStringGetCString(
        string: *const c_void,
        buffer: *mut u8,
        size: isize,
        encoding: u32,
    ) -> bool;
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: *const c_void,
        bytes: *const u8,
        length: isize,
        directory: bool,
    ) -> *const c_void;
    fn CFRelease(value: *const c_void);
}
#[link(name = "CoreServices", kind = "framework")]
unsafe extern "C" {
    fn LSCopyDefaultHandlerForURLScheme(scheme: *const c_void) -> *const c_void;
    fn LSSetDefaultHandlerForURLScheme(scheme: *const c_void, bundle: *const c_void) -> i32;
    fn LSRegisterURL(url: *const c_void, update: bool) -> i32;
}
struct OwnedCf(*const c_void);
impl Drop for OwnedCf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CFRelease(self.0);
            }
        }
    }
}
fn cf_string(value: &str) -> OwnedCf {
    // SAFETY: valid UTF-8 bytes remain alive until CoreFoundation copies them.
    let string = OwnedCf(unsafe {
        CFStringCreateWithBytes(
            std::ptr::null(),
            value.as_ptr(),
            value.len() as isize,
            0x08000100,
            false,
        )
    });
    assert!(!string.0.is_null());
    string
}
fn default_handler(scheme: &OwnedCf) -> Option<String> {
    // SAFETY: scheme is a live CFString, and the Copy result is owned here.
    let result = OwnedCf(unsafe { LSCopyDefaultHandlerForURLScheme(scheme.0) });
    if result.0.is_null() {
        return None;
    }
    let mut bytes = [0u8; 512];
    assert!(unsafe {
        CFStringGetCString(
            result.0,
            bytes.as_mut_ptr(),
            bytes.len() as isize,
            0x08000100,
        )
    });
    Some(
        std::ffi::CStr::from_bytes_until_nul(&bytes)
            .unwrap()
            .to_str()
            .unwrap()
            .into(),
    )
}
pub struct Handler {
    app: PathBuf,
}
impl Handler {
    pub fn register(app: &Path) -> Self {
        let scheme = cf_string("afirma");
        let previous = default_handler(&scheme);
        assert!(
            previous
                .as_deref()
                .is_none_or(|id| id == "org.firmica.client"),
            "refusing to replace another afirma handler"
        );
        let bytes = app.as_os_str().as_bytes();
        let url = OwnedCf(unsafe {
            CFURLCreateFromFileSystemRepresentation(
                std::ptr::null(),
                bytes.as_ptr(),
                bytes.len() as isize,
                true,
            )
        });
        assert!(!url.0.is_null());
        let handler = Self { app: app.into() };
        assert_eq!(unsafe { LSRegisterURL(url.0, true) }, 0);
        let bundle = cf_string("org.firmica.client");
        assert_eq!(
            unsafe { LSSetDefaultHandlerForURLScheme(scheme.0, bundle.0) },
            0
        );
        assert_eq!(
            default_handler(&scheme).as_deref(),
            Some("org.firmica.client")
        );
        handler
    }
}
impl Drop for Handler {
    fn drop(&mut self) {
        if default_handler(&cf_string("afirma")).as_deref() == Some("org.firmica.client") {
            let _=Command::new("/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister").arg("-u").arg(&self.app).output();
        }
    }
}
