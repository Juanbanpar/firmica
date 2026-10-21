//! macOS ACLs can grant access independently of POSIX mode bits.
use std::{
    ffi::{c_int, c_void},
    fs::File,
    io,
    os::fd::AsRawFd,
};

unsafe extern "C" {
    fn acl_get_fd(fd: c_int) -> *mut c_void;
    fn acl_get_entry(acl: *mut c_void, entry_id: c_int, entry: *mut *mut c_void) -> c_int;
    fn acl_free(acl: *mut c_void) -> c_int;
}

/// Reject extended ACLs, including inherited entries, on private files and directories.
pub(crate) fn ensure_no_acl(file: &File) -> io::Result<()> {
    // SAFETY: the descriptor is live. Darwin returns an owned ACL or NULL/errno;
    // ENOENT means no ACL property on this existing descriptor, not a missing path.
    let acl = unsafe { acl_get_fd(file.as_raw_fd()) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(rustix::io::Errno::NOENT.raw_os_error()) {
            Ok(())
        } else {
            Err(error)
        };
    }
    let mut entry = std::ptr::null_mut();
    // SAFETY: zero is Darwin's ACL_FIRST_ENTRY. The owned, valid ACL stays live
    // until its first-entry result and errno have been captured, then is freed.
    let found = unsafe { acl_get_entry(acl, 0, &mut entry) };
    let error = io::Error::last_os_error();
    unsafe {
        acl_free(acl);
    }
    if found == 0 {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "extended ACL on a private file",
        ))
    } else if error.raw_os_error() == Some(rustix::io::Errno::INVAL.raw_os_error()) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::fs::PermissionsExt, process::Command};

    #[test]
    fn extended_access_is_rejected_even_when_mode_bits_are_private() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("private");
        let file = File::create(&path).unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        ensure_no_acl(&file).unwrap();
        assert!(Command::new("/bin/chmod")
            .args(["+a", "everyone allow read"])
            .arg(&path)
            .status()
            .unwrap()
            .success());
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        assert!(ensure_no_acl(&file).is_err());
    }
}
