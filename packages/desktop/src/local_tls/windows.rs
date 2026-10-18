//! Windows profile storage: protected user-only DACLs and handle-based checks.
use super::*;
use secrecy::ExposeSecretMut;
use std::{
    ffi::{c_void, OsString},
    fs::File,
    io::{Read, Write},
    mem::{offset_of, size_of},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::MetadataExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::{LocalFree, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
        },
        EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
        GetTokenInformation, IsValidAcl, IsValidSid, IsWellKnownSid, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER,
        DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
        TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, MoveFileExW, CREATE_NEW, DELETE, FILE_ALL_ACCESS,
        FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
        MOVEFILE_WRITE_THROUGH, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    },
    System::{
        Com::CoTaskMemFree,
        SystemServices::ACCESS_ALLOWED_ACE_TYPE,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
    UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
};

struct Allocation(*mut c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: these allocations are returned by LocalAlloc-family security APIs.
        unsafe { LocalFree(self.0) };
    }
}

fn wide(path: &Path) -> Result<Vec<u16>, Error> {
    let mut value = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if value.contains(&0) {
        return Err(Error::Directory);
    }
    value.push(0);
    Ok(value)
}

fn owned(handle: windows_sys::Win32::Foundation::HANDLE) -> Result<OwnedHandle, Error> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: callers pass only newly opened, exclusively owned kernel handles.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

struct User(Vec<usize>);
impl User {
    fn current() -> Result<Self, Error> {
        let mut token = ptr::null_mut();
        // SAFETY: query-only access to our own token, writable output.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        let token = owned(token)?;
        let mut needed = 0;
        // SAFETY: the first call obtains the required allocation size.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        if needed < size_of::<TOKEN_USER>() as u32 || needed > 64 * 1024 {
            return Err(Error::Permissions);
        }
        let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        // SAFETY: aligned, stable storage covers the queried byte count.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self(buffer))
    }
    fn sid(&self) -> PSID {
        // SAFETY: GetTokenInformation initialized TOKEN_USER and its embedded SID;
        // neither the buffer nor its pointed-to SID moves during this borrow.
        unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
    fn descriptor(&self, directory: bool) -> Result<Allocation, Error> {
        let mut sid = ptr::null_mut();
        // SAFETY: valid token SID and writable LocalAlloc output.
        if unsafe { ConvertSidToStringSidW(self.sid(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error().into());
        }
        let allocation = Allocation(sid.cast());
        let mut length = 0;
        // SAFETY: the successful conversion returns a NUL-terminated UTF-16 string.
        while unsafe { *sid.add(length) } != 0 {
            length += 1;
        }
        let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid, length) });
        drop(allocation);
        let flags = if directory { "OICI" } else { "" };
        let sddl = format!("O:{sid}D:P(A;{flags};FA;;;{sid})\0")
            .encode_utf16()
            .collect::<Vec<_>>();
        let mut descriptor = ptr::null_mut();
        // SAFETY: terminated SDDL, writable output, descriptor freed by Allocation.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Allocation(descriptor))
    }
}

pub(super) fn config_base() -> Result<PathBuf, Error> {
    let mut path = ptr::null_mut();
    // SAFETY: fixed known-folder GUID, current user, writable COM-allocated output.
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, ptr::null_mut(), &mut path) };
    if result < 0 {
        return Err(Error::Directory);
    }
    let mut length = 0;
    // SAFETY: SHGetKnownFolderPath returns a terminated UTF-16 path.
    while unsafe { *path.add(length) } != 0 {
        length += 1;
    }
    let value = unsafe { OsString::from_wide(std::slice::from_raw_parts(path, length)) };
    unsafe { CoTaskMemFree(path.cast()) };
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(Error::Directory);
    }
    Ok(path)
}

fn open(path: &Path, access: u32) -> Result<File, Error> {
    let path = wide(path)?;
    // SAFETY: terminated path, no inheritance/template. Opening the reparse point
    // itself lets the handle metadata reject it before reading content or ACLs.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            ptr::null_mut(),
        )
    };
    let handle = owned(handle)?;
    Ok(File::from(handle))
}

fn privileged(sid: PSID) -> bool {
    // SAFETY: SID belongs to a kernel-returned owner or validated ACL entry.
    unsafe {
        IsWellKnownSid(sid, WinLocalSystemSid) != 0
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
    }
}

fn check(file: &File, directory: bool, private: bool) -> Result<(), Error> {
    let metadata = file.metadata()?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err(Error::Permissions);
    }
    let user = User::current()?;
    let (mut owner, mut acl, mut descriptor) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    // SAFETY: live handle with READ_CONTROL and writable output pointers. All
    // returned pointers remain inside the owned security-descriptor allocation.
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32).into());
    }
    let _descriptor = Allocation(descriptor);
    if owner.is_null() || acl.is_null() {
        return Err(Error::Permissions);
    }
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: kernel-returned descriptor and SID, checked non-null above.
    unsafe {
        if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0
            || IsValidAcl(acl) == 0
            || (EqualSid(owner, user.sid()) == 0 && (private || !privileged(owner)))
            || (private && (control & SE_DACL_PROTECTED == 0 || (*acl).AceCount != 1))
        {
            return Err(Error::Permissions);
        }
        for index in 0..(*acl).AceCount {
            let mut entry = ptr::null_mut();
            if GetAce(acl, index as u32, &mut entry) == 0 {
                return Err(Error::Permissions);
            }
            let header = &*entry.cast::<ACE_HEADER>();
            let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
                || (header.AceSize as usize) < sid_offset + 8
            {
                return Err(Error::Permissions);
            }
            let ace = &*entry.cast::<ACCESS_ALLOWED_ACE>();
            let sid = (&ace.SidStart as *const u32).cast_mut().cast();
            if GetLengthSid(sid) as usize > header.AceSize as usize - sid_offset
                || IsValidSid(sid) == 0
            {
                return Err(Error::Permissions);
            }
            let same_user = EqualSid(sid, user.sid()) != 0;
            if private {
                if !same_user
                    || ace.Mask != FILE_ALL_ACCESS
                    || u32::from(ace.Header.AceFlags) != if directory { 3 } else { 0 }
                {
                    return Err(Error::Permissions);
                }
            } else if !same_user
                && !privileged(sid)
                && ace.Mask
                    & (GENERIC_ALL
                        | GENERIC_WRITE
                        | DELETE
                        | WRITE_DAC
                        | WRITE_OWNER
                        | FILE_WRITE_DATA
                        | FILE_APPEND_DATA
                        | FILE_WRITE_EA
                        | FILE_WRITE_ATTRIBUTES
                        | FILE_DELETE_CHILD)
                    != 0
                && u32::from(ace.Header.AceFlags) & INHERIT_ONLY_ACE == 0
            {
                return Err(Error::Permissions);
            }
        }
    }
    Ok(())
}

pub(super) fn check_directory(path: &Path, private: bool) -> Result<(), Error> {
    check(&open(path, READ_CONTROL)?, true, private)
}

pub(super) fn prepare(base: &Path) -> Result<PathBuf, Error> {
    fs::create_dir_all(base)?;
    check_directory(base, false)?;
    let parent = base.join("firmica");
    let descriptor = User::current()?.descriptor(true)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let path = wide(&parent)?;
    // SAFETY: live descriptor, terminated path, no secret files exist yet.
    if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::AlreadyExists {
            return Err(error.into());
        }
    }
    check_directory(&parent, true)?;
    Ok(parent)
}

pub(super) fn staging(parent: &Path) -> Result<tempfile::TempDir, Error> {
    // The parent already has a protected user-only inheritable DACL. Harden the
    // new staging directory's owner/inheritance before writing any key material.
    let directory = tempfile::Builder::new()
        .prefix(".browser-tls-")
        .tempdir_in(parent)?;
    let user = User::current()?;
    let descriptor = user.descriptor(true)?;
    let (mut present, mut defaulted, mut acl) = (0, 0, ptr::null_mut());
    // SAFETY: generated descriptor and writable ACL outputs, all live through SetSecurityInfo.
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) }
        == 0
        || present == 0
    {
        return Err(Error::Permissions);
    }
    let file = open(directory.path(), READ_CONTROL | WRITE_DAC | WRITE_OWNER)?;
    let result = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            user.sid(),
            ptr::null_mut(),
            acl,
            ptr::null(),
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32).into());
    }
    check(&file, true, true)?;
    Ok(directory)
}

pub(super) fn read_private(path: &Path) -> Result<SecretBox<Vec<u8>>, Error> {
    let file = open(path, GENERIC_READ | READ_CONTROL)?;
    check(&file, false, true)?;
    if file.metadata()?.len() > MAX_FILE_BYTES {
        return Err(Error::Invalid);
    }
    let mut bytes = SecretBox::new(Box::new(Vec::new()));
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(bytes.expose_secret_mut())?;
    if bytes.expose_secret().len() as u64 > MAX_FILE_BYTES {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}

pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let descriptor = User::current()?.descriptor(false)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let path = wide(path)?;
    // SAFETY: CREATE_NEW never replaces an existing file. The owner-only DACL
    // applies at creation, before any key bytes are written.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_WRITE | READ_CONTROL | FILE_READ_ATTRIBUTES,
            0,
            &attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    let mut file = File::from(owned(handle)?);
    check(&file, false, true)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn publish(staging: &Path, destination: &Path) -> Result<(), Error> {
    let (from, to) = (wide(staging)?, wide(destination)?);
    // SAFETY: same-parent terminated paths; REPLACE_EXISTING/COPY_ALLOWED are
    // deliberately absent, so a concurrent destination is never overwritten.
    if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        let error = io::Error::last_os_error();
        if fs::symlink_metadata(destination).is_ok() {
            return Err(Error::Exists);
        }
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use windows_sys::Win32::Security::UNPROTECTED_DACL_SECURITY_INFORMATION;

    fn acl(path: &Path, descriptor: &Allocation, protected: bool) {
        let (mut present, mut defaulted, mut dacl) = (0, 0, ptr::null_mut());
        // SAFETY: the owned descriptor and its ACL remain live for this fixture update.
        unsafe {
            assert_ne!(
                GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted),
                0
            );
            assert_ne!(present, 0);
            let file = open(path, READ_CONTROL | WRITE_DAC).unwrap();
            let inheritance = if protected {
                PROTECTED_DACL_SECURITY_INFORMATION
            } else {
                UNPROTECTED_DACL_SECURITY_INFORMATION
            };
            assert_eq!(
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | inheritance,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    dacl,
                    ptr::null()
                ),
                0
            );
        }
    }

    #[test]
    fn foreign_read_access_and_unprotected_inheritance_are_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let base = temporary.path().join("config");
        let profile = initialize(&base, "https://example.invalid").unwrap();
        for (sddl, protected) in [
            ("D:P(A;;FA;;;OW)(A;;FR;;;WD)", true),
            ("D:AI(A;;FA;;;OW)", false),
        ] {
            let sddl = format!("{sddl}\0").encode_utf16().collect::<Vec<_>>();
            let mut descriptor = ptr::null_mut();
            // SAFETY: fixed terminated SDDL, writable LocalAlloc output.
            unsafe {
                assert_ne!(
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl.as_ptr(),
                        1,
                        &mut descriptor,
                        ptr::null_mut()
                    ),
                    0
                );
            }
            acl(&profile.key, &Allocation(descriptor), protected);
            assert!(matches!(load(&base), Err(Error::Permissions)));
            acl(
                &profile.key,
                &User::current().unwrap().descriptor(false).unwrap(),
                true,
            );
        }
        assert!(load(&base).unwrap().is_some());
        fs::write(&profile.key, vec![0; MAX_FILE_BYTES as usize + 1]).unwrap();
        assert!(matches!(load(&base), Err(Error::Invalid)));
    }

    #[test]
    fn directory_junctions_and_partial_profiles_fail_closed() {
        let temporary = tempfile::tempdir().unwrap();
        let base = temporary.path().join("config");
        let profile = initialize(&base, "https://example.invalid").unwrap();
        let directory = base.join("firmica/browser-tls");
        let saved = base.join("firmica/saved");
        fs::rename(&directory, &saved).unwrap();
        // PowerShell creates a junction without requiring symlink privileges.
        let output = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command",
                   "$ErrorActionPreference = 'Stop'; New-Item -ItemType Junction -Path $env:FIRMICA_JUNCTION -Value $env:FIRMICA_TARGET | Out-Null"])
            .env("FIRMICA_JUNCTION", &directory).env("FIRMICA_TARGET", &saved)
            .output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(matches!(load(&base), Err(Error::Permissions)));
        fs::remove_dir(&directory).unwrap();
        fs::rename(&saved, &directory).unwrap();
        fs::remove_file(&profile.certificate).unwrap();
        assert!(load(&base).is_err());
    }
}
