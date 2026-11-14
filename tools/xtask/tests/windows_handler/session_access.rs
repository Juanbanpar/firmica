//! Scoped access for a disposable logon to the CI host's existing interactive session.
use super::wide;
use std::{mem, ptr};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree, HANDLE, UNICODE_STRING},
    Security::{
        Authorization::{
            GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS,
            SE_KERNEL_OBJECT, SE_WINDOW_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
        },
        ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    },
    System::{
        LibraryLoader::{GetModuleHandleW, GetProcAddress},
        StationsAndDesktops::{CloseDesktop, CloseWindowStation, OpenDesktopW, OpenWindowStationW},
    },
};

enum Kind {
    Station,
    Desktop,
    Namespace,
}

impl Kind {
    fn security_type(&self) -> i32 {
        match self {
            Self::Namespace => SE_KERNEL_OBJECT,
            _ => SE_WINDOW_OBJECT,
        }
    }
}

pub(super) struct SessionAccess {
    handle: HANDLE,
    kind: Kind,
    descriptor: PSECURITY_DESCRIPTOR,
    original: *mut ACL,
}

impl SessionAccess {
    pub(super) fn grant(sid: &mut [usize; 16], station: bool) -> Self {
        // READ_CONTROL | WRITE_DAC. No Everyone/group ACE is added or replaced.
        let handle = unsafe {
            if station {
                OpenWindowStationW(wide("WinSta0").as_ptr(), 0, 0x0006_0000)
            } else {
                OpenDesktopW(wide("Default").as_ptr(), 0, 0, 0x0006_0000)
            }
        };
        assert!(
            !handle.is_null(),
            "cannot open the interactive desktop object"
        );
        Self::grant_handle(
            handle,
            if station {
                Kind::Station
            } else {
                Kind::Desktop
            },
            0x000f_0000 | if station { 0x037f } else { 0x01ff },
            sid,
        )
    }

    /// A secondary logon shares the host's session, whose named-object directory
    /// is ACLed to its original interactive logon. Give only the disposable logon
    /// ordinary query/traverse/create rights; existing objects retain their ACLs.
    pub(super) fn namespace(sid: &mut [usize; 16], session: u32) -> Self {
        // NtOpenDirectoryObject is documented as a dynamically resolved API:
        // https://learn.microsoft.com/windows/win32/devnotes/ntopendirectoryobject
        let module = unsafe { GetModuleHandleW(wide("ntdll.dll").as_ptr()) };
        assert!(!module.is_null());
        let address = unsafe { GetProcAddress(module, c"NtOpenDirectoryObject".as_ptr().cast()) }
            .expect("NtOpenDirectoryObject is unavailable on this test host");
        let open: unsafe extern "system" fn(*mut HANDLE, u32, *const OBJECT_ATTRIBUTES) -> i32 =
            unsafe { mem::transmute(address) };
        let mut path = wide(format!(r"\Sessions\{session}\BaseNamedObjects"));
        let name = UNICODE_STRING {
            Length: ((path.len() - 1) * 2) as u16,
            MaximumLength: (path.len() * 2) as u16,
            Buffer: path.as_mut_ptr(),
        };
        let attributes = OBJECT_ATTRIBUTES {
            Length: mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
            ObjectName: &name,
            Attributes: 0x40, // OBJ_CASE_INSENSITIVE
            ..Default::default()
        };
        let mut handle = ptr::null_mut();
        let status = unsafe { open(&mut handle, 0x0006_0000, &attributes) };
        assert_eq!(status, 0, "cannot open session namespace: {status:#x}");
        // DIRECTORY_QUERY | DIRECTORY_TRAVERSE | DIRECTORY_CREATE_OBJECT |
        // DIRECTORY_CREATE_SUBDIRECTORY; no ownership or DACL-management rights.
        Self::grant_handle(handle, Kind::Namespace, 0x000f, sid)
    }

    fn grant_handle(handle: HANDLE, kind: Kind, permissions: u32, sid: &mut [usize; 16]) -> Self {
        let mut access = Self {
            handle,
            kind,
            descriptor: ptr::null_mut(),
            original: ptr::null_mut(),
        };
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    handle,
                    access.kind.security_type(),
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut access.original,
                    ptr::null_mut(),
                    &mut access.descriptor,
                )
            },
            0,
            "cannot read session object permissions"
        );
        assert!(
            !access.original.is_null(),
            "refusing an unrestricted session object DACL"
        );
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: permissions,
            grfAccessMode: GRANT_ACCESS,
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: sid.as_mut_ptr().cast(),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut updated = ptr::null_mut();
        assert_eq!(
            unsafe { SetEntriesInAclW(1, &entry, access.original, &mut updated) },
            0
        );
        let status = unsafe {
            SetSecurityInfo(
                handle,
                access.kind.security_type(),
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                updated,
                ptr::null_mut(),
            )
        };
        unsafe {
            LocalFree(updated.cast());
        }
        assert_eq!(status, 0, "cannot grant disposable session access");
        access
    }
}

impl Drop for SessionAccess {
    fn drop(&mut self) {
        let restored = if self.descriptor.is_null() {
            0
        } else {
            unsafe {
                SetSecurityInfo(
                    self.handle,
                    self.kind.security_type(),
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    self.original,
                    ptr::null_mut(),
                )
            }
        };
        unsafe {
            LocalFree(self.descriptor);
            match self.kind {
                Kind::Station => {
                    CloseWindowStation(self.handle);
                }
                Kind::Desktop => {
                    CloseDesktop(self.handle);
                }
                Kind::Namespace => {
                    CloseHandle(self.handle);
                }
            }
        }
        if !std::thread::panicking() {
            assert_eq!(
                restored, 0,
                "cannot restore interactive session permissions"
            );
        }
    }
}
