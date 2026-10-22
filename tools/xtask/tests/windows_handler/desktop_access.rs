//! Temporary access for the disposable account to this test host's interactive desktop.
use super::wide;
use std::ptr;
use windows_sys::Win32::{
    Foundation::{LocalFree, HANDLE},
    Security::{
        Authorization::{
            GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo, EXPLICIT_ACCESS_W, GRANT_ACCESS,
            SE_WINDOW_OBJECT, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
        },
        ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    },
    System::StationsAndDesktops::{
        CloseDesktop, CloseWindowStation, OpenDesktopW, OpenWindowStationW,
    },
};

pub(super) struct DesktopAccess {
    handle: HANDLE,
    station: bool,
    descriptor: PSECURITY_DESCRIPTOR,
    original: *mut ACL,
}

impl DesktopAccess {
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
        let mut access = Self {
            handle,
            station,
            descriptor: ptr::null_mut(),
            original: ptr::null_mut(),
        };
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    handle,
                    SE_WINDOW_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut access.original,
                    ptr::null_mut(),
                    &mut access.descriptor,
                )
            },
            0,
            "cannot read desktop permissions"
        );
        assert!(
            !access.original.is_null(),
            "refusing an unrestricted desktop DACL"
        );
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: 0x000f_0000 | if station { 0x037f } else { 0x01ff },
            grfAccessMode: GRANT_ACCESS,
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
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
                SE_WINDOW_OBJECT,
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
        assert_eq!(status, 0, "cannot grant disposable desktop access");
        access
    }
}

impl Drop for DesktopAccess {
    fn drop(&mut self) {
        let restored = if self.descriptor.is_null() {
            0
        } else {
            unsafe {
                SetSecurityInfo(
                    self.handle,
                    SE_WINDOW_OBJECT,
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
            if self.station {
                CloseWindowStation(self.handle);
            } else {
                CloseDesktop(self.handle);
            }
        }
        if !std::thread::panicking() {
            assert_eq!(
                restored, 0,
                "cannot restore interactive desktop permissions"
            );
        }
    }
}
