//! utility functions used internally for configuration validation
//!
//! This module includes:
//! - [`AttemptRead`]: a trait implemented for [`std::path::PathBuf`] check certains properties on a file (e.g. whether it is readable)
//! - [`validate_keypair`]: a macro to run certain checks on a keypair (e.g. whether it is readable from disk)

use anyhow::anyhow;
use rustix::path::Arg;

/// TODO: rename trait
pub trait AttemptRead {
    /// attempts to open a file in read mode
    ///
    /// - if successful: closes the file immediately and returns `Ok(())`
    /// - if failed: does not open the file in the first place and returns `Err(std::io::Error)`
    fn attempt_read(&self) -> Result<(), std::io::Error>;

    /// whether the file is world-readable
    ///
    /// This means readable without any specific user's persmission, i.e. readable for all
    /// users on the OS.
    fn is_world_readable(&self) -> Option<bool>;

    /// attempts to open a file in write mode (but does not write anything)
    ///
    /// - if successful: closes the file immediately (without writing anything) and returns `Ok(())`
    /// - if failed: does not open the file in the first place and returns `Err(std::io::Error)`
    fn attempt_write(&self) -> Result<(), std::io::Error>;

    /// checks whether a file has the "executable" flag
    fn is_executable(&self) -> bool;

    /// checks whether a binary file behaves like the `wg` WireGuard binary
    fn behaves_like_wg_binary(&self) -> bool;
}
impl AttemptRead for std::path::PathBuf {
    fn attempt_read(&self) -> Result<(), std::io::Error> {
        let result = std::fs::OpenOptions::new()
            .read(true)
            .write(false)
            .open(self.clone());
        match result {
            Err(err) => Err(err),
            Ok(f) => {
                std::mem::drop(f);
                Ok(())
            }
        }
    }
    #[cfg(target_os = "linux")]
    fn is_world_readable(&self) -> Option<bool> {
        use std::os::unix::fs::PermissionsExt;
        self.metadata()
            .ok()
            .map(|metadata| metadata.permissions().mode() & 0o004 != 0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    fn is_world_readable(&self) -> Option<bool> {
        // TODO: implement
        None
    }
    #[cfg(target_os = "windows")]
    fn is_world_readable(&self) -> Option<bool> {
        None

        // TODO: implement this for windows
        // example implementation:
        // use std::ffi::c_void;
        // use std::mem::{size_of, zeroed};
        // use std::os::windows::ffi::OsStrExt;
        // use std::ptr::null_mut;

        // use windows_sys::Win32::{
        //     Foundation::{ERROR_SUCCESS, LocalFree},
        //     Security::{
        //         ACL,
        //         Authorization::{
        //             BuildTrusteeWithSidW, GetEffectiveRightsFromAclW, GetNamedSecurityInfoW,
        //             SE_FILE_OBJECT, TRUSTEE_W,
        //         },
        //         CreateWellKnownSid, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        //         SECURITY_MAX_SID_SIZE, WinWorldSid,
        //     },
        //     Storage::FileSystem::FILE_READ_DATA,
        // };

        // // GetNamedSecurityInfoW erwartet einen NUL-terminierten UTF-16-Pfad.
        // let path_wide: Vec<u16> = path
        //     .as_os_str()
        //     .encode_wide()
        //     .chain(std::iter::once(0))
        //     .collect();

        // let mut dacl: *mut ACL = null_mut();
        // let mut security_descriptor: PSECURITY_DESCRIPTOR = null_mut();

        // let result = unsafe {
        //     GetNamedSecurityInfoW(
        //         path_wide.as_ptr(),
        //         SE_FILE_OBJECT,
        //         DACL_SECURITY_INFORMATION,
        //         null_mut(),
        //         null_mut(),
        //         &mut dacl,
        //         null_mut(),
        //         &mut security_descriptor,
        //     )
        // };

        // if result != ERROR_SUCCESS {
        //     return Err(std::io::Error::from_raw_os_error(result as i32));
        // }

        // // GetNamedSecurityInfoW alloziert den Security Descriptor mit LocalAlloc.
        // struct SecurityDescriptorGuard(PSECURITY_DESCRIPTOR);

        // impl Drop for SecurityDescriptorGuard {
        //     fn drop(&mut self) {
        //         if !self.0.is_null() {
        //             unsafe {
        //                 LocalFree(self.0.cast::<c_void>());
        //             }
        //         }
        //     }
        // }

        // let _guard = SecurityDescriptorGuard(security_descriptor);

        // // Keine DACL / NULL DACL bedeutet uneingeschränkten Zugriff.
        // if dacl.is_null() {
        //     return Ok(true);
        // }

        // // Buffer für die Well-Known-SID "Everyone" (S-1-1-0).
        // // usize sorgt nebenbei für ausreichendes Alignment.
        // const SID_WORDS: usize =
        //     (SECURITY_MAX_SID_SIZE as usize + size_of::<usize>() - 1) / size_of::<usize>();

        // let mut sid_buffer = [0usize; SID_WORDS];
        // let mut sid_size = size_of::<[usize; SID_WORDS]>() as u32;
        // let everyone_sid: PSID = sid_buffer.as_mut_ptr().cast();

        // if unsafe { CreateWellKnownSid(WinWorldSid, null_mut(), everyone_sid, &mut sid_size) }
        //     == 0
        // {
        //     return Err(std::io::Error::last_os_error());
        // }

        // let mut trustee: TRUSTEE_W = unsafe { zeroed() };

        // unsafe {
        //     BuildTrusteeWithSidW(&mut trustee, everyone_sid);
        // }

        // let mut rights = 0u32;

        // let result = unsafe { GetEffectiveRightsFromAclW(dacl, &mut trustee, &mut rights) };

        // if result != ERROR_SUCCESS {
        //     return Err(std::io::Error::from_raw_os_error(result as i32));
        // }

        // Some(rights & FILE_READ_DATA != 0)
    }

    fn attempt_write(&self) -> Result<(), std::io::Error> {
        let result = std::fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open(self.clone());
        match result {
            Err(err) => Err(err),
            Ok(f) => {
                std::mem::drop(f);
                Ok(())
            }
        }
    }
    fn is_executable(&self) -> bool {
        use rustix::fs::{Access, AtFlags, CWD, accessat};
        accessat(CWD, self, Access::EXEC_OK, AtFlags::EACCESS).is_ok()

        // unix-specific implementation
        // use std::os::unix::fs::PermissionsExt;
        // self.metadata()
        //     .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        //     .unwrap_or(false)
    }
    fn behaves_like_wg_binary(&self) -> bool {
        let implementation = || -> Result<(), anyhow::Error> {
            let command_name = self.to_string_lossy();
            if !std::process::Command::new(self)
                .arg("--version")
                .output()?
                .stdout
                .to_string_lossy()
                .to_lowercase()
                .contains("wireguard")
            {
                return Err(anyhow!(
                    "output generated with `{command_name} --version` does not contain the string `wireguard`"
                ));
            }
            Ok(())
            // TODO: check if `wg set` is available
        };
        implementation().is_ok() // TODO: return error?
    }
}

macro_rules! validate_keypair {
    ($secret_path: expr, $public_path: expr, $warnings: ident, $errors: ident, $recipe: ident,
        $context: expr,
        $SecretKeyFileDoesNotExist: ident, $SecretKeyFileCanNotBeRead: ident, $SecretKeyFileHasInvalidContent: ident, $SecretKeyFileIsGloballyReadable: ident,
        $PublicKeyFileDoesNotExist: ident, $PublicKeyFileCanNotBeRead: ident, $PublicKeyFileHasInvalidContent: ident,
    ) => {
        if !$secret_path.is_file() {
            if $recipe.check_whether_files_exist {
                $errors.push(Error::$SecretKeyFileDoesNotExist(
                    $context,
                    $secret_path.clone(),
                ));
            }
        } else {
            // our secret key file exists
            if let Err(err) = $secret_path.attempt_read() {
                if $recipe.check_file_permissions {
                    $errors.push(Error::$SecretKeyFileCanNotBeRead(
                        $context,
                        $secret_path.clone(),
                        err,
                    ));
                }
            } else {
                // our secret key file exists and is readable
                if $recipe.check_file_permissions
                    && let Some(true) = $secret_path.is_world_readable()
                {
                    $warnings.push(Warning::$SecretKeyFileIsGloballyReadable(
                        $context,
                        $secret_path.clone(),
                    ));
                }
                if $recipe.check_key_file_contents {
                    if let Err(_err) = SSk::load(&$secret_path) {
                        $errors.push(Error::$SecretKeyFileHasInvalidContent(
                            $context,
                            $secret_path.clone(),
                        ));
                    }
                }
            }
        }
        if !$public_path.is_file() {
            if $recipe.check_whether_files_exist {
                $errors.push(Error::$PublicKeyFileDoesNotExist(
                    $context,
                    $public_path.clone(),
                ));
            }
        } else {
            // our public key file exists
            if let Err(err) = $public_path.attempt_read() {
                if $recipe.check_file_permissions {
                    $errors.push(Error::$PublicKeyFileCanNotBeRead(
                        $context,
                        $public_path.clone(),
                        err,
                    ));
                }
            } else {
                // our public key file exists and is readable
                if $recipe.check_key_file_contents {
                    if let Err(_err) = SPk::load(&$public_path) {
                        $errors.push(Error::$PublicKeyFileHasInvalidContent(
                            $context,
                            $public_path.clone(),
                        ));
                    }
                }
            }
        }
    };
    ($secret_path: expr, $public_path: expr, $warnings: ident, $errors: ident, $recipe: ident,
        $SecretKeyFileDoesNotExist: ident, $SecretKeyFileCanNotBeRead: ident, $SecretKeyFileHasInvalidContent: ident, $SecretKeyFileIsGloballyReadable: ident,
        $PublicKeyFileDoesNotExist: ident, $PublicKeyFileCanNotBeRead: ident, $PublicKeyFileHasInvalidContent: ident,
    ) => {
        if !$secret_path.is_file() {
            if $recipe.check_whether_files_exist {
                $errors.push(Error::$SecretKeyFileDoesNotExist($secret_path.clone()));
            }
        } else {
            // our secret key file exists
            if let Err(err) = $secret_path.attempt_read() {
                if $recipe.check_file_permissions {
                    $errors.push(Error::$SecretKeyFileCanNotBeRead($secret_path.clone(), err));
                }
            } else {
                // our secret key file exists and is readable
                if $recipe.check_file_permissions
                    && let Some(true) = $secret_path.is_world_readable()
                {
                    $warnings.push(Warning::$SecretKeyFileIsGloballyReadable(
                        $secret_path.clone(),
                    ));
                }
                if $recipe.check_key_file_contents {
                    if let Err(_err) = SSk::load(&$secret_path) {
                        $errors.push(Error::$SecretKeyFileHasInvalidContent($secret_path.clone()));
                    }
                }
            }
        }
        if !$public_path.is_file() {
            if $recipe.check_whether_files_exist {
                $errors.push(Error::$PublicKeyFileDoesNotExist($public_path.clone()));
            }
        } else {
            // our public key file exists
            if let Err(err) = $public_path.attempt_read() {
                if $recipe.check_file_permissions {
                    $errors.push(Error::$PublicKeyFileCanNotBeRead($public_path.clone(), err));
                }
            } else {
                // our public key file exists and is readable
                if $recipe.check_key_file_contents {
                    if let Err(_err) = SPk::load(&$public_path) {
                        $errors.push(Error::$PublicKeyFileHasInvalidContent($public_path.clone()));
                    }
                }
            }
        }
    };
}
pub(crate) use validate_keypair;
