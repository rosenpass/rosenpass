//! provides validation of a given [`RosenpassConfig`]
//!
//! Functions and Types from this module which you might want to use
//! - [`RosenpassConfig::validate`]
//! - [`Error`], [`Warning`], [`Issue`]
//! - [`ValidationRecipe`], [`ValidationRecipeBuilder`]
//!
//! This module contains submodules:
//! - [`implementation`]: actual implementation of [`RosenpassConfig::validate`]
//! - [`error`]: error and warning types (the outcome of a validation)
//! - [`util`]: utility functions used internally in this module

pub mod error;
pub mod implementation;
pub mod util;

pub use error::{Error, Issue, Warning};

// allow unused import because the import is actually used in the doc comment which clippy does not
// identify correctly
#[allow(unused_imports)]
use super::RosenpassConfig;

/// specifies which validation checks are supposed to run on a given [`RosenpassConfig`] when
/// calling [`RosenpassConfig::validate`]
#[derive(Debug, Clone, Copy)]
pub struct ValidationRecipe {
    /// check inconsistencies between configuration items
    ///
    /// The parsers and the [`RosenpassConfig`] type declaration already put heavy constraints on
    /// the configuration. However, it is still possible to generate an inconsistent
    /// [`RosenpassConfig`]. This ingredient will find (almost?) all inconsistencies so that the
    /// code after a call to [`RosenpassConfig::validate`] can call `unwrap` without restraint.
    pub check_inconsistencies: bool,

    /// emit a warning for disabled peers and WireGuard devices
    pub warn_about_disabled_entries: bool,

    /// check whether the referenced files actually exist – this concerns mostly key private/public
    /// key files
    pub check_whether_files_exist: bool,

    /// check whether the necessary the process has the necessary file permissions
    /// - key files need to be readable
    /// - output files (logging/key_out) must be writable
    /// - specified binaries (probably legacy) need to be executable
    /// - potentially more checks
    pub check_file_permissions: bool,

    /// check whether specified external executable binaries behave as expected
    ///
    /// This is probably legacy – users were able to specify the `wg` binary in Rosenpass version
    /// 0.2 through an `exchange_command` in the configuration TOML file but it will be deprecated
    pub check_whether_external_binaries_behave: bool,

    /// check the contents of specified files for pausibility
    ///
    /// Specifically, key files are checked whether their content is indeed a valid key.
    pub check_key_file_contents: bool,

    pub look_up_hostnames: bool,
}
impl ValidationRecipe {
    pub fn nothing() -> ValidationRecipe {
        ValidationRecipe {
            check_inconsistencies: false,
            warn_about_disabled_entries: false,
            check_whether_files_exist: false,
            check_file_permissions: false,
            check_whether_external_binaries_behave: false,
            check_key_file_contents: false,
            look_up_hostnames: false,
        }
    }
    pub fn all() -> ValidationRecipe {
        ValidationRecipe {
            check_inconsistencies: true,
            warn_about_disabled_entries: true,
            check_whether_files_exist: true,
            check_file_permissions: true,
            check_whether_external_binaries_behave: true,
            check_key_file_contents: true,
            look_up_hostnames: true,
        }
    }
}
impl Default for ValidationRecipe {
    fn default() -> Self {
        ValidationRecipe::all()
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ValidationRecipeBuilder(ValidationRecipe);
impl ValidationRecipeBuilder {
    pub fn build(&self) -> ValidationRecipe {
        self.0 // ValidationRecipe implements `Copy`
    }
    pub fn new_empty() -> Self {
        Self(ValidationRecipe::nothing())
    }
    pub fn new_all() -> Self {
        Self(ValidationRecipe::all())
    }
    pub fn check_inconsistencies(mut self, check: bool) -> Self {
        self.0.check_inconsistencies = check;
        self
    }
    pub fn warn_about_disabled_entries(mut self, check: bool) -> Self {
        self.0.warn_about_disabled_entries = check;
        self
    }
    pub fn check_whether_files_exist(mut self, check: bool) -> Self {
        self.0.check_whether_files_exist = check;
        self
    }
    pub fn check_file_permissions(mut self, check: bool) -> Self {
        self.0.check_file_permissions = check;
        self
    }
    pub fn check_whether_external_binaries_behave(mut self, check: bool) -> Self {
        self.0.check_whether_external_binaries_behave = check;
        self
    }
    pub fn check_key_file_contents(mut self, check: bool) -> Self {
        self.0.check_key_file_contents = check;
        self
    }
    pub fn look_up_hostnames(mut self, check: bool) -> Self {
        self.0.look_up_hostnames = check;
        self
    }
}
