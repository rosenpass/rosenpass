//! provides validation of a given [`RosenpassConfig`]
//!
//! Functions and Types from this module which you might want to use
//! - [`RosenpassConfig::validate`]
//! - [`Error`], [`Warning`], [`Issue`]
//!
//! This module includes:
//! - [`error`]: error and warning types (the outcome of a validation)
//! - [`implementation`]: actual implementation of [`RosenpassConfig::validate`]
//! - [`util`]: utility functions used internally in this module

pub mod error;
mod implementation;
mod util;

pub use error::{Error, Issue, Warning};

// allow unused import because the import is actually used in the doc comment which clippy does not
// identify correctly
#[allow(unused_imports)]
use super::RosenpassConfig;

#[derive(Debug)]
pub struct ValidationRecipe {
    pub check_inconsistencies: bool,
    pub check_whether_files_exist: bool,
    pub check_file_permissions: bool,
    pub check_whether_external_binaries_behave: bool,
    pub check_key_file_contents: bool,
}
impl ValidationRecipe {
    pub fn nothing() -> ValidationRecipe {
        ValidationRecipe {
            check_inconsistencies: false,
            check_whether_files_exist: false,
            check_file_permissions: false,
            check_whether_external_binaries_behave: false,
            check_key_file_contents: false,
        }
    }
    pub fn all() -> ValidationRecipe {
        ValidationRecipe {
            check_inconsistencies: true,
            check_whether_files_exist: true,
            check_file_permissions: true,
            check_whether_external_binaries_behave: true,
            check_key_file_contents: true,
        }
    }
}
impl Default for ValidationRecipe {
    fn default() -> Self {
        ValidationRecipe::all()
    }
}
