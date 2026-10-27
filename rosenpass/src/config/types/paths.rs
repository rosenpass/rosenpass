//! implements [`ResolvePathRelativeToConfig`]

use super::{ConfigSource, ConfigSourceTomlFile, RosenpassConfig};
use crate::oldconfig::util::ResolvePathWithTilde;
use std::path::{Path, PathBuf};

pub trait ResolvePathRelativeToConfig {
    fn resolve_path(&self, path: &Path) -> PathBuf;
}

impl ResolvePathRelativeToConfig for ConfigSourceTomlFile {
    fn resolve_path(&self, path: &Path) -> PathBuf {
        path.resolve_relative_with_tilde(
            self.file_path
                .parent()
                .expect("can not determine parent of config file path"),
        )
    }
}
impl ResolvePathRelativeToConfig for RosenpassConfig {
    fn resolve_path(&self, path: &Path) -> PathBuf {
        match &self.parsed_from {
            ConfigSource::TomlFile(file) => file.resolve_path(path),
        }
    }
}
