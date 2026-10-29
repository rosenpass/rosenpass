//! implements function necessary to resolve file/directory paths (i.e. relative paths)
//!
//! implements:
//! - [`ResolvePathRelativeToConfig`]
//! - [`resolve_path_with_tilde`]
//! - [`resolve_relative_path_with_tilde`]

use super::{ConfigSource, ConfigSourceTomlFile, RosenpassConfig};
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
            ConfigSource::CommandLineArguments(_) | ConfigSource::GeneratedFromCode => path
                .resolve_relative_with_tilde(
                    std::env::current_dir().expect("can not determine current working directory"),
                ),
        }
    }
}

/// takes a path that can potentially start with a `~` and resolves that `~` to the user's home directory
///
/// ## Example
/// ```
/// use rosenpass::config::util::resolve_path_with_tilde;
/// let home = home::home_dir().unwrap();
/// let mut path = std::path::PathBuf::from("~/foo.toml");
/// resolve_path_with_tilde(&mut path);
/// assert!(path == home.join("foo.toml"));
/// ```
pub fn resolve_path_with_tilde(path: &mut PathBuf) {
    if let Some(first_segment) = path.iter().next() {
        if !path.has_root() && first_segment == "~" {
            let home_dir = home::home_dir().unwrap_or_else(|| {
                log::error!("config file contains \"~\" but can not determine home diretory");
                std::process::exit(1);
            });
            let orig_path = path.clone();
            path.clear();
            path.push(home_dir);
            for segment in orig_path.iter().skip(1) {
                path.push(segment);
            }
        }
    }
}
/// takes a path that can be relative to a working directory or might start with a `~` and resolves it
///
/// Note: `working_diretory` may not start with a tilde.
///
/// ```
/// use rosenpass::config::util::resolve_relative_path_with_tilde;
/// let path = std::path::PathBuf::from("foo.toml");
/// let working_directory = std::path::PathBuf::from("some_dir");
/// let resolved_path = resolve_relative_path_with_tilde(&path, &working_directory);
/// assert!(resolved_path == working_directory.join(path));
/// ```
pub fn resolve_relative_path_with_tilde(path: &Path, working_directory: &Path) -> PathBuf {
    let mut path = path.to_owned();
    resolve_path_with_tilde(&mut path);
    if !path.is_relative() {
        path
    } else {
        working_directory.join(path)
    }
}

pub trait ResolvePathWithTilde<WDT> {
    fn resolve_relative_with_tilde(&self, working_directory: WDT) -> PathBuf;
}
impl ResolvePathWithTilde<&Path> for PathBuf {
    fn resolve_relative_with_tilde(&self, working_directory: &Path) -> PathBuf {
        resolve_relative_path_with_tilde(self, working_directory)
    }
}
impl ResolvePathWithTilde<PathBuf> for PathBuf {
    fn resolve_relative_with_tilde(&self, working_directory: PathBuf) -> PathBuf {
        resolve_relative_path_with_tilde(self, &working_directory)
    }
}
impl ResolvePathWithTilde<&Path> for &Path {
    fn resolve_relative_with_tilde(&self, working_directory: &Path) -> PathBuf {
        resolve_relative_path_with_tilde(self, working_directory)
    }
}
impl ResolvePathWithTilde<PathBuf> for &Path {
    fn resolve_relative_with_tilde(&self, working_directory: PathBuf) -> PathBuf {
        resolve_relative_path_with_tilde(self, &working_directory)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_resolve_path_with_tilde() {
        let test = |path_str: &str, resolved: PathBuf| {
            let mut path = PathBuf::from(path_str);
            resolve_path_with_tilde(&mut path);
            assert!(
                path == resolved,
                "Path {:?} has been resolved to {:?} but should have been resolved to {:?}.",
                path_str,
                path,
                resolved
            );
        };
        // do not use `std::env::set_var` here because it is unsound in multi-threaded
        // programs and tests are run multi-threaded by default
        let home_dir = home::home_dir().expect("can not determine home directory");

        // should resolve
        test("~/foo.toml", home_dir.join("foo.toml"));
        test("~//foo", home_dir.join("foo"));
        test("~/../other_user/foo", home_dir.join("../other_user/foo"));

        // should _not_ resolve
        test("~foo/bar", PathBuf::from("~foo/bar"));
        test(".~/foo", PathBuf::from(".~/foo"));
        test("/~/foo.toml", PathBuf::from("/~/foo.toml"));
        test(r"~\foo", PathBuf::from(r"~\foo"));
        test(r"C:\~\foo.toml", PathBuf::from(r"C:\~\foo.toml"));
    }
    #[test]
    fn test_resolve_relative_path_with_tilde() {
        let home_dir = home::home_dir().expect("can not determine home directory");
        let working_dir = PathBuf::from("/foo/bar");
        assert_ne!(
            home_dir, working_dir,
            "home dir and working dir are unexpectedly the same"
        );
        let test = |path_str: &str, resolved: PathBuf| {
            let result = resolve_relative_path_with_tilde(&PathBuf::from(path_str), &working_dir);
            assert_eq!(
                result, resolved,
                "Path {:?} has been resolved to {:?} but should have been resolved to {:?}.",
                path_str, result, resolved
            )
        };

        // should resolve
        test("~/foo.toml", home_dir.join("foo.toml"));
        test("foo.toml", working_dir.join("foo.toml"));
        test("a/b.toml", working_dir.join("a").join("b.toml"));

        // should _not_ resolve
        // TODO
    }
}
