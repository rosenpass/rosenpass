use std::path::PathBuf;

/// takes a path that can potentially start with a `~` and resolves that `~` to the user's home directory
///
/// ## Example
/// ```
/// use rosenpass::config::resolve_path_with_tilde;
/// std::env::set_var("HOME","/home/dummy");
/// let mut path = std::path::PathBuf::from("~/foo.toml");
/// resolve_path_with_tilde(&mut path);
/// assert!(path == std::path::PathBuf::from("/home/dummy/foo.toml"));
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

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_resolve_path_with_tilde() {
        let test = |path_str: &str, resolved: &str| {
            let mut path = PathBuf::from(path_str);
            resolve_path_with_tilde(&mut path);
            assert!(
                path == PathBuf::from(resolved),
                "Path {:?} has been resolved to {:?} but should have been resolved to {:?}.",
                path_str,
                path,
                resolved
            );
        };
        // set environment because otherwise the test result would depend on the system running this
        std::env::set_var("USER", "dummy");
        std::env::set_var("HOME", "/home/dummy");

        // should resolve
        test("~/foo.toml", "/home/dummy/foo.toml");
        test("~//foo", "/home/dummy/foo");
        test("~/../other_user/foo", "/home/dummy/../other_user/foo");

        // should _not_ resolve
        test("~foo/bar", "~foo/bar");
        test(".~/foo", ".~/foo");
        test("/~/foo.toml", "/~/foo.toml");
        test(r"~\foo", r"~\foo");
        test(r"C:\~\foo.toml", r"C:\~\foo.toml");
    }
}
