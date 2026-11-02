#![cfg(test)]
//! unit tests for [`crate::cli::parse_cmd`]

use std::{fmt, path::PathBuf};

use anstyle::AnsiColor;

use super::{CliCommand, FlatCliCommand, GenKeysParameters, GenKeysPathsSource};
use crate::{cli::CliGrammar, config::tests::test_cli::harness::replace_spaces};

// TODO: write all these tests for `rp`, too

/// wrapper a round [`parse_cmd`] for unit tests
///
/// determines the grammar from the first parameter being either `rosenpass` or `rp` – never do this
/// in production, this is for unit tests only!
fn parse_cmd(command_line: &str) -> Result<(CliCommand, String), anyhow::Error> {
    // start preparing the command line
    let command_line = command_line.trim();

    // print command line for easier debugging
    let output = fmt::from_fn(move |f| {
        let bold = anstyle::Style::new().bold();
        let blue = AnsiColor::BrightBlue.on_default();
        writeln!(
            f,
            "{bold}parsing command line:{bold:#}\n{blue}{command_line}{blue:#}"
        )
    });
    anstream::eprintln!("{}", output);

    // finish preparing the command line
    let command_line = replace_spaces(command_line);

    // determine the grammar: in unit tests, this is determined by the first parameter being
    // either `rosenpass` or `rp`. Of course in production, the grammar is baked into each binary.
    let grammar = match command_line
        .split('\0')
        .next()
        .expect("can not process empty command line")
    {
        "rosenpass" => CliGrammar::Rosenpass,
        "rp" => CliGrammar::Rp,
        name => panic!("can not run unit test with unkown grammar \"{name}\""),
    };

    // parse
    let result = CliCommand::parse(command_line.as_str(), grammar);

    // return
    result
}

// mod exchange {} This subcommand is already tested in `crate::config::tests`

mod exchange_config {
    // TODO: test exchange-config
}
mod generate_config {
    use super::*;

    #[test]
    fn rosenpass_parse_generate_config_no_force() {
        let (CliCommand::GenConfig(parameters), _) =
            parse_cmd("rosenpass gen-config some/path").unwrap()
        else {
            panic!("parsing failed");
        };
        assert_eq!(parameters.config_file, PathBuf::from("some/path"));
        assert!(!parameters.force);
    }
    #[test]
    fn rosenpass_parse_generate_config_force_short() {
        let (CliCommand::GenConfig(parameters), _) =
            parse_cmd("rosenpass gen-config -f some/path").unwrap()
        else {
            panic!("parsing failed");
        };
        assert_eq!(parameters.config_file, PathBuf::from("some/path"));
        assert!(parameters.force);
    }
    #[test]
    fn rosenpass_parse_generate_config_force_long() {
        let (CliCommand::GenConfig(parameters), _) =
            parse_cmd("rosenpass gen-config some/path --force").unwrap()
        else {
            panic!("parsing failed");
        };
        assert_eq!(parameters.config_file, PathBuf::from("some/path"));
        assert!(parameters.force);
    }
    #[test]
    fn rp_parse_generate_config_not_supported() {
        assert!(
            parse_cmd("rp gen-config some/path")
                .expect_err("expected parser to fail")
                .to_string()
                .contains("this subcommand only exists for the rosenpass tool")
        );
    }
}
mod generate_keys {
    use super::*;

    #[test]
    fn rosenpass_parse_genkeys_short() {
        let (
            CliCommand::GenKeys(GenKeysParameters {
                file_paths,
                force: true,
            }),
            _,
        ) = parse_cmd("rosenpass gen-keys -s foo -p bar -f").unwrap()
        else {
            panic!("parsing failed");
        };
        let GenKeysPathsSource::Raw {
            // rosenpass works on files, not on directories and thus does not create the directory
            generate_directory: None,
            secret_key_file,
            public_key_file,
            wg_secret_key_file: None, // rosenpass does not generate WireGuard keys
        } = file_paths
        else {
            panic!("parsing failed");
        };
        assert_eq!(secret_key_file, PathBuf::from("foo"),);
        assert_eq!(public_key_file, PathBuf::from("bar"),);
    }

    #[test]
    fn rosenpass_parse_genkeys_legacy() {
        let (
            CliCommand::GenKeys(GenKeysParameters {
                file_paths,
                force: false,
            }),
            _,
        ) = parse_cmd("rosenpass gen-keys --private-key foo --public-key bar").unwrap()
        else {
            panic!("parsing failed");
        };
        let GenKeysPathsSource::Raw {
            // rosenpass works on files, not on directories and thus does not create the directory
            generate_directory: None,
            secret_key_file,
            public_key_file,
            wg_secret_key_file: None, // rosenpass does not generate WireGuard keys
        } = file_paths
        else {
            panic!("parsing failed");
        };
        assert_eq!(secret_key_file, PathBuf::from("foo"),);
        assert_eq!(public_key_file, PathBuf::from("bar"),);
    }
    #[test]
    fn rp_parse_genkeys() {
        for set_force in [false, true] {
            let CliCommand::GenKeys(GenKeysParameters {
                file_paths:
                    GenKeysPathsSource::Raw {
                        generate_directory,
                        secret_key_file,
                        public_key_file,
                        wg_secret_key_file,
                    },
                force,
            }) = parse_cmd(
                format!(
                    "rp genkey some/dir {}",
                    // if set_force { "-f" } else { "" }
                    // https://github.com/rosenpass/rosenpass/issues/1201
                    ""
                )
                .as_str(),
            )
            .unwrap()
            .0
            else {
                panic!("parsing failed")
            };
            let dir = PathBuf::from("some/dir");
            assert_eq!(generate_directory, Some(dir.clone()));
            assert_eq!(secret_key_file, dir.join("pqsk"));
            assert_eq!(public_key_file, dir.join("pqpk"));
            assert_eq!(wg_secret_key_file, Some(dir.join("wgsk")));
            // assert_eq!(force, set_force);
            // https://github.com/rosenpass/rosenpass/issues/1201
            assert!(!force);
        }
    }
}
// TODO: implement: generate public keys
mod help {
    use super::*;
    #[test]
    fn rosenpass_parse_help_subcommand() {
        let (CliCommand::Help((Some(FlatCliCommand::Exchange), CliGrammar::Rosenpass)), _) =
            parse_cmd("rosenpass help exchange").unwrap()
        else {
            panic!("parsing failed")
        };
    }

    #[test]

    fn rosenpass_parse_help_option() {
        let (CliCommand::Help((Some(FlatCliCommand::Exchange), CliGrammar::Rosenpass)), _) =
            parse_cmd("rosenpass exchange --help").unwrap()
        else {
            panic!("parsing failed")
        };
    }

    #[test]

    fn rosenpass_parse_help_option_at_end() {
        let (CliCommand::Help((Some(FlatCliCommand::Exchange), CliGrammar::Rosenpass)), _) =
            parse_cmd("rosenpass exchange foo bar listen 1.2.3.4:2345 --help").unwrap()
        else {
            panic!("parsing failed")
        };
    }

    #[test]

    fn rosenpass_parse_help_option_in_middle() {
        let (CliCommand::Help((Some(FlatCliCommand::Exchange), CliGrammar::Rosenpass)), _) =
            parse_cmd("rosenpass exchange foo bar listen 1.2.3.4:2345 --help listen 2.3.4.5:3456")
                .unwrap()
        else {
            panic!("parsing failed")
        };
    }
    #[test]
    fn parse_bare_help() {
        let lines = vec![
            "rosenpass",
            "rosenpass --help",
            "rosenpass -h",
            "rosenpass help",
        ];
        for line in lines {
            let CliCommand::Help((None, CliGrammar::Rosenpass)) = parse_cmd(line).unwrap().0 else {
                panic!("parsing failed");
            };
        }
    }

    #[test]
    fn rosenpass_invalid_subcommand() {
        assert!(
            parse_cmd("rosenpass foo bar")
                .expect_err("excpected error")
                .to_string()
                .contains("Expected [")
        )
    }

    #[test]
    fn rp_invalid_subcommand() {
        assert!(
            parse_cmd("rp foo bar")
                .expect_err("expected error")
                .to_string()
                .contains("Expected [")
        );
    }
}
mod validate {
    use super::*;
    #[test]
    fn parse_validate_one() {
        let (CliCommand::Validate(paths), _) = parse_cmd("rosenpass validate path/file").unwrap()
        else {
            panic!("parsing failed")
        };
        assert_eq!(paths, vec![PathBuf::from("path/file")]);
    }
    #[test]
    fn parse_validate_many() {
        let (CliCommand::Validate(paths), _) =
            parse_cmd("rosenpass validate file1 foo/file2 foo/bar/file3").unwrap()
        else {
            panic!("parsing failed")
        };
        assert_eq!(
            paths,
            vec![
                PathBuf::from("file1"),
                PathBuf::from("foo/file2"),
                PathBuf::from("foo/bar/file3")
            ]
        );
    }
    #[test]
    fn rp_does_not_support_validate() {
        assert!(
            parse_cmd("rp validate file1")
                .expect_err("expected error")
                .to_string()
                .contains("this subcommand only exists for the rosenpass tool")
        );
    }
}
mod generate_manpage {
    use super::*;
    #[test]
    fn parse_generate_manpage() {
        for tool in ["rosenpass", "rp"] {
            let (CliCommand::GenerateManpage(path), _) =
                parse_cmd(&format!("{tool} --generate-manpage some/path")).unwrap()
            else {
                panic!("parsing failed");
            };
            assert_eq!(path, PathBuf::from("some/path"))
        }
    }

    #[test]
    fn parse_generate_manpage_refuses_multiple_paths() {
        assert!(parse_cmd("rosenpass --generate-manpage some/path additional/path",).is_err());
    }
}

// ======================================== TODO: shell completion ========================================
