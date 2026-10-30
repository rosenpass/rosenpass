#![cfg(test)]
//! unit tests for [`crate::cli::CliCommand::parse`]

use std::path::PathBuf;

use super::{CliCommand, FlatCliCommand, GenKeysParameters, GenKeysPathsSource};
use crate::config::tests::test_cli::harness::replace_spaces;

// ======================================== TODO: exchange ========================================

// ======================================== TODO: exchange config ========================================

// ======================================== generate config ========================================
#[test]
fn parse_generate_config_no_force() {
    let CliCommand::GenConfig(parameters) =
        CliCommand::parse(&replace_spaces("rosenpass gen-config some/path")).unwrap()
    else {
        panic!("parsing failed");
    };
    assert_eq!(parameters.config_file, PathBuf::from("some/path"));
    assert!(!parameters.force);
}
#[test]
fn parse_generate_config_force_short() {
    let CliCommand::GenConfig(parameters) =
        CliCommand::parse(&replace_spaces("rosenpass gen-config -f some/path")).unwrap()
    else {
        panic!("parsing failed");
    };
    assert_eq!(parameters.config_file, PathBuf::from("some/path"));
    assert!(parameters.force);
}
#[test]
fn parse_generate_config_force_long() {
    let CliCommand::GenConfig(parameters) =
        CliCommand::parse(&replace_spaces("rosenpass gen-config some/path --force")).unwrap()
    else {
        panic!("parsing failed");
    };
    assert_eq!(parameters.config_file, PathBuf::from("some/path"));
    assert!(parameters.force);
}

// ======================================== generate keys ========================================
#[test]
fn parse_genkeys_short() {
    let CliCommand::GenKeys(GenKeysParameters {
        file_paths,
        force: true,
    }) = CliCommand::parse(&replace_spaces("rosenpass gen-keys -s foo -p bar -f")).unwrap()
    else {
        panic!("parsing failed");
    };
    let GenKeysPathsSource::Raw {
        secret_key_file,
        public_key_file,
    } = file_paths
    else {
        panic!("parsing failed");
    };
    assert_eq!(secret_key_file, PathBuf::from("foo"),);
    assert_eq!(public_key_file, PathBuf::from("bar"),);
}

#[test]
fn parse_genkeys_legacy() {
    let CliCommand::GenKeys(GenKeysParameters {
        file_paths,
        force: false,
    }) = CliCommand::parse(&replace_spaces(
        "rosenpass gen-keys --private-key foo --public-key bar",
    ))
    .unwrap()
    else {
        panic!("parsing failed");
    };
    let GenKeysPathsSource::Raw {
        secret_key_file,
        public_key_file,
    } = file_paths
    else {
        panic!("parsing failed");
    };
    assert_eq!(secret_key_file, PathBuf::from("foo"),);
    assert_eq!(public_key_file, PathBuf::from("bar"),);
}

// ======================================== help ========================================
#[test]
fn parse_help_subcommand() {
    let CliCommand::Help(Some(FlatCliCommand::Exchange)) =
        CliCommand::parse(&replace_spaces("rosenpass help exchange")).unwrap()
    else {
        panic!("parsing failed")
    };
}

#[test]

fn parse_help_option() {
    let CliCommand::Help(Some(FlatCliCommand::Exchange)) =
        CliCommand::parse(&replace_spaces("rosenpass exchange --help")).unwrap()
    else {
        panic!("parsing failed")
    };
}

#[test]

fn parse_help_option_at_end() {
    let CliCommand::Help(Some(FlatCliCommand::Exchange)) = CliCommand::parse(&replace_spaces(
        "rosenpass exchange foo bar listen 1.2.3.4:2345 --help",
    ))
    .unwrap() else {
        panic!("parsing failed")
    };
}

#[test]

fn parse_help_option_in_middle() {
    let CliCommand::Help(Some(FlatCliCommand::Exchange)) = CliCommand::parse(&replace_spaces(
        "rosenpass exchange foo bar listen 1.2.3.4:2345 --help listen 2.3.4.5:3456",
    ))
    .unwrap() else {
        panic!("parsing failed")
    };
}

// ======================================== validate ========================================
#[test]
fn parse_validate_one() {
    let CliCommand::Validate(paths) =
        CliCommand::parse(&replace_spaces("rosenpass validate path/file")).unwrap()
    else {
        panic!("parsing failed")
    };
    assert_eq!(paths, vec![PathBuf::from("path/file")]);
}
#[test]
fn parse_validate_many() {
    let CliCommand::Validate(paths) = CliCommand::parse(&replace_spaces(
        "rosenpass validate file1 foo/file2 foo/bar/file3",
    ))
    .unwrap() else {
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

// ======================================== generate manpage ========================================
#[test]
fn parse_generate_manpage() {
    let CliCommand::GenerateManpage(path) =
        CliCommand::parse(&replace_spaces("rosenpass --generate-manpage some/path")).unwrap()
    else {
        panic!("parsing failed");
    };
    assert_eq!(path, PathBuf::from("some/path"))
}

#[test]
fn parse_generate_manpage_refuses_multiple_paths() {
    assert!(
        CliCommand::parse(&replace_spaces(
            "rosenpass --generate-manpage some/path additional/path",
        ))
        .is_err()
    );
}

// ======================================== TODO: shell completion ========================================
