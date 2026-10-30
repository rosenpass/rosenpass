use core::fmt;

use anstyle::AnsiColor;

use crate::config::{
    PrettyIssueOutput, RosenpassConfig,
    parse_from_cli::{ParseIssue, ParseResult, ParseWarning},
};

// some default values for tests
pub(crate) const ALICE_SECDIR: &str = "../data/keys/alice-0.2-secret";
pub(crate) const ALICE_SECFILE: &str = "../data/keys/alice-0.2-secret/pqsk";
pub(crate) const ALICE_PUBDIR: &str = "../data/keys/alice-0.2-public";
pub(crate) const ALICE_PUBFILE: &str = "../data/keys/alice-0.2-public/pqpk";
pub(crate) const ALICE_LISTEN_0: &str = "1.2.3.4:2345";
pub(crate) const ALICE_LISTEN_1: &str = "[::]:3456";

pub(crate) const BOB_PUBDIR: &str = "../data/keys/bob-0.2-public";
pub(crate) const BOB_PUBFILE: &str = "../data/keys/bob-0.2-public/pqpk";
pub(crate) const BOB_ENDPOINT: &str = "3.4.5.6:4567";
pub(crate) const BOB_PSK: &str = "../data/keys/alice-bob.psk";
pub(crate) const BOB_OUTFILE: &str = "/tmp/bob-outfile";
pub(crate) const BOB_WG_DEV: &str = "wg27";
/// some base64-encoded WG pubkey, might have a trailing new line character
pub(crate) const BOB_WG_PUB: &str = include_str!("../data/keys/bob-0.2-public/wgpk");
pub(crate) const BOB_WG_EXTRA_ARGS: &str = "persistent-keepalive 123 endpoint 7.6.5.4:6543 allowed-ips 9.8.7.6,1234::,8.7.6.0/24,2345::/16";
pub(crate) const BOB_CONF: &str = "/tmp/bob-config.toml";

pub(crate) const CHARLIE_PUBDIR: &str = "../data/keys/charlie-0.2-public";
pub(crate) const CHARLIE_PUBFILE: &str = "../data/keys/charlie-0.2-public/pqpk";

/// TODO: is similar to implementation for parsing TOML, this is not DRY
pub(crate) fn print_parse_result(
    full_cmd_line: &str,
    data: &Result<(RosenpassConfig, Vec<ParseWarning>), Vec<ParseIssue>>,
) {
    match &data {
        Ok((data, warnings)) => {
            println!("successfully parsed this config:");
            println!("{:#?}", data);
            if warnings.is_empty() {
                println!("no warnings occured");
            } else {
                println!("{} warnings occured:", warnings.len());
                for warning in warnings.iter() {
                    anstream::eprintln!("{}", warning.pretty(full_cmd_line));
                }
            }
        }
        Err(err) => {
            println!("failed parsing a valid `RosenpassConfig`");
            println!("{} issues occured:", err.len());
            for issue in err.iter() {
                anstream::eprintln!("{}", issue.pretty(full_cmd_line));
            }
        }
    }
}
pub(crate) fn replace_spaces(input: &str) -> String {
    let input = input.replace('\n', " ");
    let mut chars = input.chars().peekable();
    let mut output = String::with_capacity(input.len());

    while let Some(c) = chars.next() {
        if c == ' ' {
            output.push('\0');
            while chars.next_if_eq(&' ').is_some() {}
        } else {
            output.push(c);
        }
    }

    output
}
#[test]
fn test_replace_spaces() {
    assert_eq!(replace_spaces("a   b   c"), "a\0b\0c");
}

pub(crate) fn parse_str(line: &str) -> ParseResult<RosenpassConfig> {
    // start preparing the command line
    let line = line.trim();

    // print command line for easier debugging
    let output = fmt::from_fn(move |f| {
        let bold = anstyle::Style::new().bold();
        let blue = AnsiColor::BrightBlue.on_default();
        writeln!(
            f,
            "{bold}parsing command line:{bold:#}\n{blue}{line}{blue:#}",
            line = line
        )
    });
    anstream::eprintln!("{}", output);

    // finish preparing the command line
    let line = replace_spaces(line);

    // parse
    let result = RosenpassConfig::parse_from_cli(line.as_str());

    // print parse result for easier debugging
    print_parse_result(line.as_str(), &result);

    // return
    result
}
