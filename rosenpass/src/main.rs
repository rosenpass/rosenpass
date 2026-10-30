//! For the main function
#![recursion_limit = "256"]

#[cfg(feature = "experiment_api")]
mod api;
mod app_server;
mod config;
mod error;
mod hash_domains;
mod internal;
mod msgs;
mod oldcli;
mod protocol;

use crate::{error::RosenpassError, oldcli::CliCommand};
use clap_mangen::roff::{Roff, roman};
use log::error;
use std::process::exit;

/// Printing custom man sections when generating the man page
fn print_custom_man_section(section: &str, text: &str, file: &mut std::fs::File) {
    let mut roff = Roff::default();
    roff.control("SH", [section]);
    roff.text([roman(text)]);
    let _ = roff.to_writer(file);
}

/// parses command line, catches errors, prints them through the logger, then exits
///
/// The bulk of the command line logic is handled inside [crate::oldcli::CliCommand::run].
pub fn main() {
    // DO NOT set logging here. Logging is set differently per subcommand.
    // I.e. the exchange command reads it from the command line, the exchange-config command
    // reads it from a config file, some commands just use the default.

    // run the application based on the command line arguments
    match CliCommand::parse_and_run_from_env(None) {
        Ok(_) => {}
        Err(e) => {
            error!("{e:?}");
            exit(1);
        }
    }
}

/// Custom man page section: Exit Status
static EXIT_STATUS_MAN: &str = r"
The rosenpass utility exits 0 on success, and >0 if an error occurs.";

/// Custom man page section: See also.
static SEE_ALSO_MAN: &str = r"
rp(1), wg(1)

Karolin Varner, Benjamin Lipp, Wanja Zaeske, and Lisa Schmidt, Rosenpass, https://rosenpass.eu/whitepaper.pdf, 2023.";

/// Custom man page section: Standards.
static STANDARDS_MAN: &str = r"
This tool is the reference implementation of the Rosenpass protocol, as
specified within the whitepaper referenced above.";

/// Custom man page section: Authors.
static AUTHORS_MAN: &str = r"
Rosenpass was created by Karolin Varner, Benjamin Lipp, Wanja Zaeske, Marei
Peischl, Stephan Ajuvo, and Lisa Schmidt.";

/// Custom man page section: Bugs.
static BUGS_MAN: &str = r"
The bugs are tracked at https://github.com/rosenpass/rosenpass/issues.";
