use std::fmt::{self, Display};

use crate::config::{PrettyIssueOutput, RosenpassConfig};
use anyhow::anyhow;

/// returns the help message for the `rosenpass exchange` subcommand
/// 
/// You can find the PEG definition in `rosenpass/src/config/parse_from_cli/exchange.pest`:
/// 
/// ```pest
#[doc = include_str!("../../config/parse_from_cli/exchange.pest")]
/// ```
#[rustfmt::skip]
pub fn help<'a>(indent: &'a str) -> impl Display + 'a {
    let i = indent; // shorter, save a bit of space in the code
    fmt::from_fn(move |f| {
        // first line
        write!(f, "exchange <OWN_CONFIG> ")?;
        #[cfg(feature = "experiment_api")]
        write!(f, "[API_CONFIG] [PSK_BROKER_CONFIG] ")?;
        write!(f, "[PEERS]...")?;
        writeln!(f)?;

        // OWN_CONFIG
        writeln!(f, "{i}OWN_CONFIG: public-key <PATH> secret-key <PATH> [listen <ADDR>:<PORT>]... [verbose|quiet]")?;

        // API_CONFIG
        #[cfg(feature = "experiment_api")] {
            writeln!(f, "{i}API_CONFIG: [--listen-path <PATH>]... [--listen-fd <FD>]... [--stream-fd <FD>]...")?;
            writeln!(f, "{i}PSK_BROKER_CONFIG: [--psk-broker-path <FD>] [--psk-broker-fd <FD>] [--psk-broker-spawn]")?;
        }

        // PEERS
        writeln!(f, "{i}PEERS...: peer public-key <PATH> [endpoint <HOST/IP>:<PORT>] [preshared-key <PATH>] [outfile <PATH>] [WG]")?;
        writeln!(f, "{i}{i}WG: wireguard <DEVICE> <THEIR_PUBKEY> [endpoint <ip>:<port>] [persistent-keepalive <interval seconds>] [allowed-ips [+|-]<ip1>/<cidr1>[,[+|-]<ip2>/<cidr2>]...]")?;

        Ok(())
    })
}

/// parse [`super::CliCommand::Exchange`] from a command line
pub fn parse(parameters: &str) -> Result<RosenpassConfig, anyhow::Error> {
    // TODO: make this more pretty?
    let full_line = format!("rosenpass\0exchange\0{parameters}");

    // TODO: should these errors be passed to the caller instead of being printed directly?
    let (config, warnings) = RosenpassConfig::parse_from_cli(full_line.as_str()).map_err(|e| {
        e.iter()
            .map(|e| anstream::eprintln!("{}", e.pretty(full_line.as_str())))
            .for_each(drop);
        anyhow!("parsing failed")
    })?;

    // emit warnings
    for warning in warnings.iter() {
        anstream::eprintln!("{}", warning.pretty(full_line.as_str()));
    }

    // return
    Ok(config)
}
