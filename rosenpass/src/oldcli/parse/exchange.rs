use crate::config::{PrettyIssueOutput, RosenpassConfig};
use anyhow::anyhow;

/// parse [`super::CliCommand::ExchangeConfig`] from a command line
pub fn parse(parameters: &str) -> Result<RosenpassConfig, anyhow::Error> {
    // TODO: make this more pretty?
    let full_line = format!("rosenpass\0exchange\0{parameters}");

    // TODO: should these errors be passed to the caller instead of being printed directly?
    let (config, warnings) = RosenpassConfig::parse_from_cli(full_line.as_str()).map_err(|e| {
        e.iter()
            .map(|e| anstream::eprintln!("{}", e.pretty(full_line.as_str())));
        anyhow!("parsing failed")
    })?;

    // emit warnings
    for warning in warnings.iter() {
        anstream::eprintln!("{}", warning.pretty(full_line.as_str()));
    }

    // return
    Ok(config)
}
