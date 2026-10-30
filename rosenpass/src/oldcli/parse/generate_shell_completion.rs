// use anyhow::anyhow;
// use pest_typed::TypedParser;
// use pest_typed_derive::TypedParser;
// use std::{iter, path::PathBuf};

// #[derive(TypedParser)]
// #[grammar_inline = r#"
// separator = _{ "\0" }
// validate_arguments = { SOI ~ path ~ ( separator ~ path)* ~ EOI }
// path = @{ (!separator ~ ANY)+ }
// "#]
// #[emit_rule_reference]
// struct Parser;

// /// parse [`super::CliCommand::GenerateShellCompletion`] from a command line
// pub fn parse(parameters: &str) -> Result<clap_complete::Shell, anyhow::Error> {
//     let parameters =
//         Parser::try_parse::<pairs::validate_arguments>(parameters).map_err(|error| {
//             let error = error
//                 .renamed_rules(|rule| match *rule {
//                     // TODO: rule renaming does not work:
//                     // https://github.com/TheVeryDarkness/pest-typed/issues/4
//                     Rule::validate_arguments => "arguments to the subcommand".into(),
//                     Rule::path => "path to a configuration file".into(),
//                     Rule::EOI => "end of command line".into(),
//                     Rule::separator => "end of argument".into(),
//                 })
//                 .to_string()
//                 .replace('\0', " ");
//             anyhow!(error)
//         })?;
// }
