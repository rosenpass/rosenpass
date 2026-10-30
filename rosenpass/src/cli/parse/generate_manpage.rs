use anyhow::anyhow;
use pest_typed::TypedParser;
use pest_typed_derive::TypedParser;
use std::{
    fmt::{self, Display},
    iter,
    path::PathBuf,
};

#[derive(TypedParser)]
#[grammar_inline = r#"
separator = _{ "\0" }
generate_manpage_arguments = { SOI ~ path  ~ EOI }
path = @{ (!separator ~ ANY)+ }
"#]
#[emit_rule_reference]
struct Parser;

/// returns the help message for the `rosenpass --generate-manpage` subcommand
#[rustfmt::skip]
pub fn help<'a>(indent: &'a str) -> impl Display + 'a {
    let i = indent; // shorter, save a bit of space in the code
    fmt::from_fn(move |f| {
        todo!()
    })
}

/// parse [`super::CliCommand::GenerateManpage`] from a command line
pub fn parse(parameters: &str) -> Result<PathBuf, anyhow::Error> {
    let parameters =
        Parser::try_parse::<pairs::generate_manpage_arguments>(parameters).map_err(|error| {
            let error = error
                .renamed_rules(|rule| match *rule {
                    // TODO: rule renaming does not work:
                    // https://github.com/TheVeryDarkness/pest-typed/issues/4
                    Rule::generate_manpage_arguments => "arguments to the subcommand".into(),
                    Rule::path => "output directory".into(),
                    Rule::EOI => "end of command line".into(),
                    Rule::separator => "end of argument".into(),
                })
                .to_string()
                .replace('\0', " ");
            anyhow!(error)
        })?;
    Ok(PathBuf::from(parameters.path().span.as_str()))
}
