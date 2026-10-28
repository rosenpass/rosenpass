//! TODO: doc
//!
//! TODO: allow mutilple spans per problem

use core::fmt;
use std::fmt::Display;

use anstyle::AnsiColor;
use thiserror::Error;

use crate::config::{PrettyIssueOutput, parse_from_toml::util::ProcessableParseError};

// ============================== user-facing types ==============================
#[derive(Debug)]
pub enum ParseIssue {
    Warning(ParseWarning),
    Error(ParseError),
}

pub type ParseError = ParseProblem<ParseProblemError>;
pub type ParseWarning = ParseProblem<ParseProblemWarning>;
pub type ParseResult<T> = Result<(T, Vec<ParseWarning>), Vec<ParseIssue>>;

#[must_use]
#[derive(Debug, Clone)]
pub struct ParseProblem<P: ParseProblemLike> {
    // character index of the error source in the command line
    span: Span,

    /// full command line from which this error originates
    full_line: String,

    problem: P,
}
#[must_use]
#[derive(Debug, Error, Clone)]
pub enum ParseProblemError {
    #[error("missing key \"{0}\"")]
    MissingKey(String),

    #[error("arguments \"{0}\" and \"{1}\" are mutually exclusive")]
    TwoConflictingArguments(String, String),

    #[error("\"{0}\" is not a valid socket address")]
    InvalidSocketAddr(String),

    #[error("\"{0}\" is not a valid IP address or IP network in CIDR notation")]
    InvalidAddressOrNetwork(String),

    #[error("invalid WireGuard extra option \"{0}\"")]
    InvalidWireguardExtraOption(String),

    #[error("\"{0}\" is not a valid port number")]
    InvalidPortNumber(String),

    #[error("\"{0}\" is not a valid time in integer seconds")]
    InvalidTimeInSeconds(String),
}

#[must_use]
#[derive(Debug, Error, Clone)]
pub enum ParseProblemWarning {
    #[error("argument \"{0}\" is deprecated")]
    DeprecatedArgument(String),

    #[error("argument \"{0}\" is deprecated, use \"{1}\" instead")]
    DeprecatedArgumentWithReplacement(String, String),
}

// ============================== more types ==============================
impl ProcessableParseError for ParseError {}
impl ProcessableParseError for ParseWarning {}

// TODO: extend this implementation(?)
impl<P: ParseProblemLike> Display for ParseProblem<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.problem)
    }
}
impl<P: ParseProblemLike> std::error::Error for ParseProblem<P> {
    // TODO
    // fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
    // }
}

trait ParseProblemLike: Display + std::error::Error {}
impl ParseProblemLike for ParseProblemError {}
impl ParseProblemLike for ParseProblemWarning {}

type Span = Option<std::ops::Range<usize>>;

impl<P: ParseProblemLike> ParseProblem<P> {
    /// renders a parsing error/warning, e.g.:
    ///
    /// ```text
    /// error: "123a" is not a valid time in integer seconds
    ///   --> command line:1:46
    ///    |
    ///  1 | rosenpass exchange ... persistent-keepalive 123a ...
    ///    |                                              ^^^^
    /// ```
    fn pretty_with_level<'a>(
        &'a self,
        level: &'static str,
        accent: anstyle::Style,
        raw: &'a str,
    ) -> impl Display + 'a {
        fmt::from_fn(move |f| {
            let bold = anstyle::Style::new().bold();

            // rustc uses cyan on Windows for readability...
            let blue = if cfg!(windows) {
                AnsiColor::BrightCyan.on_default().bold()
            } else {
                AnsiColor::BrightBlue.on_default().bold()
            };

            // heading
            writeln!(
                f,
                "{accent}{level}:{accent:#} {bold}{}{bold:#}",
                self.problem
            )?;

            // location & excerpt (the command line is always a single line)
            if let Some(span) = &self.span {
                // render the NUL argument separators as spaces; both are one byte wide, so the
                // byte-based span still aligns with the rendered line
                let line = raw.replace('\0', " ");
                writeln!(f, " {blue}-->{blue:#} command line:1:{}", span.start + 1)?;
                writeln!(f, "  {blue}|{blue:#}")?;
                writeln!(f, "1 {blue}|{blue:#} {line}")?;
                writeln!(
                    f,
                    "  {blue}|{blue:#} {}{accent}{}{accent:#}",
                    " ".repeat(span.start),
                    "^".repeat(span.len().max(1))
                )?;
            }

            Ok(())
        })
    }
}

impl PrettyIssueOutput for ParseWarning {
    fn pretty<'a>(&'a self, raw: &'a str) -> impl std::fmt::Display + 'a {
        self.pretty_with_level("warning", AnsiColor::Yellow.on_default().bold(), raw)
    }
}
impl PrettyIssueOutput for ParseError {
    fn pretty<'a>(&'a self, raw: &'a str) -> impl std::fmt::Display + 'a {
        self.pretty_with_level("error", AnsiColor::BrightRed.on_default().bold(), raw)
    }
}
impl PrettyIssueOutput for ParseIssue {
    fn pretty<'a>(&'a self, raw: &'a str) -> impl std::fmt::Display + 'a {
        fmt::from_fn(move |f| match self {
            Self::Warning(warning) => fmt::Display::fmt(&warning.pretty(raw), f),
            Self::Error(error) => fmt::Display::fmt(&error.pretty(raw), f),
        })
    }
}

impl<P: ParseProblemLike> ParseProblem<P> {
    pub fn new(span: Span, full_line: &str, problem: P) -> Self {
        Self {
            span,
            full_line: full_line.to_string(),
            problem,
        }
    }
}

// TODO: rename?
pub(crate) trait ProcessParseResult2 {
    type Error;
    type Warning;
    type Output;
    /// process a [`ParseResult`] by storing its errors and warnings and just returning the parsing artifact
    fn process_parse_result(
        self,
        errors: &mut Vec<Self::Error>,
        warnings: &mut Vec<Self::Warning>,
    ) -> Option<Self::Output>;
}
impl<T> ProcessParseResult2 for ParseResult<T> {
    type Error = ParseError;
    type Warning = ParseWarning;
    type Output = T;
    fn process_parse_result(
        self,
        errors: &mut Vec<Self::Error>,
        warnings: &mut Vec<Self::Warning>,
    ) -> Option<Self::Output> {
        match self {
            Ok((result, w)) => {
                warnings.extend(w);
                Some(result)
            }
            Err(issues) => {
                for issue in issues {
                    match issue {
                        ParseIssue::Warning(warning) => warnings.push(warning),
                        ParseIssue::Error(error) => errors.push(error),
                    }
                }
                None
            }
        }
    }
}

// ============================== print ==============================
// TODO: print diagnostics

// ============================== utility regarding error handling ==============================
macro_rules! return_on_error {
    ($errors:ident,$warnings:ident) => {
        if !$errors.is_empty() {
            let issues = $warnings
                .into_iter()
                .map(ParseIssue::Warning)
                .chain($errors.into_iter().map(ParseIssue::Error))
                .collect::<Vec<ParseIssue>>();
            return Err(issues);
        }
    };
}
pub(crate) use return_on_error;
macro_rules! declare_issues {
    ($errors:ident, $warnings:ident) => {
        // #[allow(unused_mut, unused_variables)]
        let mut $errors: Vec<ParseError> = Vec::new();
        #[allow(unused_mut, unused_variables)]
        let mut $warnings: Vec<ParseWarning> = Vec::new();
    };
}
pub(crate) use declare_issues;
