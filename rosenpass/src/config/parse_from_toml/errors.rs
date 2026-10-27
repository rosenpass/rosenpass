//! TODO: document module
use anstyle::{AnsiColor, Style};

use super::util::resolve_span;
use core::fmt;
use std::{
    fmt::{Debug, Display},
    marker::PhantomData,
    path::{Path, PathBuf},
};

mod sealed {
    pub trait Sealed {}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseIssueLevel {
    Error,
    Warning,
}
pub trait ParseIssueKind: sealed::Sealed + Debug {
    const LEVEL: ParseIssueLevel;
}
#[derive(Debug, Clone)]
pub struct Warning;
#[derive(Debug, Clone)]
pub struct Error;
impl sealed::Sealed for Warning {}
impl sealed::Sealed for Error {}
impl ParseIssueKind for Warning {
    const LEVEL: ParseIssueLevel = ParseIssueLevel::Warning;
}
impl ParseIssueKind for Error {
    const LEVEL: ParseIssueLevel = ParseIssueLevel::Error;
}
/// TODO: use an enum with `thiserror` instead of the `message: String`
#[derive(Debug, Clone)]
pub struct ParseIssueInner<K: ParseIssueKind> {
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub length: usize,

    // the long errors message printed into its own line
    pub message: String,

    // some inline message shown next to the "^" indicator
    pub inline_message: Option<String>,

    pub _kind: PhantomData<K>,
}
impl<K: ParseIssueKind> ParseIssueInner<K> {
    pub fn level(&self) -> ParseIssueLevel {
        K::LEVEL
    }
    pub fn new<S: ToString>(
        raw: &str,
        file_path: &Path,
        span: Option<std::ops::Range<usize>>,
        message: S,
    ) -> ParseIssueInner<K> {
        let location = span.as_ref().and_then(|span| resolve_span(raw, span));
        let length = span.as_ref().map(|s| s.end - s.start);
        ParseIssueInner::<K> {
            file: file_path.to_path_buf(),
            line: location.map(|l| l.0).unwrap_or(1),
            column: location.map(|l| l.1).unwrap_or(1),
            length: length.unwrap_or(1),
            message: message.to_string(),
            inline_message: Some(message.to_string()),
            _kind: Default::default(),
        }
    }

    pub fn new_ext<S1: ToString, S2: ToString>(
        raw: &str,
        file_path: &Path,
        span: Option<std::ops::Range<usize>>,
        message: S1,
        inline_message: S2,
    ) -> ParseIssueInner<K> {
        let location = span.as_ref().and_then(|span| resolve_span(raw, span));
        let length = span.as_ref().map(|s| s.end - s.start);
        ParseIssueInner::<K> {
            file: file_path.to_path_buf(),
            line: location.map(|l| l.0).unwrap_or(1),
            column: location.map(|l| l.1).unwrap_or(1),
            length: length.unwrap_or(1),
            message: message.to_string(),
            inline_message: Some(inline_message.to_string()),
            _kind: Default::default(),
        }
    }
}

/// renders an error/warning in the same format like the Rust compiler
///
/// Example:
/// ```text
/// error: invalid socket address syntax
///  --> src/config/tests/data/configs/tmp.toml:14:12
///     |
///  14 | endpoint = "my-peer.test:9999"
///     |            ^
/// ```
fn render_diagnostic<'a>(
    level: &'static str,
    accent: Style,
    file: &'a Path,
    line: usize,
    column: usize,
    length: usize,
    message: &'a str,
    inline_message: Option<&'a str>,
    raw: &'a str,
) -> impl fmt::Display + 'a {
    fmt::from_fn(move |f| {
        let bold = Style::new().bold();

        // rustc uses cyan on Windows for readability...
        let blue = if cfg!(windows) {
            AnsiColor::BrightCyan.on_default().bold()
        } else {
            AnsiColor::BrightBlue.on_default().bold()
        };

        // heading
        writeln!(
            f,
            "{accent}{level}:{accent:#} \
             {bold}{message}{bold:#}"
        )?;

        // location
        writeln!(
            f,
            " {blue}-->{blue:#} {file}:{line}:{column}",
            file = file.display()
        )?;

        // excepert from source
        {
            let line_count = raw.lines().count();
            if line == 0 || line > line_count {
                return Ok(());
            }

            // two lines before and after, clamped to the file
            let start = line.saturating_sub(2).max(1);
            let end = line.saturating_add(2).min(line_count);
            let width = end.to_string().len();

            // gutter above the excerpt
            writeln!(f, " {:width$} {blue}|{blue:#}", "")?;

            // source context
            for (index, source_line) in raw
                .lines()
                .enumerate()
                .skip(start - 1)
                .take(end - start + 1)
            {
                let current_line = index + 1;

                writeln!(f, " {blue}{current_line:>width$} |{blue:#} {source_line}")?;

                // make sure that the "^^^^^^" does not overflow the line
                let length = length.min(source_line.len().saturating_sub(column - 1));

                // highlight the affected line
                if current_line == line {
                    writeln!(
                        f,
                        " {:width$} {blue}|{blue:#} \
                        {:pad$}{accent}{indicator}{inline_message}{accent:#}",
                        "",
                        "",
                        pad = column.saturating_sub(1),
                        indicator = "^".repeat(length),
                        inline_message =
                            inline_message.map(|s| format!(" {s}")).unwrap_or_default() // default is empty string
                    )?;
                }
            }
        }

        Ok(())
    })
}
pub trait PrettyIssueOutput {
    fn pretty<'a>(&'a self, raw: &'a str) -> impl Display + 'a;
}
// TODO: the following code is not DRY
impl PrettyIssueOutput for ParseWarning {
    fn pretty<'a>(&'a self, raw: &'a str) -> impl Display + 'a {
        render_diagnostic(
            "warning",
            AnsiColor::Yellow.on_default().bold(),
            &self.file,
            self.line,
            self.column,
            self.length,
            &self.message,
            self.inline_message.as_deref(),
            raw,
        )
    }
}
impl PrettyIssueOutput for ParseError {
    fn pretty<'a>(&'a self, raw: &'a str) -> impl Display + 'a {
        render_diagnostic(
            "error",
            AnsiColor::BrightRed.on_default().bold(),
            &self.file,
            self.line,
            self.column,
            self.length,
            &self.message,
            self.inline_message.as_deref(),
            raw,
        )
    }
}
impl PrettyIssueOutput for ParseIssue {
    fn pretty<'a>(&'a self, raw: &'a str) -> impl Display + 'a {
        fmt::from_fn(move |f| match &self {
            ParseIssue::Warning(warning) => fmt::Display::fmt(&warning.pretty(raw), f),
            ParseIssue::Error(error) => fmt::Display::fmt(&error.pretty(raw), f),
        })
    }
}

impl<K: ParseIssueKind> std::error::Error for ParseIssueInner<K> {}
pub type ParseWarning = ParseIssueInner<Warning>;
pub type ParseError = ParseIssueInner<Error>;
#[derive(Debug)]
pub enum ParseIssue {
    Warning(ParseWarning),
    Error(ParseError),
}
impl ParseIssue {
    pub fn file(&self) -> &Path {
        match &self {
            ParseIssue::Warning(inner) => &inner.file,
            ParseIssue::Error(inner) => &inner.file,
        }
    }
    pub fn line(&self) -> usize {
        match &self {
            ParseIssue::Warning(inner) => inner.line,
            ParseIssue::Error(inner) => inner.line,
        }
    }
    pub fn column(&self) -> usize {
        match &self {
            ParseIssue::Warning(inner) => inner.column,
            ParseIssue::Error(inner) => inner.column,
        }
    }
    pub fn message(&self) -> &str {
        match &self {
            ParseIssue::Warning(inner) => inner.message.as_str(),
            ParseIssue::Error(inner) => inner.message.as_str(),
        }
    }
    // TODO: fn is_error()
    // TODO: fn is_warning()
}

impl<K: ParseIssueKind> std::fmt::Display for ParseIssueInner<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.level() {
            ParseIssueLevel::Warning => {
                write!(
                    f,
                    "warning:{}:{}:{}: {}",
                    self.file.display(),
                    self.line,
                    self.column,
                    self.message
                )
            }
            ParseIssueLevel::Error => {
                write!(
                    f,
                    "error:{}:{}:{}: {}",
                    self.file.display(),
                    self.line,
                    self.column,
                    self.message
                )
            }
        }
    }
}
impl std::fmt::Display for ParseIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::Warning(inner) => write!(f, "{}", inner),
            Self::Error(inner) => write!(f, "{}", inner),
        }
    }
}

impl std::error::Error for ParseIssue {}
