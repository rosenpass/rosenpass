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
#[derive(Debug, Clone)]
pub struct ParseIssueInner<K: ParseIssueKind> {
    pub file: PathBuf,
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub _kind: PhantomData<K>,
}
impl<K: ParseIssueKind> ParseIssueInner<K> {
    pub fn level(&self) -> ParseIssueLevel {
        K::LEVEL
    }
    pub fn new(
        raw: &str,
        file: &Path,
        span: Option<std::ops::Range<usize>>,
        message: String,
    ) -> ParseIssueInner<K> {
        let location = span.and_then(|span| resolve_span(raw, &span));
        ParseIssueInner::<K> {
            file: file.to_path_buf(),
            line: location.map(|l| l.0).unwrap_or(1),
            column: location.map(|l| l.1).unwrap_or(1),
            message,
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
    message: &'a str,
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

                // highlight the affected line
                if current_line == line {
                    writeln!(
                        f,
                        " {:width$} {blue}|{blue:#} \
                     {:pad$}{accent}^{accent:#}",
                        "",
                        "",
                        pad = column.saturating_sub(1),
                    )?;
                }
            }
        }

        // // excerpt from source
        // if let Some(source_line) = line.checked_sub(1).and_then(|n| raw.lines().nth(n)) {
        //     let width = line.to_string().len();

        //     // Gutter above source
        //     writeln!(f, " {:width$} {blue}|{blue:#}", "")?;

        //     // Source line
        //     writeln!(
        //         f,
        //         " {blue}{line:>width$}{blue:#} \
        //          {blue}|{blue:#} {source_line}"
        //     )?;

        //     // Highlighted location
        //     write!(
        //         f,
        //         " {:width$} {blue}|{blue:#} {}",
        //         "",
        //         " ".repeat(column.saturating_sub(1))
        //     )?;

        //     write!(f, "{accent}^{accent:#}")?;
        //     writeln!(f)?;
        // }

        Ok(())
    })
}
pub trait PrettyIssueOutput {
    fn pretty<'a>(&'a self, raw: &'a str) -> impl Display + 'a;
}
impl PrettyIssueOutput for ParseWarning {
    fn pretty<'a>(&'a self, raw: &'a str) -> impl Display + 'a {
        render_diagnostic(
            "warning",
            AnsiColor::Yellow.on_default().bold(),
            &self.file,
            self.line,
            self.column,
            &self.message,
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
            &self.message,
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
