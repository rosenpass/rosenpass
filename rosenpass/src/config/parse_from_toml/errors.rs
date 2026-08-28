//! TODO: document module
//! TODO: format errors/warnings with file name
use super::util::resolve_span;
use std::{fmt::Debug, marker::PhantomData};

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
        span: Option<std::ops::Range<usize>>,
        message: String,
    ) -> ParseIssueInner<K> {
        let location = span.map(|span| resolve_span(raw, &span)).flatten();
        ParseIssueInner::<K> {
            line: location.map(|l| l.0).unwrap_or(1),
            column: location.map(|l| l.1).unwrap_or(1),
            message: message,
            _kind: Default::default(),
        }
    }
}
impl<K: ParseIssueKind> std::fmt::Display for ParseIssueInner<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.level() {
            ParseIssueLevel::Warning => {
                write!(f, "warning:{}:{}: {}", self.line, self.column, self.message)
            }
            ParseIssueLevel::Error => {
                write!(f, "error:{}:{}: {}", self.line, self.column, self.message)
            }
        }
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
impl std::fmt::Display for ParseIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // let line = self.line();
        // let column = self.column();
        // let message = self.message();
        // match &self {
        //     Self::Warning(inner) => write!(f, "warning:{}:{}: {}", line, column, message),
        //     Self::Error(inner) => write!(f, "error:{}:{}: {}", line, column, message),
        // }
        match &self {
            Self::Warning(inner) => write!(f, "{}", inner),
            Self::Error(inner) => write!(f, "{}", inner),
        }
    }
}
impl std::error::Error for ParseIssue {}
