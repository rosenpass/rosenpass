use std::error::Error;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::result::Result;
use std::{fs::OpenOptions, io::ErrorKind};

// Adding these imports for log and thiserror
use log::{error, info};
use thiserror::Error;

/// Creating Custom error type for file operations
#[derive(Error, Debug)]
enum FileError {
    #[error("Failed to open file: {0}")]
    OpenFileError(#[from] io::Error),
    #[error("File too long!")]
    FileTooLongError,
}

/// Open a file writable
pub fn fopen_w<P: AsRef<Path>>(path: P) -> io::Result<File> {
    Ok(OpenOptions::new()
        .read(false)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?)
}

/// Open a file readable
pub fn fopen_r<P: AsRef<Path>>(path: P) -> io::Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .truncate(false)
        .open(&path)?)
}

pub trait ReadExactToEnd {
    type Error: Error;

    fn read_exact_to_end(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
}

impl<R: Read> ReadExactToEnd for R {
    type Error = FileError;

    fn read_exact_to_end(&mut self, buf: &mut [u8]) -> Result<(), Self::Error> {
        let mut dummy = [0u8; 8];
        self.read_exact(buf)?;

        // Change ensure! to an if statement for error handling
        if self.read(&mut dummy)? != 0 {
            return Err(FileError::FileTooLongError);
        }

        Ok(())
    }
}

pub trait LoadValue {
    type Error: Error;

    fn load<P: AsRef<Path>>(path: P) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

pub trait LoadValueB64 {
    type Error: Error;

    fn load_b64<P: AsRef<Path>>(path: P) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

pub trait StoreValue {
    type Error: Error;

    fn store<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>;
}