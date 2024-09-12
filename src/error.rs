use core::fmt::Display;
use std::borrow::Cow;

pub enum Error {
    Io(std::io::Error),
    Join(tokio::task::JoinError),
    Utf8(core::str::Utf8Error),
    ParseInt(core::num::ParseIntError),
    Other(Cow<'static, str>),
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<tokio::task::JoinError> for Error {
    fn from(value: tokio::task::JoinError) -> Self {
        Self::Join(value)
    }
}

impl From<core::str::Utf8Error> for Error {
    fn from(value: core::str::Utf8Error) -> Self {
        Self::Utf8(value)
    }
}

impl From<core::num::ParseIntError> for Error {
    fn from(value: core::num::ParseIntError) -> Self {
        Self::ParseInt(value)
    }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
        Self::Other(Cow::Owned(value))
    }
}

impl From<&'static str> for Error {
    fn from(value: &'static str) -> Self {
        Self::Other(Cow::Borrowed(value))
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(err) => write!(f, "{err}"),
            Error::Join(err) => write!(f, "{err}"),
            Error::Utf8(err) => write!(f, "{err}"),
            Error::ParseInt(err) => write!(f, "{err}"),
            Error::Other(err) => write!(f, "{err}"),
        }
    }
}
