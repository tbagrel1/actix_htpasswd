use std::{
    io,
    fmt::{
        Debug,
        Display,
        Formatter
    },
};

use self::Error::*;

pub enum Error {
    HeaderNotLongEnough,
    CannotConvertHeaderToString,
    UnsupportedScheme {
        scheme: String,
    },
    MissingScheme,
    MalformedCredentials,
    CannotExtractUsername,
    CannotExtractPassword,
    EmptyPassword,
    CannotOpenHtpasswdFile {
        path_string: String,
        io_error: io::Error,
    },
    CannotReadHtpasswdFile {
        path_string: String,
        io_error: io::Error,
    },
    MalformedHtpasswdLine {
        path_string: String,
        line: usize,
    },
    InvalidPasswordString {
        path_string: String,
        line: usize,
    },
    DuplicateUser {
        user: String,
    },
}
impl Error {
    fn kind(&self) -> &'static str {
        match self {
            HeaderNotLongEnough => "HeaderNotLongEnough",
            CannotConvertHeaderToString => "CannotConvertHeaderToString",
            UnsupportedScheme { .. } => "UnsupportedScheme",
            MissingScheme => "MissingScheme",
            MalformedCredentials => "MalformedCredentials",
            CannotExtractUsername => "CannotExtractUsername",
            CannotExtractPassword => "CannotExtractPassword",
            EmptyPassword => "EmptyPassword",
            CannotOpenHtpasswdFile { .. } => "CannotOpenHtpasswdFile",
            CannotReadHtpasswdFile { .. } => "CannotReadHtpasswdFile",
            MalformedHtpasswdLine { .. } => "MalformedHtpasswdLine",
            InvalidPasswordString { .. } => "InvalidPasswordString",
            DuplicateUser { .. } => "DuplicateUser",
        }
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            HeaderNotLongEnough => write!(
                f, "Authorization header not long enough to contain basic auth info"
            ),
            CannotConvertHeaderToString => write!(
                f, "Authorization header cannot be converted to string"
            ),
            UnsupportedScheme { scheme } => write!(
                f, "Unsupported authentication scheme: expected \"Basic\", got \"{}\"",
                scheme
            ),
            MissingScheme => write!(
                f, "Authentication scheme is missing!"
            ),
            MalformedCredentials => write!(
                f, "Encoded credentials are missing"
            ),
            CannotExtractUsername => write!(
                f, "Cannot extract username from credentials"
            ),
            CannotExtractPassword => write!(
                f, "Cannot extract password from credentials"
            ),
            EmptyPassword => write!(
                f, "Empty password isn't allowed"
            ),
            CannotOpenHtpasswdFile { path_string, io_error } => write!(
                f, "Cannot open Htpasswd file \"{}\": {}",
                path_string, io_error
            ),
            CannotReadHtpasswdFile { path_string, io_error } => write!(
                f, "Cannot read Htpasswd file \"{}\": {}",
                path_string, io_error
            ),
            MalformedHtpasswdLine { path_string, line } => write!(
                f, "Invalid line in Htpasswd file \"{}\" at line {}",
                path_string, line
            ),
            InvalidPasswordString { path_string, line } => write!(
                f, "Invalid base64 string for password in Htpasswd file \"{}\" at line {}",
                path_string, line
            ),
            DuplicateUser { user } => write!(
                f, "Duplicate user \"{}\"",
                user, path_string, line
            ),
        }
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}({})", self.kind(), self)
    }
}

impl std::error::Error for Error {}
