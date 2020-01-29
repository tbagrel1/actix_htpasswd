use actix_web::{
    HttpRequest,
    http::header::AUTHORIZATION
};

use crate::error::Error;

pub(crate) struct AuthData {
    pub(crate) user: String,
    pub(crate) password: String
}
impl AuthData {
    pub(crate) fn from_request(req: &HttpRequest) -> Result<Option<AuthData>, Error> {
        // Credits to https://github.com/actix/actix-web-httpauth/blob/master/src/headers/authorization/scheme/basic.rs
        let header = match req.headers().get(AUTHORIZATION) {
            Some(header) => header,
            None => return Ok(None)
        };

        // "Basic *" length
        if header.len() < 7 {
            return Err(Error::HeaderNotLongEnough);
        }

        let mut parts = header.to_str()
            .or(Err(Error::CannotConvertHeaderToString))?
            .splitn(2, ' ');

        match parts.next() {
            Some(scheme) => if scheme != "Basic" {
                return Err(Error::UnsupportedScheme { scheme: scheme.to_owned() })
            },
            None => return Err(Error::MissingScheme),
        }

        let raw_user_password = base64::decode(
            parts.next()
                .ok_or(Error::MalformedCredentials)?
        ).or(Err(Error::MalformedCredentials))?;

        let owned_user_password = String::from_utf8_lossy(&raw_user_password);
        let mut user_password = owned_user_password.splitn(2, ':');

        let user = user_password
            .next()
            .ok_or(Error::CannotExtractUsername)?
            .to_string();
        let password = user_password
            .next()
            .ok_or(Error::CannotExtractPassword)?
            .to_string();
        if password.is_empty() {
            return Err(Error::EmptyPassword)
        }

        Ok(Some(AuthData {
            user,
            password,
        }))
    }
}
