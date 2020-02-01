use std::{
    fmt::{
        Display,
        Formatter,
    },
    marker::PhantomData
};

use actix_web::{
    FromRequest,
    HttpRequest,
    dev::Payload,
    web::Data,
    error::{
        Error as HttpError,
        ErrorForbidden,
        ErrorUnauthorized
    },
};
use futures::future::{
    err,
    ok,
    Ready
};
use serde::{
    Serialize,
    Deserialize
};

use crate::{
    auth_data::AuthData,
    htpasswd_database::HtpasswdDatabase,
    user_control_policy::UserControlPolicy,
};

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub enum AuthResult {
    Anonymous,
    LoggedUser { user: String },
}

impl Display for AuthResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            AuthResult::Anonymous => write!(f, "not authenticated (anonymous)"),
            AuthResult::LoggedUser { user } => write!(f, "authenticated as \"{}\"", user)
        }
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct AuthControl<U: UserControlPolicy> {
    _phantom_data: PhantomData<U>, // keep UserControlPolicy type
    pub auth_result: AuthResult,
}

impl<U: UserControlPolicy> FromRequest for AuthControl<U> {
    type Error = HttpError;
    type Future = Ready<Result<Self, HttpError>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let htpasswd_database = req.app_data::<Data<HtpasswdDatabase>>()
            .expect("No HtpasswdDatabase added to the actix app. Cannot check credentials");

        // Extract authentication data from the request, and match it against
        // the HtpasswdDatabase carried by the Actix app
        let auth_result = match AuthData::from_request(req) {
            Ok(Some(auth_data)) => {
                if htpasswd_database.is_valid(&auth_data) {
                    AuthResult::LoggedUser {
                        user: auth_data.user,
                    }
                } else {
                    return err(ErrorUnauthorized(format!(
                        "Unknown user or invalid password"
                    )));
                }
            },
            Ok(None) => AuthResult::Anonymous,
            Err(msg) => {
                return err(ErrorUnauthorized(format!(
                    "Malformed authorization header: {}", msg
                )))
            }
        };

        // At this point, authentication is done. It's time for user access
        // control. The "U" type represents the chosen UserControlPolicy.
        if U::allows(&auth_result) {
            ok(AuthControl {
                _phantom_data: PhantomData,
                auth_result,
            })
        } else {
            err(ErrorForbidden(format!(
                "Insufficient privileges to access this resource"
            )))
        }
    }
}

impl<U: UserControlPolicy> Display for AuthControl<U> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(
            f, "AuthControl: {} policy caught a user {}: {}",
            U::display(),
            self.auth_result,
            if U::allows(&self.auth_result) { "access granted" } else { "access forbidden" }
        )
    }
}
