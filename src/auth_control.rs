use std::marker::PhantomData;

use actix_web::{
    FromRequest,
    HttpRequest,
    dev::Payload,
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

use crate::{
    auth_data::AuthData,
    htpasswd_database::HtpasswdDatabase,
    user_control_policy::UserControlPolicy,
};

pub enum AuthResult {
    Anonymous,
    LoggedUser { user: String },
}

pub struct AuthControl<U: UserControlPolicy> {
    _phantom_data: PhantomData<U>, // keep UserControlPolicy type
    pub auth_result: AuthResult,
}
impl<U: UserControlPolicy> FromRequest for AuthControl<U> {
    type Error = HttpError;
    type Future = Ready<Result<Self, HttpError>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let htpasswd_database = req.app_data::<HtpasswdDatabase>()
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
