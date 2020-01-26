use std::future::Future;
use actix_web::{HttpResponse, Responder, FromRequest, HttpRequest, Error};
use std::io;
use std::path::Path;
use crate::auth_control::UserControlPolicy;
use std::marker::PhantomData;
use actix_web::web::Bytes;
use std::pin::Pin;
use actix_web::dev::Payload;
use actix_web::error::PayloadError;
use crate::AuthResult::LoggedUser;

struct RegisteredUser {
    user: String,
    password_sha1: String
}

struct AuthData {
    user: String,
    password: String
}
impl AuthData {
    fn from_request(req: &HttpRequest) -> Option<AuthData> {
        unimplemented!()
    }
}

pub struct HtpasswdDatabase {
    registered_users: Vec<RegisteredUser>
}
impl HtpasswdDatabase {
    pub fn create_from(htpasswd_file_path: &Path) -> io::Result<HtpasswdDatabase> {
        unimplemented!()
    }
    fn is_valid(&self, auth_data: &AuthData) -> bool {
        unimplemented!()
    }
}

pub enum AuthResult {
    Anonymous,
    LoggedUser {
        user: String
    }
}

pub struct AuthControl<U: UserControlPolicy> {
    phantom_data: PhantomData<U>, // keep UserControlPolicy type
    pub auth_result: AuthResult
}

impl<U: UserControlPolicy> FromRequest for AuthControl<U> {
    type Error = ();
    type Future = Result<AuthControl<U>, HttpResponse>;
    type Config = ();

    fn from_request(req: &HttpRequest, payload: &mut Payload<Pin<Box<Stream<Item=Result<Bytes, PayloadError>>>>>) -> Self::Future {
        let htpasswd_database: &HtpasswdDatabase = app.app_data::<HtpasswdDatabase>().expect("No HtpasswdDatabase added to the actix app. Cannot check credentials"); // TODO implement
        let auth_result = match AuthData::from_request(req) {
            Some(auth_data) => if htpasswd_database.is_valid(&auth_data) {
                LoggedUser { user: auth_data.user }
            } else {
                Anonymous
            },
            None => Anonymous
        };
        if U::allows(&auth_result) {
            Ok(AuthControl {
                phantom_data: PhantomData,
                auth_result
            })
        } else {
            Err(HttpResponse::Unauthorized().finish())
        }
    }
}

pub trait UserControlPolicy {
    fn allows(auth_result: &AuthResult) -> bool;
}

pub struct Anonymous;
impl UserControlPolicy for Anonymous {
    fn allows(auth_result: &AuthResult) -> bool {
        true
    }
}

pub struct AnyLoggedUser;
impl UserControlPolicy for AnyLoggedUser {
    fn allows(auth_result: &AuthResult) -> bool {
        match &auth_result {
            AuthResult::Anonymous => false,
            AuthResult::LoggedUser { .. } => true,
        }
    }
}

/// # Example
///
/// ```rust
/// use actix_htpasswd::{AuthControl, AuthResult, UserControlPolicy, Anonymous};
/// use actix_web::Responder;
///
/// struct OnlyAdmin;
/// impl UserControlPolicy for OnlyAdmin {
///     fn allows(auth_result: &AuthResult) -> bool {
///         match &auth_result {
///             AuthResult::Anonymous => false,
///             AuthResult::LoggedUser { user } => user == "admin"
///         }
///     }
/// }
///
/// async fn admin_page_handler(auth_control: AuthControl<OnlyAdmin>) -> impl Responder {
///     format!("Admin page")
/// }
///
/// async fn index_handler(auth_control: AuthControl<Anonymous>) -> impl Responder {
///     match auth_control.auth_result {
///         AuthResult::Anonymous => format!("You are not logged in yet :)"),
///         AuthResult::LoggedUser { user } => format!("Hello {}!", user)
///     }
/// }
/// ```
