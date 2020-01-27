use futures::future::{err, ok, Ready};
use std::path::Path;
use std::marker::PhantomData;
use std::fs::File;
use std::io::{self, BufReader, BufRead};
use std::collections::HashMap;

use actix_web::{
    FromRequest, HttpRequest,
    error::{
        Error as HttpError, ErrorUnauthorized, ErrorForbidden
    },
    dev::Payload,
    http::header::AUTHORIZATION
};
use base64;
use sha1::{Sha1, Digest};

fn invalid_data_error<M>(msg: M) -> io::Error where M: Into<String> + Sized {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

struct AuthData {
    user: String,
    password: String
}
impl AuthData {
    fn from_request(req: &HttpRequest) -> Result<Option<AuthData>, String> {
        // Credits to https://github.com/actix/actix-web-httpauth/blob/master/src/headers/authorization/scheme/basic.rs
        let header = match req.headers().get(AUTHORIZATION) {
            Some(header) => header,
            None => return Ok(None)
        };

        // "Basic *" length
        if header.len() < 7 {
            return Err(format!("Authorization header not long enough to contain basic auth info"));
        }

        let mut parts = header.to_str()
            .or(Err(format!("Authorization header cannot be converted to string")))?
            .splitn(2, ' ');

        match parts.next() {
            Some(scheme) => if scheme != "Basic" {
                return Err(format!("Unsupported authentication scheme: expected \"Basic\", got \"{}\"", scheme))
            },
            None => return Err(format!("Authentication scheme is missing!")),
        }

        let raw_user_password = base64::decode(
            parts.next()
                .ok_or(format!("Encoded credentials are missing"))?
            ).or(Err(format!("Malformed base64 string for credentials")))?;

        let owned_user_password = String::from_utf8_lossy(&raw_user_password);
        let mut user_password = owned_user_password.splitn(2, ':');

        let user = user_password
            .next()
            .ok_or(format!("Cannot extract username from credentials"))?
            .to_string();
        let password = user_password
            .next()
            .ok_or(format!("Cannot extract password from credentials"))?
            .to_string();
        if password.is_empty() {
            return Err(format!("Empty password isn't allowed"))
        }

        Ok(Some(AuthData {
            user,
            password,
        }))
    }
}

pub struct HtpasswdDatabase {
    registered_users: HashMap<String, Vec<u8>>
}
impl HtpasswdDatabase {
    pub fn create_from(htpasswd_file_path: &Path) -> io::Result<HtpasswdDatabase> {
        let file = File::open(htpasswd_file_path)?;
        let reader = BufReader::new(file);
        let mut registered_users = HashMap::new();
        for (i, line_res) in reader.lines().enumerate() {
            let owned_line = line_res?;
            let line = owned_line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split(":{SHA}").collect();
            if parts.len() != 2 {
                return Err(invalid_data_error(format!(
                    "Invalid line in Htpasswd file \"{}\" at line {}",
                    htpasswd_file_path.to_string_lossy(), i
                )));
            }
            let user = parts[0];
            let base64_sha1_password = parts[1];
            let sha1_password = match base64::decode(base64_sha1_password) {
                Ok(vec) => vec,
                Err(_) => return Err(invalid_data_error(format!(
                    "Invalid base64 string for password in Htpasswd file \"{}\" at line {}",
                    htpasswd_file_path.to_string_lossy(), i
                )))
            };
            if registered_users.contains_key(user) {
                return Err(invalid_data_error(format!(
                    "Duplicate user \"{}\" in Htpasswd file \"{}\" at line {}",
                    user, htpasswd_file_path.to_string_lossy(), i
                )))
            }
            registered_users.insert(user.to_owned(), sha1_password);
        }
        Ok(HtpasswdDatabase {
            registered_users
        })
    }

    fn is_valid(&self, auth_data: &AuthData) -> bool {
        if !self.registered_users.contains_key(&auth_data.user) {
            return false;
        }
        let mut sha1_hasher = Sha1::new();
        sha1_hasher.input(&auth_data.password);
        let sha1_password = sha1_hasher.result().to_vec();

        &sha1_password == self.registered_users.get(&auth_data.user).unwrap()
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
    type Error = HttpError;
    type Future = Ready<Result<Self, HttpError>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let htpasswd_database = req.app_data::<HtpasswdDatabase>()
            .expect("No HtpasswdDatabase added to the actix app. Cannot check credentials");
        let auth_result = match AuthData::from_request(req) {
            Ok(Some(auth_data)) => if htpasswd_database.is_valid(&auth_data) {
                AuthResult::LoggedUser { user: auth_data.user }
            } else {
                return err(ErrorUnauthorized(format!("Unknown user or invalid password")))
            },
            Ok(None) => AuthResult::Anonymous,
            Err(msg) => return err(ErrorUnauthorized(format!("Malformed authorization header: {}", msg)))
        };
        if U::allows(&auth_result) {
            ok(AuthControl {
                phantom_data: PhantomData,
                auth_result
            })
        } else {
            err(ErrorForbidden(format!("Insufficient privileges to access this resource")))
        }
    }
}

/// # Example
///
/// It's really easy to add additionnal user control policies :
///
/// ```rust
/// use actix_htpasswd::{AuthControl, AuthResult, UserControlPolicy, Anyone};
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
/// async fn index_handler(auth_control: AuthControl<Anyone>) -> impl Responder {
///     match auth_control.auth_result {
///         AuthResult::Anonymous => format!("You are not logged in yet :)"),
///         AuthResult::LoggedUser { user } => format!("Hello {}!", user)
///     }
/// }
/// ```
pub trait UserControlPolicy {
    fn allows(auth_result: &AuthResult) -> bool;
}

pub struct Anyone;
impl UserControlPolicy for Anyone {
    fn allows(_auth_result: &AuthResult) -> bool {
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
