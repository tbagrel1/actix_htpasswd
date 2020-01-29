use serde::{
    Serialize,
    Deserialize
};

use crate::auth_control::AuthResult;

pub trait UserControlPolicy {
    fn display() -> &'static str;

    fn allows(auth_result: &AuthResult) -> bool;
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct Anyone;
impl UserControlPolicy for Anyone {
    fn display() -> &'static str {
        "Anyone"
    }
    fn allows(_auth_result: &AuthResult) -> bool {
        true
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct AnyLoggedUser;
impl UserControlPolicy for AnyLoggedUser {
    fn display() -> &'static str {
        "AnyLoggedUser"
    }

    fn allows(auth_result: &AuthResult) -> bool {
        match &auth_result {
            AuthResult::Anonymous => false,
            AuthResult::LoggedUser { .. } => true,
        }
    }
}
