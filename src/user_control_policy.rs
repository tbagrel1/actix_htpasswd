use crate::auth_control::AuthResult;

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
