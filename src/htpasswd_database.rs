use std::{
    collections::HashMap,
    fs::File,
    path::Path,
    convert::TryFrom,
    io::{
        BufRead,
        BufReader
    },
};

use sha1::{
    Digest,
    Sha1
};

use crate::{
    auth_data::AuthData,
    error::Error
};

#[derive(Clone, Eq, PartialEq)]
pub struct HtpasswdDatabase {
    registered_users: HashMap<String, Vec<u8>>,
}
impl HtpasswdDatabase {
    pub fn new() -> HtpasswdDatabase {
        HtpasswdDatabase { registered_users: HashMap::new() }
    }

    pub fn add(&mut self, user: &str, sha1_password: Vec<u8>) -> Result<(), Error> {
        if self.registered_users.contains_key(user) {
            return Err(Error::DuplicateUser {
                user: user.to_owned(),
            });
        }

        self.registered_users.insert(user.to_owned(), sha1_password);
        Ok(())
    }

    pub(crate) fn is_valid(&self, auth_data: &AuthData) -> bool {
        if !self.registered_users.contains_key(&auth_data.user) {
            return false;
        }

        // At the moment, only SHA-1 hashed passwords are supported in the
        // Htpasswd file. Thus, SHA-1 of the supplied password is computed here.
        let mut sha1_hasher = Sha1::new();
        sha1_hasher.input(&auth_data.password);

        let sha1_password = sha1_hasher.result().to_vec();

        &sha1_password == self.registered_users.get(&auth_data.user).unwrap()
    }
}

impl TryFrom<&Path> for HtpasswdDatabase {
    type Error = Error;

    fn try_from(htpasswd_file_path: &Path) -> Result<Self, Self::Error> {
        let path_string = htpasswd_file_path.to_string_lossy().to_string();

        let file = File::open(htpasswd_file_path)
            .map_err(|io_error| Error::CannotOpenHtpasswdFile {
                path_string: path_string.clone(),
                io_error,
            })?;

        let reader = BufReader::new(file);

        // Create the internal hashmap which will be used to store the
        // recognized credentials
        let mut registered_users = HashMap::new();

        for (i, line_res) in reader.lines().enumerate() {

            let owned_line = line_res
                .map_err(|io_error| Error::CannotReadHtpasswdFile {
                    path_string: path_string.clone(),
                    io_error,
                })?;

            let line = owned_line.trim();
            if line.is_empty() {
                continue;
            }

            // Cut the htpasswd line on the ":{SHA}" string, which splits
            // the username from the base64 representation of the password sha1.
            // At the moment, only SHA-1 hashed passwords are supported in the
            // Htpasswd file.
            let parts: Vec<&str> = line.split(":{SHA}").collect();
            if parts.len() != 2 {
                return Err(Error::MalformedHtpasswdLine {
                    path_string: path_string.clone(),
                    line: i,
                });
            }

            let user = parts[0];
            let base64_sha1_password = parts[1];

            let sha1_password =
                base64::decode(base64_sha1_password)
                    .map_err(|_| Error::InvalidPasswordString {
                        path_string: path_string.clone(),
                        line: i,
                    })?;

            // Check for duplicated credentials in the Htpasswd file
            if registered_users.contains_key(user) {
                return Err(Error::DuplicateUser {
                    user: user.to_owned(),
                });
            }

            registered_users.insert(user.to_owned(), sha1_password);
        }

        Ok(HtpasswdDatabase { registered_users })
    }
}
