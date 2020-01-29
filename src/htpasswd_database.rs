use std::{
    collections::HashMap,
    fs::File,
    path::Path,
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

pub struct HtpasswdDatabase {
    registered_users: HashMap<String, Vec<u8>>,
}
impl HtpasswdDatabase {
    pub fn from_file(htpasswd_file_path: &Path) -> Result<HtpasswdDatabase, Error> {
        let path_string = htpasswd_file_path.to_string_lossy().to_string();

        let file = File::open(htpasswd_file_path)
            .map_err(|io_error| Error::CannotOpenHtpasswdFile {
                path_string: path_string.clone(),
                io_error,
            })?;

        let reader = BufReader::new(file);

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

            if registered_users.contains_key(user) {
                return Err(Error::DuplicateUser {
                    path_string: path_string.clone(),
                    line: i,
                    user: user.to_owned(),
                });
            }

            registered_users.insert(user.to_owned(), sha1_password);
        }

        Ok(HtpasswdDatabase { registered_users })
    }

    pub(crate) fn is_valid(&self, auth_data: &AuthData) -> bool {
        if !self.registered_users.contains_key(&auth_data.user) {
            return false;
        }

        let mut sha1_hasher = Sha1::new();
        sha1_hasher.input(&auth_data.password);

        let sha1_password = sha1_hasher.result().to_vec();

        &sha1_password == self.registered_users.get(&auth_data.user).unwrap()
    }
}
