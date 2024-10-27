use async_trait::async_trait;
use dotenvy;

use super::{
    super::base::DataStoreDriver,
    lib::{self, FtpCredentials},
};

// To use this data store, create a .env file in the base directory with the following values:
// export BRIDGE_FTPS_HOST="..."
// export BRIDGE_FTPS_PORT="..."
// export BRIDGE_FTPS_USERNAME="..."
// export BRIDGE_FTPS_PASSWORD="..."
// export BRIDGE_FTPS_BASE_PATH="..."

// NOTE: BRIDGE_FTPS_HOST should be a domain that supports SSL

#[derive(Debug)]
pub struct Ftps {
    credentials: lib::FtpCredentials,
}

impl Ftps {
    pub fn new() -> Option<Self> {
        dotenvy::dotenv().ok();
        let host = dotenvy::var("BRIDGE_FTPS_HOST");
        let port = dotenvy::var("BRIDGE_FTPS_PORT");
        let username = dotenvy::var("BRIDGE_FTPS_USERNAME");
        let password = dotenvy::var("BRIDGE_FTPS_PASSWORD");
        let base_path = dotenvy::var("BRIDGE_FTPS_BASE_PATH");

        if host.is_err()
            || port.is_err()
            || username.is_err()
            || password.is_err()
            || base_path.is_err()
        {
            return None;
        }

        let credentials = FtpCredentials {
            is_secure: false,
            host: host.unwrap(),
            port: port.unwrap(),
            username: username.unwrap(),
            password: password.unwrap(),
            base_path: base_path.unwrap(),
        };

        match lib::test_connection(&credentials) {
            Ok(_) => Some(Self { credentials }),
            Err(err) => {
                eprintln!("{err:?}");
                None
            }
        }
    }
}

#[async_trait]
impl DataStoreDriver for Ftps {
    async fn list_objects(&self, file_path: Option<&str>) -> Result<Vec<String>, String> {
        lib::list_objects(&self.credentials, file_path).await
    }

    async fn fetch_json(&self, key: &str, file_path: Option<&str>) -> Result<String, String> {
        lib::fetch_json(&self.credentials, key, file_path).await
    }

    async fn upload_json(
        &self,
        key: &str,
        json: String,
        file_path: Option<&str>,
    ) -> Result<usize, String> {
        lib::upload_json(&self.credentials, key, json, file_path).await
    }
}
