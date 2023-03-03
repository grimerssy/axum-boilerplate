use std::time::Duration;

use oauth2::url::Host;
use serde::Deserialize;

use crate::services::{cookie::CookieService, token::TokenService};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub issuer: Host<String>,
    pub audience: Host<String>,
    pub access_token_ttl: Duration,
    pub refresh_token_ttl: Duration,
}

impl Config {
    pub fn token_service(self, secret: &[u8]) -> TokenService {
        TokenService::new(
            self.issuer,
            self.audience,
            self.access_token_ttl,
            secret,
        )
    }

    pub fn cookie_service(
        &self,
        secret: &[u8],
    ) -> anyhow::Result<CookieService> {
        CookieService::new(
            secret,
            self.access_token_ttl,
            self.refresh_token_ttl,
        )
    }
}
