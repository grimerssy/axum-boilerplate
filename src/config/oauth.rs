use reqwest::Url;
use serde::Deserialize;

use crate::services::oauth::{ClientConfig, OauthClient};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub google: ClientConfig,
}

impl Config {
    pub fn oauth_client(self, base_url: &Url) -> anyhow::Result<OauthClient> {
        OauthClient::new(base_url, self.google)
    }
}
