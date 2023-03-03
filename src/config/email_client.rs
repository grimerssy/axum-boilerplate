use std::{str::FromStr, time::Duration};

use reqwest::Url;
use secrecy::Secret;
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};
use validator::validate_email;

use crate::services::email::EmailClient;

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub timeout: Duration,
    #[serde_as(as = "DisplayFromStr")]
    pub base_url: Url,
    #[serde_as(as = "DisplayFromStr")]
    pub sender: Email,
    pub authorization_token: Secret<String>,
}

impl Config {
    pub fn client(self) -> EmailClient {
        EmailClient::new(
            self.timeout,
            self.base_url,
            self.sender.0,
            self.authorization_token,
        )
    }
}

#[derive(Clone, Debug)]
pub struct Email(String);

impl FromStr for Email {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if validate_email(s) {
            Ok(Self(s.into()))
        } else {
            anyhow::bail!("{s} is not a valid email")
        }
    }
}
