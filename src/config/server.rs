use reqwest::Url;
use secrecy::Secret;
use serde::Deserialize;
use serde_aux::field_attributes::deserialize_number_from_string;
use serde_with::{serde_as, DisplayFromStr};

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub host: [u8; 4],
    #[serde(deserialize_with = "deserialize_number_from_string")]
    pub port: u16,
    #[serde_as(as = "DisplayFromStr")]
    pub base_url: Url,
    pub hmac_secret: Secret<String>,
}
