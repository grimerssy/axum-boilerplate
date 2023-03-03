use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use oauth2::url::Host;
use rand::{distributions::Alphanumeric, Rng};
use secrecy::Secret;
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct TokenService {
    algorithm: Algorithm,
    issuer: Host<String>,
    audience: Host<String>,
    token_ttl: Duration,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Claims {
    aud: String,
    iat: usize,
    exp: usize,
    iss: String,
    sub: String,
    user_id: i64,
}

impl Claims {
    fn new(user_id: i64, aud: String, iss: String, ttl: Duration) -> Self {
        let iat = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let exp = iat + ttl;
        Self {
            aud,
            iat: iat.as_secs() as usize,
            exp: exp.as_secs() as usize,
            iss,
            sub: format!("user-{user_id}"),
            user_id,
        }
    }
}

impl TokenService {
    pub fn new(
        issuer: Host<String>,
        audience: Host<String>,
        token_ttl: Duration,
        secret: &[u8],
    ) -> Self {
        let encoding_key = EncodingKey::from_secret(secret);
        let decoding_key = DecodingKey::from_secret(secret);
        Self {
            algorithm: Algorithm::HS256,
            issuer,
            audience,
            token_ttl,
            encoding_key,
            decoding_key,
        }
    }

    #[tracing::instrument(name = "Generate access token", skip(self))]
    pub fn generate_access_token(
        &self,
        user_id: i64,
    ) -> anyhow::Result<Secret<String>> {
        let claims = Claims::new(
            user_id,
            self.audience.to_string(),
            self.issuer.to_string(),
            self.token_ttl,
        );
        jsonwebtoken::encode(
            &Header::new(self.algorithm),
            &claims,
            &self.encoding_key,
        )
        .map(Secret::new)
        .context("Failed to encode a JWT token")
    }

    pub fn generate_refresh_token() -> Secret<String> {
        let token = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect::<String>();
        Secret::new(token)
    }

    #[tracing::instrument(name = "Decode access token", skip(self))]
    pub fn get_user_id(&self, token: &str) -> anyhow::Result<i64> {
        jsonwebtoken::decode::<Claims>(
            token,
            &self.decoding_key,
            &Validation::new(self.algorithm),
        )
        .map(|t| t.claims.user_id)
        .context("Failed to decode a JWT token")
    }
}
