use async_trait::async_trait;
use axum::{extract::FromRequestParts, http::request::Parts, RequestPartsExt};
use secrecy::ExposeSecret;
use tower_cookies::Cookies;

use crate::{server::ServerState, telemetry, Error};

#[derive(Clone, Copy, Debug, Default)]
pub struct User {
    pub id: i64,
}

#[async_trait]
impl FromRequestParts<ServerState> for User {
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ServerState,
    ) -> Result<Self, Self::Rejection> {
        let cookies = parts
            .extract::<Cookies>()
            .await
            .map_err(|_| Error::NoAccessToken)?;
        let access_token = state
            .cookie_service
            .get_access_token(&cookies)
            .ok_or(Error::NoAccessToken)?;
        let token_service = state.token_service.clone();
        let id = telemetry::instrument_blocking_task(move || {
            token_service.get_user_id(access_token.expose_secret())
        })
        .await?
        .map_err(|_| Error::InvalidAccessToken)?;
        Ok(Self { id })
    }
}
