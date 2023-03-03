use anyhow::Context;
use axum::{extract::State, http::StatusCode};
use secrecy::{ExposeSecret, Secret};
use tower_cookies::Cookies;
use tracing::{field::display, Span};

use crate::{
    database::Executor,
    error::Error,
    services::{cookie::CookieService, token::TokenService},
    telemetry, Pool,
};

#[tracing::instrument(
    name = "Refresh user's token pair"
    skip_all,
    fields(
        user_id = tracing::field::Empty,
    )
)]
pub async fn handler(
    cookies: Cookies,
    State(pool): State<Pool>,
    State(token_service): State<TokenService>,
    State(cookie_service): State<CookieService>,
) -> crate::Result<StatusCode> {
    let refresh_token = cookie_service
        .get_refresh_token(&cookies)
        .ok_or(Error::NoRefreshToken)?;
    let user_id = get_user_id(&refresh_token, &pool)
        .await?
        .ok_or(Error::InvalidRefreshToken)?;
    Span::current().record("user_id", &display(user_id));
    let access_token = telemetry::instrument_blocking_task(move || {
        token_service.generate_access_token(user_id)
    })
    .await??;
    cookie_service.set_access_token(&cookies, access_token);
    cookie_service.set_refresh_token(&cookies, refresh_token);
    Ok(StatusCode::OK)
}

#[tracing::instrument(
    name = "Get user id"
    skip_all,
    err(Debug),
)]
async fn get_user_id<'e, E: Executor<'e>>(
    refresh_token: &Secret<String>,
    executor: E,
) -> anyhow::Result<Option<i64>> {
    let id = sqlx::query!(
        r#"
        select id
        from users
        where refresh_token = $1;
        "#,
        refresh_token.expose_secret()
    )
    .fetch_optional(executor)
    .await
    .context("Failed to select user id from database")?
    .map(|r| r.id);
    Ok(id)
}
