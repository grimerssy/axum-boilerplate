use anyhow::Context;
use axum::{extract::State, http::StatusCode};
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use tower_cookies::Cookies;
use validator::Validate;

use crate::{
    database::Executor,
    error::Error,
    extractors::validated::Form,
    services::{
        cookie::CookieService, hash::PasswordHasher, token::TokenService,
    },
    telemetry::{self, instrument_blocking_task},
    Pool,
};

#[derive(Clone, Debug, Deserialize, Validate)]
pub struct Payload {
    email: String,
    password: Secret<String>,
}

#[tracing::instrument(
    name = "Log in existing user",
    skip_all,
    fields(email = %payload.email)
)]
pub async fn handler(
    cookies: Cookies,
    State(pool): State<Pool>,
    State(password_hasher): State<PasswordHasher>,
    State(token_service): State<TokenService>,
    State(cookie_service): State<CookieService>,
    Form(payload): Form<Payload>,
) -> crate::Result<StatusCode> {
    let user = find_user(&payload.email, &pool).await?;
    let password_hash = user
        .password_hash
        .unwrap_or_else(|| password_hasher.mock_password_hash());
    let is_password_valid = instrument_blocking_task(move || {
        password_hasher.verify_password(&payload.password, &password_hash)
    })
    .await??;
    if !is_password_valid {
        Err(Error::InvalidCredentials).map_err(telemetry::warn)?;
    }
    let access_token = instrument_blocking_task(move || {
        token_service.generate_access_token(user.id)
    })
    .await??;
    let refresh_token = match user.refresh_token {
        Some(token) => token,
        None => {
            let token = TokenService::generate_refresh_token();
            save_refresh_token(user.id, &token, &pool).await?;
            token
        }
    };
    cookie_service.set_access_token(&cookies, access_token);
    cookie_service.set_refresh_token(&cookies, refresh_token);
    Ok(StatusCode::OK)
}

#[derive(Clone, Debug, Default)]
struct User {
    id: i64,
    password_hash: Option<Secret<String>>,
    refresh_token: Option<Secret<String>>,
}

#[tracing::instrument(name = "Find user by email", skip(executor), err(Debug))]
async fn find_user<'e, E: Executor<'e>>(
    email: &str,
    executor: E,
) -> anyhow::Result<User> {
    match sqlx::query!(
        r#"
        select id, password_hash, refresh_token
        from users
        where email = $1;
        "#,
        email
    )
    .fetch_optional(executor)
    .await
    .context("Failed to fetch user's password hash")
    .map_err(telemetry::error)?
    {
        Some(r) => Ok(User {
            id: r.id,
            password_hash: r.password_hash.map(Secret::new),
            refresh_token: r.refresh_token.map(Secret::new),
        }),
        None => Ok(User::default()),
    }
}

#[tracing::instrument(
    name = "Save user's refresh token",
    skip(executor),
    err(Debug)
)]
async fn save_refresh_token<'e, E: Executor<'e>>(
    user_id: i64,
    refresh_token: &Secret<String>,
    executor: E,
) -> anyhow::Result<()> {
    sqlx::query!(
        r#"
        update users
        set refresh_token = $1
        where id = $2;
        "#,
        refresh_token.expose_secret(),
        user_id
    )
    .execute(executor)
    .await
    .map(|_| ())
    .context("Failed to set user's refresh token")
}
