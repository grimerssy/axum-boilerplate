use anyhow::Context;
use axum::{extract::State, http::StatusCode};
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use validator::Validate;

use crate::{
    database::Executor,
    domain::validated_password::{
        ascii, at_least_8, at_most_32, digit, lowercase, uppercase, Password,
    },
    error::Error,
    extractors::{validated::Form, User},
    services::hash::PasswordHasher,
    telemetry, Pool,
};

#[derive(Clone, Debug, Deserialize, Validate)]
pub struct Payload {
    current_password: Secret<String>,
    #[validate(
        custom(
            function = "at_least_8",
            message = "must contain at least 8 characters"
        ),
        custom(
            function = "at_most_32",
            message = "must contain at most 32 characters"
        ),
        custom(
            function = "ascii",
            message = "must contain only latin letters, digits and special characters"
        ),
        custom(
            function = "lowercase",
            message = "must contain at least one lowercase letter"
        ),
        custom(
            function = "uppercase",
            message = "must contain at least one uppercase letter"
        ),
        custom(
            function = "digit",
            message = "must contain at least one digit"
        )
    )]
    new_password: Password,
}

pub async fn handler(
    user: User,
    State(password_hasher): State<PasswordHasher>,
    State(pool): State<Pool>,
    Form(payload): Form<Payload>,
) -> crate::Result<StatusCode> {
    let expected_password_hash = get_password_hash(user.id, &pool)
        .await?
        .unwrap_or_else(|| password_hasher.mock_password_hash());
    let moved_password_hasher = password_hasher.clone();
    let is_password_valid = telemetry::instrument_blocking_task(move || {
        moved_password_hasher
            .verify_password(&payload.current_password, &expected_password_hash)
    })
    .await??;
    if !is_password_valid {
        Err(Error::InvalidPassword).map_err(telemetry::warn)?;
    }
    let new_password_hash = telemetry::instrument_blocking_task(move || {
        password_hasher.hash_password(payload.new_password.as_ref())
    })
    .await??;
    update_password_hash(user.id, new_password_hash, &pool).await?;
    Ok(StatusCode::OK)
}

async fn get_password_hash<'e, E: Executor<'e>>(
    user_id: i64,
    executor: E,
) -> anyhow::Result<Option<Secret<String>>> {
    sqlx::query!(
        r#"
        select password_hash
        from users
        where id = $1;
        "#,
        user_id
    )
    .fetch_one(executor)
    .await
    .map(|r| r.password_hash.map(Secret::new))
    .context("Failed to get password hash from the database")
}

async fn update_password_hash<'e, E: Executor<'e>>(
    user_id: i64,
    new_password_hash: Secret<String>,
    executor: E,
) -> anyhow::Result<()> {
    sqlx::query!(
        r#"
        update users
        set password_hash = $1
        where id = $2;
        "#,
        new_password_hash.expose_secret(),
        user_id
    )
    .execute(executor)
    .await
    .map(|_| ())
    .context("Failed to update password hash in the database")
}
