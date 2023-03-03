use anyhow::Context;
use axum::{
    extract::{Query, State},
    http::StatusCode,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{database::Executor, error::Error, telemetry, Pool};

#[derive(Clone, Debug, Deserialize)]
pub struct Params {
    token: Uuid,
}

#[tracing::instrument(
    name = "Verify a user",
    skip_all,
    fields(
        token = %params.token,
    )
)]
pub async fn handler(
    Query(params): Query<Params>,
    State(pool): State<Pool>,
) -> crate::Result<StatusCode> {
    verify_user(&params.token, &pool).await?;
    Ok(StatusCode::OK)
}

#[tracing::instrument(name = "Update user verification status", skip(executor))]
async fn verify_user<'e, E: Executor<'e>>(
    verification_token: &Uuid,
    executor: E,
) -> crate::Result<()> {
    match sqlx::query!(
        r#"
        update users
        set verified = true
        where verification_token = $1;
        "#,
        verification_token
    )
    .execute(executor)
    .await
    .context("Failed to update user verification status")
    .map_err(telemetry::error)?
    .rows_affected()
    {
        0 => Err(Error::UnknownVerificationToken).map_err(telemetry::warn),
        1 => Ok(()),
        _ => unreachable!(),
    }
}
