use anyhow::Context;
use axum::{
    extract::{Query, State},
    http::StatusCode,
};
use secrecy::{ExposeSecret, Secret};
use tower_cookies::Cookies;
use uuid::Uuid;

use crate::{
    database::{begin_transaction, commit, Executor},
    error::Error,
    services::{
        cookie::CookieService,
        oauth::{AuthRequest, OauthClient, User},
        token::TokenService,
    },
    telemetry, Pool,
};

pub async fn handler(
    cookies: Cookies,
    Query(auth_req): Query<AuthRequest>,
    State(pool): State<Pool>,
    State(oauth_client): State<OauthClient>,
    State(token_service): State<TokenService>,
    State(cookie_service): State<CookieService>,
) -> crate::Result<StatusCode> {
    let user = oauth_client.fetch_google_user(auth_req).await?;
    let mut transaction = begin_transaction(&pool).await?;
    let user = match get_db_user(&user.email, &mut transaction).await? {
        Some(user) => user,
        None => {
            let verification_token = Uuid::new_v4();
            let id = insert_user_returning_id(
                &user,
                &verification_token,
                &mut transaction,
            )
            .await?;
            DbUser {
                id,
                refresh_token: None,
            }
        }
    };
    let refresh_token = match user.refresh_token {
        Some(token) => token,
        None => {
            let token = TokenService::generate_refresh_token();
            insert_refresh_token(user.id, &token, &mut transaction).await?;
            token
        }
    };
    let access_token = telemetry::instrument_blocking_task(move || {
        token_service.generate_access_token(user.id)
    })
    .await??;
    cookie_service.set_access_token(&cookies, access_token);
    cookie_service.set_refresh_token(&cookies, refresh_token);
    commit(transaction).await?;
    Ok(StatusCode::OK)
}

struct DbUser {
    id: i64,
    refresh_token: Option<Secret<String>>,
}

async fn get_db_user<'e, E: Executor<'e>>(
    email: &str,
    executor: E,
) -> anyhow::Result<Option<DbUser>> {
    match sqlx::query!(
        r#"
        select id, refresh_token
        from users
        where email = $1;
        "#,
        email
    )
    .fetch_optional(executor)
    .await
    .context("Failed to get db user")?
    {
        Some(row) => {
            let user = DbUser {
                id: row.id,
                refresh_token: row.refresh_token.map(Secret::new),
            };
            Ok(Some(user))
        }
        None => Ok(None),
    }
}

async fn insert_user_returning_id<'e, E: Executor<'e>>(
    user: &User,
    verification_token: &Uuid,
    executor: E,
) -> crate::Result<i64> {
    match sqlx::query!(
        r#"
        insert into users (
          name, email, verified, picture_url, verification_token
        )
        values ($1, $2, $3, $4, $5)
        on conflict do nothing
        returning id;
        "#,
        user.name,
        user.email,
        user.email_verified,
        user.picture_url,
        verification_token
    )
    .fetch_optional(executor)
    .await
    .context("Failed to insert user")?
    {
        Some(user) => Ok(user.id),
        None => Err(Error::EmailTaken).map_err(telemetry::warn),
    }
}

async fn insert_refresh_token<'e, E: Executor<'e>>(
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
    .context("Failed to update refresh token for user")
}
