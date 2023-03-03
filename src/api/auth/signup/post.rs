use anyhow::Context;
use axum::{extract::State, http::StatusCode};
use reqwest::Url;
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;
use uuid::Uuid;
use validator::Validate;

use crate::{
    database::{begin_transaction, commit, Executor},
    domain::validated_password::{
        ascii, at_least_8, at_most_32, digit, lowercase, uppercase, Password,
    },
    error::Error,
    extractors::validated::Form,
    services::{
        email::{EmailClient, SendEmailRequest},
        hash::PasswordHasher,
    },
    telemetry, Pool,
};

#[derive(Clone, Debug, Deserialize, Validate)]
#[serde(rename_all = "camelCase")]
pub struct Payload {
    #[validate(
        length(min = 1, message = "cannot be empty"),
        length(max = 50, message = "cannot be longer than 50 characters")
    )]
    name: String,
    #[validate(
        email(message = "is not a valid email"),
        length(max = 50, message = "cannot be longer than 50 characters")
    )]
    email: String,
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
    password: Password,
}

#[tracing::instrument(
    name = "Register new user",
    skip_all,
    fields(
        name = %payload.name,
        email = %payload.email,
    )
)]
pub async fn handler(
    State(base_url): State<Url>,
    State(pool): State<Pool>,
    State(hasher): State<PasswordHasher>,
    State(email_client): State<EmailClient>,
    Form(payload): Form<Payload>,
) -> crate::Result<StatusCode> {
    let password_hash = telemetry::instrument_blocking_task(move || {
        hasher.hash_password(payload.password.as_ref())
    })
    .await??;
    let verification_token = Uuid::new_v4();
    let mut transaction = begin_transaction(&pool).await?;
    insert_user(
        &payload.name,
        &payload.email,
        &password_hash,
        &verification_token,
        &mut transaction,
    )
    .await?;
    send_verification_email(
        &email_client,
        &payload.email,
        &base_url,
        &verification_token,
    )
    .await?;
    commit(transaction).await?;
    Ok(StatusCode::CREATED)
}

#[tracing::instrument(name = "Save new user", skip(password_hash, executor))]
async fn insert_user<'e, E: Executor<'e>>(
    name: &str,
    email: &str,
    password_hash: &Secret<String>,
    verification_token: &Uuid,
    executor: E,
) -> crate::Result<()> {
    match sqlx::query!(
        r#"
        insert into users (
          name,
          email,
          password_hash,
          verification_token
        )
        values ($1, $2, $3, $4)
        on conflict do nothing;
        "#,
        name,
        email,
        password_hash.expose_secret(),
        verification_token
    )
    .execute(executor)
    .await
    .context("Failed to insert user")
    .map_err(telemetry::error)?
    .rows_affected()
    {
        0 => Err(Error::EmailTaken).map_err(telemetry::warn),
        1 => Ok(()),
        _ => unreachable!(),
    }
}

#[tracing::instrument(
    name = "Send verification email",
    skip(email_client, base_url)
)]
async fn send_verification_email(
    email_client: &EmailClient,
    recipient: &str,
    base_url: &Url,
    verification_token: &Uuid,
) -> anyhow::Result<()> {
    let mut verification_link = base_url.clone();
    verification_link.set_path("auth/verify");
    verification_link.set_query(Some(&format!("token={verification_token}")));

    let request = SendEmailRequest {
        recipient,
        subject: "Account verification",
        text_body: &format!("{verification_link}"),
        html_body: &format!("<a>{verification_link}</a>"),
    };
    email_client
        .send_email(&request)
        .await
        .context("Failed to send a verification email")
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{header::CONTENT_TYPE, Request},
    };
    use wiremock::ResponseTemplate;

    use crate::{
        test_helpers::{
            assert_client_error, extract_verification_link,
            when_sending_an_email, TestServer,
        },
        Pool,
    };

    #[sqlx::test]
    async fn rejects_invalid_name(pool: Pool) {
        let mut server = TestServer::new(pool).await;
        let tests = vec![
            ("".into(), "is empty"),
            ("\0".repeat(50 + 1), "is too long"),
        ];
        for (name, reason) in tests {
            let req = request(&name, &valid_email(), &valid_password());
            let res = server.call(req).await;
            assert_client_error(res.status(), &format!("name {reason}"))
        }
    }

    #[sqlx::test]
    async fn rejects_invalid_email(pool: Pool) {
        let mut server = TestServer::new(pool).await;
        let tests = vec![
            ("".into(), "is empty"),
            ("\0".repeat(50 + 1), "is too long"),
            ("not an email".into(), "is not a valid email"),
        ];
        for (email, reason) in tests {
            let req = request(&valid_name(), &email, &valid_password());
            let res = server.call(req).await;
            assert_client_error(res.status(), &format!("email {reason}"))
        }
    }

    #[sqlx::test]
    async fn rejects_invalid_password(pool: Pool) {
        let mut server = TestServer::new(pool).await;
        let tests = vec![
            ("".into(), "is empty"),
            ("\0".repeat(8 - 1), "is too short"),
            ("\0".repeat(32 + 1), "is too long"),
            ("ÅßÇxyz123".into(), "contains non-ascii characters"),
            ("ABCXYZ123".into(), "does not contain any lowercase letters"),
            ("abcxyz123".into(), "does not contain any uppercase letters"),
            ("ABCxyzABC".into(), "does not contain any digits"),
        ];
        for (password, reason) in tests {
            let req = request(&valid_name(), &valid_email(), &password);
            let res = server.call(req).await;
            assert_client_error(res.status(), &format!("password {reason}"))
        }
    }

    #[sqlx::test]
    async fn does_not_save_user_if_fails(pool: Pool) {
        let mut server = TestServer::new(pool.clone()).await;
        let mock =
            when_sending_an_email().respond_with(ResponseTemplate::new(500));
        server.mount_mock(mock).await;
        let res = server.call(valid_request()).await;
        assert!(res.status().is_server_error());
        assert_eq!(count_users(&pool).await, 0);
    }

    #[sqlx::test]
    async fn saves_new_user(pool: Pool) {
        let mut server = TestServer::new(pool.clone()).await;
        let mock =
            when_sending_an_email().respond_with(ResponseTemplate::new(200));
        server.mount_mock(mock).await;
        let res = server.call(valid_request()).await;
        assert!(res.status().is_success());
        assert_eq!(count_users(&pool).await, 1);
    }

    #[sqlx::test]
    async fn sends_email_with_valid_verification_link(pool: Pool) {
        let mut server = TestServer::new(pool.clone()).await;
        let mock = when_sending_an_email()
            .respond_with(ResponseTemplate::new(200))
            .expect(1);
        server.mount_mock(mock).await;
        let res = server.call(valid_request()).await;
        assert!(res.status().is_success());
        let email_requests = server.received_emails().await;
        let link = extract_verification_link(email_requests.first().unwrap());
        let verification_token =
            sqlx::query!(r#"select verification_token from users;"#)
                .fetch_one(&pool)
                .await
                .unwrap()
                .verification_token;
        assert_eq!(link.path(), "/auth/verify");
        let query = link
            .query_pairs()
            .next()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .unwrap();
        assert_eq!(query, ("token".into(), verification_token.to_string()));
    }

    #[sqlx::test]
    async fn fails_on_duplicate_request(pool: Pool) {
        let mut server = TestServer::new(pool.clone()).await;
        let mock = when_sending_an_email()
            .respond_with(ResponseTemplate::new(200))
            .expect(1);
        server.mount_mock(mock).await;
        let res = server.call(valid_request()).await;
        assert!(res.status().is_success());
        let res = server.call(valid_request()).await;
        assert_eq!(res.status(), axum::http::StatusCode::CONFLICT);
        assert_eq!(count_users(&pool).await, 1);
    }

    fn request(name: &str, email: &str, password: &str) -> Request<Body> {
        let body = (("name", name), ("email", email), ("password", password));
        let body = serde_urlencoded::to_string(body).unwrap();
        Request::builder()
            .method("POST")
            .uri("/auth/signup")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap()
    }

    async fn count_users(pool: &Pool) -> i64 {
        sqlx::query!(r#"select count(*) from users;"#)
            .fetch_one(pool)
            .await
            .unwrap()
            .count
            .unwrap()
    }

    fn valid_name() -> String {
        "Name Surname".into()
    }

    fn valid_email() -> String {
        "email@domain.com".into()
    }

    fn valid_password() -> String {
        "ABCxyz123".into()
    }

    fn valid_request() -> Request<Body> {
        request(&valid_name(), &valid_email(), &valid_password())
    }
}
