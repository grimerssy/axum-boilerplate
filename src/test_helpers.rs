use std::str::FromStr;

use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHasher,
    Version,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
    Router,
};
use fake::{
    faker::{internet::en::SafeEmail, lorem::en::Sentence},
    Fake,
};
use once_cell::sync::Lazy;
use reqwest::Url;
use secrecy::ExposeSecret;
use tower::{Service, ServiceExt};
use uuid::Uuid;
use wiremock::{
    matchers::{method, path},
    Mock, MockBuilder, MockServer,
};

use crate::{telemetry, Config, Pool, Server};

static INIT: Lazy<()> = Lazy::new(|| {
    if std::env::var("LOG_TESTS").is_ok() {
        telemetry::init().unwrap();
    }
});

pub struct TestServer {
    router: Router,
    email_server: MockServer,
}

impl TestServer {
    pub async fn new(pool: Pool) -> Self {
        Lazy::force(&INIT);

        let email_server = MockServer::start().await;

        let mut config = Config::new().unwrap();
        config.email_client.base_url =
            Url::from_str(&email_server.uri()).unwrap();

        let router = Server::router(config, pool).unwrap();

        Self {
            router,
            email_server,
        }
    }

    pub async fn call(&mut self, req: Request<Body>) -> Response {
        self.router.ready().await.unwrap().call(req).await.unwrap()
    }

    pub async fn mount_mock(&self, mock: Mock) {
        mock.mount(&self.email_server).await;
    }

    pub async fn received_emails(&self) -> Vec<wiremock::Request> {
        self.email_server.received_requests().await.unwrap()
    }
}

#[derive(Clone, Debug)]
pub struct TestUser {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub picture_url: String,
    pub password: String,
    pub password_hash: String,
    pub verification_token: Uuid,
    pub verified: bool,
    pub refresh_token: String,
}

impl TestUser {
    pub async fn new(pool: &Pool) -> Self {
        let config = Config::new().unwrap();
        let hmac_secret = config.server.hmac_secret.expose_secret();
        let salt = SaltString::generate(&mut rand::thread_rng());
        let password = String::new();
        let password_hash = Argon2::new_with_secret(
            hmac_secret.as_bytes(),
            Algorithm::default(),
            Version::default(),
            Params::default(),
        )
        .unwrap()
        .hash_password(password.as_bytes(), &salt)
        .map(|ph| ph.to_string())
        .unwrap();
        sqlx::query!(
            r#"
            insert into users(
              name,
              email,
              picture_url,
              password_hash,
              verification_token,
              verified,
              refresh_token
            )
            values ($1, $2, $3, $4, $5, $6, $7)
            returning *;
            "#,
            Sentence(1..2).fake::<String>(),
            SafeEmail().fake::<String>(),
            Sentence(1..2).fake::<String>(),
            password_hash,
            Uuid::new_v4(),
            true,
            Sentence(1..2).fake::<String>(),
        )
        .fetch_one(pool)
        .await
        .map(|r| Self {
            id: r.id,
            name: r.name,
            email: r.email.unwrap(),
            picture_url: r.picture_url.unwrap(),
            password,
            password_hash: r.password_hash.unwrap(),
            verification_token: r.verification_token,
            verified: r.verified,
            refresh_token: r.refresh_token.unwrap(),
        })
        .unwrap()
    }
}

pub fn extract_verification_link(request: &wiremock::Request) -> Url {
    use linkify::{LinkFinder, LinkKind};
    let extract_link = |s: &str| {
        let links = LinkFinder::new()
            .links(s)
            .filter(|l| l.kind() == &LinkKind::Url)
            .collect::<Vec<_>>();
        assert_eq!(links.len(), 1);
        let link = links.first().unwrap().as_str().to_owned();
        Url::parse(&link).unwrap()
    };
    let body =
        serde_json::from_slice::<serde_json::Value>(&request.body).unwrap();
    let text_link = extract_link(body["TextBody"].as_str().unwrap());
    let html_link = extract_link(body["HtmlBody"].as_str().unwrap());
    assert_eq!(text_link, html_link);
    text_link
}

pub fn when_sending_an_email() -> MockBuilder {
    Mock::given(method("POST")).and(path("/email"))
}

pub fn assert_client_error(status: StatusCode, reason: &str) {
    assert!(
        status.is_client_error(),
        "requests must be rejected when {reason}"
    )
}
