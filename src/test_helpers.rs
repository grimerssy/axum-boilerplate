use std::str::FromStr;

use axum::{
    body::Body,
    http::{header::CONTENT_TYPE, Request, StatusCode},
    response::Response,
    Router,
};
use once_cell::sync::Lazy;
use reqwest::Url;
use tower::{Service, ServiceExt};
use wiremock::{
    matchers::{method, path},
    Mock, MockBuilder, MockServer, ResponseTemplate,
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

pub struct TestUser;

impl TestUser {
    pub fn name() -> String {
        "Name Surname".into()
    }

    pub fn email() -> String {
        "email@domain.com".into()
    }

    pub fn password() -> String {
        "ABCxyz123".into()
    }

    pub async fn signup(server: &mut TestServer) -> Response {
        let mock =
            when_sending_an_email().respond_with(ResponseTemplate::new(200));
        server.mount_mock(mock).await;
        let body = (
            ("name", Self::name()),
            ("email", Self::email()),
            ("password", Self::password()),
        );
        let body = serde_urlencoded::to_string(body).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/auth/signup")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        server.call(req).await
    }

    pub async fn login(server: &mut TestServer) -> Response {
        let body = (("email", Self::email()), ("password", Self::password()));
        let body = serde_urlencoded::to_string(body).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        server.call(req).await
    }

    pub async fn enter_session(server: &mut TestServer) {
        let res = Self::signup(server).await;
        assert!(res.status().is_success());
        let res = Self::login(server).await;
        assert!(res.status().is_success());
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
