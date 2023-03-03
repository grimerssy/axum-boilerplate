use std::str::FromStr;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
    Router,
};
use once_cell::sync::Lazy;
use reqwest::Url;
use tower::{Service, ServiceExt};
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
