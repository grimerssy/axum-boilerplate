use std::time::Duration;

use anyhow::Context;
use reqwest::Url;
use secrecy::{ExposeSecret, Secret};
use serde::Serialize;

#[derive(Clone)]
pub struct EmailClient {
    http_client: reqwest::Client,
    base_url: Url,
    sender: String,
    authorization_token: Secret<String>,
}

#[derive(Clone, Debug)]
pub struct SendEmailRequest<'a> {
    pub recipient: &'a str,
    pub subject: &'a str,
    pub text_body: &'a str,
    pub html_body: &'a str,
}

impl EmailClient {
    pub fn new(
        timeout: Duration,
        base_url: Url,
        sender: String,
        authorization_token: Secret<String>,
    ) -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .unwrap(),
            base_url,
            sender,
            authorization_token,
        }
    }

    #[tracing::instrument(
        name = "Send an email",
        skip_all,
        fields(
            recipient = %request.recipient,
            subject = %request.subject
        )
        err(Debug),
    )]
    pub async fn send_email(
        &self,
        request: &SendEmailRequest<'_>,
    ) -> anyhow::Result<()> {
        let url = self.base_url.join("/email").unwrap();
        let request_body = PostmarkEmailRequest {
            from: self.sender.as_ref(),
            to: request.recipient,
            subject: request.subject,
            text_body: request.text_body,
            html_body: request.html_body,
        };
        self.http_client
            .post(url)
            .header(
                "X-Postmark-Server-Token",
                self.authorization_token.expose_secret(),
            )
            .json(&request_body)
            .send()
            .await
            .context("Failed to execute a http request")?
            .error_for_status()
            .map(|_| ())
            .context("Failed to send an email")
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct PostmarkEmailRequest<'a> {
    from: &'a str,
    to: &'a str,
    subject: &'a str,
    text_body: &'a str,
    html_body: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use wiremock::{MockServer, ResponseTemplate};

    #[tokio::test]
    async fn send_email_sends_the_expected_request() {
        let server = MockServer::start().await;
        configure_server(&server, ResponseTemplate::new(200)).await;
        let result = send_email(&server).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn send_email_fails_if_server_returns_500() {
        let server = MockServer::start().await;
        configure_server(&server, ResponseTemplate::new(500)).await;
        let result = send_email(&server).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn send_email_fails_if_server_takes_too_long() {
        let server = MockServer::start().await;
        configure_server(
            &server,
            ResponseTemplate::new(200).set_delay(Duration::from_secs(60)),
        )
        .await;
        let result = send_email(&server).await;
        assert!(result.is_err());
    }

    async fn configure_server(server: &MockServer, response: ResponseTemplate) {
        use reqwest::header::CONTENT_TYPE;
        use wiremock::{
            matchers::{header, header_exists, method, path},
            Mock,
        };
        Mock::given(header_exists("X-Postmark-Server-Token"))
            .and(header(CONTENT_TYPE, "application/json"))
            .and(path("/email"))
            .and(method("POST"))
            .and(expected_body())
            .respond_with(response)
            .expect(1)
            .mount(server)
            .await
    }

    async fn send_email(server: &MockServer) -> anyhow::Result<()> {
        use fake::{
            faker::{
                internet::en::SafeEmail,
                lorem::en::{Paragraph, Sentence},
            },
            Fake, Faker,
        };
        let email = || SafeEmail().fake::<String>();
        let subject = Sentence(1..2).fake::<String>();
        let content = Paragraph(1..10).fake::<String>();
        let timeout = Duration::from_millis(200);
        let base_url = Url::parse(&server.uri()).unwrap();
        let sender = email();
        let authorization_token = Secret::new(Faker.fake());
        let request = SendEmailRequest {
            recipient: &email(),
            subject: &subject,
            text_body: &content,
            html_body: &content,
        };
        EmailClient::new(timeout, base_url, sender, authorization_token)
            .send_email(&request)
            .await
    }

    fn expected_body() -> impl wiremock::Match + 'static {
        struct BodyMatcher;
        impl wiremock::Match for BodyMatcher {
            fn matches(&self, request: &wiremock::Request) -> bool {
                let json = serde_json::from_slice(&request.body);
                if json.is_err() {
                    return false;
                }
                let json: serde_json::Value = json.unwrap();
                json.get("From").is_some()
                    && json.get("To").is_some()
                    && json.get("Subject").is_some()
                    && json.get("TextBody").is_some()
                    && json.get("HtmlBody").is_some()
            }
        }
        BodyMatcher
    }
}
