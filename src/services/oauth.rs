use anyhow::Context;
use oauth2::{
    basic::{BasicClient, BasicTokenType},
    reqwest::async_http_client,
    AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EmptyExtraTokenFields, RedirectUrl, RevocationUrl, Scope,
    StandardTokenResponse, TokenResponse, TokenUrl,
};
use reqwest::Url;
use secrecy::{ExposeSecret, Secret};
use serde::Deserialize;

static GOOGLE_USER_INFO: &str =
    "https://www.googleapis.com/oauth2/v1/userinfo?alt=json";
static GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
static GOOGLE_TOKEN_URL: &str = "https://www.googleapis.com/oauth2/v3/token";
static GOOGLE_REDIRECT_ENDPOINT: &str = "auth/google/callback";
static GOOGLE_REVOKATION_URL: Option<&str> =
    Some("https://oauth2.googleapis.com/revoke");

#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub picture_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthRequest {
    code: String,
    #[allow(unused)]
    state: String,
}

#[derive(Clone)]
pub struct OauthClient {
    http_client: reqwest::Client,
    google_client: BasicClient,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClientConfig {
    pub client_id: String,
    pub client_secret: Secret<String>,
}

impl OauthClient {
    pub fn new(
        base_url: &Url,
        google_config: ClientConfig,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            http_client: reqwest::Client::new(),
            google_client: Self::oauth_client(
                base_url,
                google_config,
                GOOGLE_AUTH_URL,
                GOOGLE_TOKEN_URL,
                GOOGLE_REDIRECT_ENDPOINT,
                GOOGLE_REVOKATION_URL,
            )?,
        })
    }

    pub fn google_auth_url(&self) -> String {
        let (auth_url, _csrf_token) = self
            .google_client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.email".to_string(),
            ))
            .add_scope(Scope::new(
                "https://www.googleapis.com/auth/userinfo.profile".to_string(),
            ))
            .url();
        auth_url.to_string()
    }

    pub async fn fetch_google_user(
        &self,
        auth_request: AuthRequest,
    ) -> anyhow::Result<User> {
        let token =
            Self::exchange_code(&self.google_client, auth_request).await?;

        self.get_user(GOOGLE_USER_INFO, token.access_token())
            .await?
            .json::<GoogleUser>()
            .await
            .map(|gu| gu.into())
            .context("Failed to deserialize google user")
    }

    fn oauth_client(
        base_url: &Url,
        config: ClientConfig,
        auth_url: &str,
        token_url: &str,
        redirect_endpoint: &str,
        revokation_url: Option<&str>,
    ) -> anyhow::Result<BasicClient> {
        let client = BasicClient::new(
            ClientId::new(config.client_id),
            Some(ClientSecret::new(
                config.client_secret.expose_secret().to_owned(),
            )),
            AuthUrl::new(auth_url.into()).unwrap(),
            Some(TokenUrl::new(token_url.into()).unwrap()),
        );
        let redirect_url =
            RedirectUrl::new(format!("{base_url}{redirect_endpoint}"))
                .context("Failed to create redirect url")?;
        let client = client.set_redirect_uri(redirect_url);
        if let Some(revokation_url) = revokation_url {
            let revokation_url = RevocationUrl::new(revokation_url.into())
                .context("Failed to create revokation url")?;
            return Ok(client.set_revocation_uri(revokation_url));
        }
        Ok(client)
    }

    async fn exchange_code(
        oauth_client: &BasicClient,
        auth_request: AuthRequest,
    ) -> anyhow::Result<
        StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    > {
        oauth_client
            .exchange_code(AuthorizationCode::new(auth_request.code))
            .request_async(async_http_client)
            .await
            .context("Failed to exchange google oauth code")
    }

    async fn get_user(
        &self,
        url: &str,
        access_token: &AccessToken,
    ) -> anyhow::Result<reqwest::Response> {
        self.http_client
            .get(url)
            .bearer_auth(access_token.secret())
            .send()
            .await
            .context("Failed to fetch user")
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct GoogleUser {
    name: String,
    email: String,
    verified_email: bool,
    picture: String,
}

impl From<GoogleUser> for User {
    fn from(value: GoogleUser) -> Self {
        Self {
            name: value.name,
            email: value.email,
            email_verified: value.verified_email,
            picture_url: Some(value.picture),
        }
    }
}
