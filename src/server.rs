use std::net::SocketAddr;

use axum::{body::Body, extract::FromRef, http::Request, Router};
use reqwest::Url;
use secrecy::ExposeSecret;
use tower::ServiceBuilder;
use tower_cookies::CookieManagerLayer;
use tower_http::trace::TraceLayer;
use tower_request_id::{RequestId, RequestIdLayer};

use crate::{
    api,
    config::Config,
    services::{
        cookie::CookieService, email::EmailClient, hash::PasswordHasher,
        oauth::OauthClient, token::TokenService,
    },
    Pool,
};

#[derive(Clone, FromRef)]
pub struct ServerState {
    pub base_url: Url,
    pub oauth_client: OauthClient,
    pub token_service: TokenService,
    pub cookie_service: CookieService,
    pub database_pool: Pool,
    pub email_client: EmailClient,
    pub password_hasher: PasswordHasher,
}

pub struct Server;

impl Server {
    pub async fn run(config: Config) -> anyhow::Result<()> {
        let addr = SocketAddr::from((config.server.host, config.server.port));
        let pool = Pool::connect_lazy_with(config.database.connect_options());
        let router = Self::router(config, pool)?;
        axum::Server::bind(&addr)
            .serve(router.into_make_service())
            .await
            .map_err(anyhow::Error::from)
    }

    pub fn router(
        config: Config,
        database_pool: Pool,
    ) -> anyhow::Result<Router> {
        let hmac_secret = config.server.hmac_secret.expose_secret().as_bytes();
        let base_url = config.server.base_url;
        let email_client = config.email_client.client();
        let password_hasher = config.password_hasher.hasher(hmac_secret)?;
        let cookie_service = config.auth.cookie_service(hmac_secret)?;
        let token_service = config.auth.token_service(hmac_secret);
        let oauth_client = config.oauth.oauth_client(&base_url)?;

        let trace_layer = TraceLayer::new_for_http().make_span_with(
            |request: &Request<Body>| {
                let request_id = request
                    .extensions()
                    .get::<RequestId>()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "unknown".into());
                tracing::info_span!(
                    "request",
                    id = %request_id,
                    method = %request.method(),
                    uri = %request.uri(),
                )
            },
        );

        let state = ServerState {
            base_url,
            oauth_client,
            token_service,
            cookie_service,
            database_pool,
            email_client,
            password_hasher,
        };
        let mw = ServiceBuilder::new()
            .layer(CookieManagerLayer::new())
            .layer(RequestIdLayer)
            .layer(trace_layer);

        Ok(api::router().with_state(state).layer(mw))
    }
}
