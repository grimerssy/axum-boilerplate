use axum::{extract::State, response::Redirect};

use crate::services::oauth::OauthClient;

pub async fn handler(State(oauth_client): State<OauthClient>) -> Redirect {
    let auth_url = oauth_client.google_auth_url();
    Redirect::to(&auth_url)
}
