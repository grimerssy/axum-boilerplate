use std::net::SocketAddr;

use axum::{http::StatusCode, routing::post, Router, Server};
use axum_boilerplate::Config;

#[tokio::main]
async fn main() {
    let addr = Config::new()
        .unwrap()
        .email_client
        .base_url
        .to_string()
        .replace("http://localhost", "127.0.0.1")
        .trim_matches('/')
        .parse::<SocketAddr>()
        .unwrap();
    Server::bind(&addr)
        .serve(router().into_make_service())
        .await
        .unwrap()
}

fn router() -> Router {
    Router::new().route("/email", post(|| async { StatusCode::OK }))
}
