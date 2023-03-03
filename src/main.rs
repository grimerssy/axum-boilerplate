use axum_boilerplate::{telemetry, Config, Server};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry::init()?;
    let config = Config::new()?;
    Server::run(config).await
}
