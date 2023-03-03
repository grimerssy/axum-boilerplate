use anyhow::Context;
use tracing::{error, warn, Subscriber};
use tracing_log::LogTracer;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter, FmtSubscriber};

pub fn init() -> anyhow::Result<()> {
    LogTracer::init()?;
    tracing::subscriber::set_global_default(subscriber())
        .map_err(anyhow::Error::from)
}

fn subscriber() -> impl Subscriber + Send + Sync {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or("info".into());
    FmtSubscriber::builder()
        .with_env_filter(env_filter)
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .pretty()
        .finish()
}

pub async fn instrument_blocking_task<F, R>(f: F) -> anyhow::Result<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let current_span = tracing::Span::current();
    tokio::task::spawn_blocking(move || current_span.in_scope(f))
        .await
        .context("Failed to spawn blocking task")
}

pub fn warn<E>(e: E) -> E
where
    E: std::fmt::Debug,
{
    warn!("{e:?}");
    e
}

pub fn error<E>(e: E) -> E
where
    E: std::fmt::Debug,
{
    error!("{e:?}");
    e
}
