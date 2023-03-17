#[cfg(test)]
mod test_helpers;

mod api;
mod config;
mod database;
mod domain;
mod error;
mod extractors;
mod server;
mod services;

use error::Error;
type Result<T> = std::result::Result<T, Error>;

pub mod telemetry;

pub use {self::config::Config, database::Pool, server::Server};
