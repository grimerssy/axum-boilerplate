mod auth;
mod database;
mod email_client;
mod oauth;
mod password_hasher;
mod server;

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(flatten)]
    pub server: server::Config,
    pub auth: auth::Config,
    pub oauth: oauth::Config,
    pub database: database::Config,
    pub email_client: email_client::Config,
    pub password_hasher: password_hasher::Config,
}

impl Config {
    pub fn new() -> Result<Self, config::ConfigError> {
        let environment = current_environment();
        let base_path = std::env::current_dir().unwrap();
        let config_directory = base_path.join("config");
        let config_file = format!("{environment}.yaml");
        config::Config::builder()
            .add_source(config::File::from(config_directory.join(config_file)))
            .add_source(config::Environment::default().separator("__"))
            .build()?
            .try_deserialize::<Self>()
    }
}

fn current_environment() -> String {
    let env = std::env::var("ENVIRONMENT")
        .expect("ENVIRONMENT variable must be set")
        .to_lowercase();
    if ["local", "production"].contains(&env.as_str()) {
        env
    } else {
        panic!(
            "`{env}` is not a valid ENVIRONMENT. \
             Use either `local` or `production`"
        )
    }
}
