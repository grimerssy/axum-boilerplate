use serde::Deserialize;

use crate::services::hash::PasswordHasher;

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Config {
    pub fn hasher(self, secret: &[u8]) -> anyhow::Result<PasswordHasher> {
        PasswordHasher::new(secret, self.m_cost, self.t_cost, self.p_cost)
    }
}
