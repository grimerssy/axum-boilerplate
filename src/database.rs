use anyhow::Context;
use sqlx::{Postgres, Transaction};

pub type Database = Postgres;

pub type Pool = sqlx::Pool<Database>;

pub trait Executor<'c>: sqlx::Executor<'c, Database = Database> {}
impl<'c, T> Executor<'c> for T where T: sqlx::Executor<'c, Database = Database> {}

pub async fn begin_transaction(
    pool: &Pool,
) -> anyhow::Result<Transaction<'_, Database>> {
    pool.begin().await.context("Failed to begin transaction")
}

pub async fn commit(
    transaction: Transaction<'_, Database>,
) -> anyhow::Result<()> {
    transaction
        .commit()
        .await
        .context("Failed to commit transaction")
}
