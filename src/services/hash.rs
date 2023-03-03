use anyhow::Context;
use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash,
    PasswordHasher as Hasher, PasswordVerifier, Version,
};
use secrecy::{CloneableSecret, ExposeSecret, Secret, Zeroize};

#[derive(Clone, Debug)]
struct HmacKey(Vec<u8>);

#[derive(Clone)]
pub struct PasswordHasher {
    hmac_secret: Secret<HmacKey>,
    params: Params,
}

impl PasswordHasher {
    pub fn new(
        secret: &[u8],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> anyhow::Result<Self> {
        let hmac_secret = Secret::new(HmacKey(secret.to_vec()));
        let params = Params::new(m_cost, t_cost, p_cost, None)
            .context("Failed to create Argon2 params")?;
        Ok(Self {
            hmac_secret,
            params,
        })
    }

    #[tracing::instrument(name = "Hash password", skip_all, err(Debug))]
    pub fn hash_password(
        &self,
        password: &Secret<String>,
    ) -> anyhow::Result<Secret<String>> {
        let salt = SaltString::generate(&mut rand::thread_rng());
        self.hasher()?
            .hash_password(password.expose_secret().as_bytes(), &salt)
            .map(|h| h.to_string())
            .map(Secret::new)
            .context("Failed to hash password")
    }

    #[tracing::instrument(name = "Verify password", skip_all, err(Debug))]
    pub fn verify_password(
        &self,
        password: &Secret<String>,
        password_hash: &Secret<String>,
    ) -> anyhow::Result<bool> {
        let password = password.expose_secret().as_bytes();
        let password_hash = PasswordHash::new(password_hash.expose_secret())
            .context("Failed to parse hash in PHC string format.")?;
        match self.hasher()?.verify_password(password, &password_hash) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn mock_password_hash(&self) -> Secret<String> {
        Secret::new(
            "$argon2id$v=19$m=4096,t=3,p=1\
                $0000000000000000000000\
                $0000000000000000000000000000000000000000000"
                .to_owned(),
        )
    }

    fn hasher(&self) -> anyhow::Result<Argon2<'_>> {
        Argon2::new_with_secret(
            &self.hmac_secret.expose_secret().0,
            Algorithm::default(),
            Version::default(),
            self.params.clone(),
        )
        .context("Failed to create an Argon2 hasher")
    }
}

impl CloneableSecret for HmacKey {}
impl Zeroize for HmacKey {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}
