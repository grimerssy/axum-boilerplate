use secrecy::{ExposeSecret, Secret};
use tower_cookies::{cookie::time::Duration, Cookie, Cookies, Key};

const ACCESS_TOKEN_KEY: &str = "access_token";
const REFRESH_TOKEN_KEY: &str = "refresh_token";

#[derive(Clone)]
pub struct CookieService {
    key: Key,
    access_token_ttl: Duration,
    refresh_token_ttl: Duration,
}

impl CookieService {
    pub fn new(
        secret: &[u8],
        access_token_ttl: std::time::Duration,
        refresh_token_ttl: std::time::Duration,
    ) -> anyhow::Result<Self> {
        let access_token_ttl =
            Duration::new(access_token_ttl.as_secs().try_into()?, 0);
        let refresh_token_ttl =
            Duration::new(refresh_token_ttl.as_secs().try_into()?, 0);
        let key = Key::from(secret);
        Ok(Self {
            key,
            access_token_ttl,
            refresh_token_ttl,
        })
    }

    pub fn set_access_token(&self, cookies: &Cookies, token: Secret<String>) {
        cookies.private(&self.key).add(
            Cookie::build(ACCESS_TOKEN_KEY, token.expose_secret().to_owned())
                .max_age(self.access_token_ttl)
                .http_only(true)
                .secure(true)
                .finish(),
        );
    }

    pub fn set_refresh_token(&self, cookies: &Cookies, token: Secret<String>) {
        cookies.private(&self.key).add(
            Cookie::build(REFRESH_TOKEN_KEY, token.expose_secret().to_owned())
                .path("/auth/refresh")
                .max_age(self.refresh_token_ttl)
                .http_only(true)
                .secure(true)
                .finish(),
        );
    }

    pub fn get_access_token(
        &self,
        cookies: &Cookies,
    ) -> Option<Secret<String>> {
        cookies
            .private(&self.key)
            .get(ACCESS_TOKEN_KEY)
            .map(|c| c.value().into())
            .map(Secret::new)
    }

    pub fn get_refresh_token(
        &self,
        cookies: &Cookies,
    ) -> Option<Secret<String>> {
        cookies
            .private(&self.key)
            .get(REFRESH_TOKEN_KEY)
            .map(|c| c.value().into())
            .map(Secret::new)
    }
}
