use std::result::Result;

use secrecy::{ExposeSecret, Secret};
use serde::{Deserialize, Serialize};
use validator::ValidationError;

#[derive(Clone, Debug, Deserialize)]
pub struct Password(Secret<String>);

impl AsRef<Secret<String>> for Password {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

impl ExposeSecret<String> for Password {
    fn expose_secret(&self) -> &String {
        self.as_ref().expose_secret()
    }
}

impl Serialize for Password {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{:?}", self.0))
    }
}

pub fn at_least_8(p: &Password) -> Result<(), ValidationError> {
    if p.expose_secret().len() < 8 {
        Err(ValidationError::new("must contain at least 8 characters"))
    } else {
        Ok(())
    }
}

pub fn at_most_32(p: &Password) -> Result<(), ValidationError> {
    if p.expose_secret().len() > 32 {
        Err(ValidationError::new("must contain at most 32 characters"))
    } else {
        Ok(())
    }
}

pub fn ascii(p: &Password) -> Result<(), ValidationError> {
    if p.expose_secret().contains(|c: char| !c.is_ascii()) {
        Err(ValidationError::new(
            "must contain only valid ASCII characters",
        ))
    } else {
        Ok(())
    }
}

pub fn lowercase(p: &Password) -> Result<(), ValidationError> {
    if p.expose_secret().contains(char::is_lowercase) {
        Ok(())
    } else {
        Err(ValidationError::new(
            "must contain at least one lowercase character",
        ))
    }
}

pub fn uppercase(p: &Password) -> Result<(), ValidationError> {
    if p.expose_secret().contains(char::is_uppercase) {
        Ok(())
    } else {
        Err(ValidationError::new(
            "must contain at least one uppercase character",
        ))
    }
}

pub fn digit(p: &Password) -> Result<(), ValidationError> {
    if p.expose_secret().contains(|c: char| c.is_ascii_digit()) {
        Ok(())
    } else {
        Err(ValidationError::new("must contain at least one digit"))
    }
}
