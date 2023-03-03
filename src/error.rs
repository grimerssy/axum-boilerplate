use std::fmt;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(thiserror::Error)]
pub enum Error {
    #[error("email is taken")]
    EmailTaken,
    #[error("missing access token")]
    NoAccessToken,
    #[error("invalid access token")]
    InvalidAccessToken,
    #[error("missing refresh token")]
    NoRefreshToken,
    #[error("invalid refresh token")]
    InvalidRefreshToken,
    #[error("invalid login or password")]
    InvalidCredentials,
    #[error("invalid password")]
    InvalidPassword,
    #[error("unknown verification token")]
    UnknownVerificationToken,
    #[error("an unexpected error occurred")]
    Unexpected(#[from] anyhow::Error),
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmailTaken
            | Self::InvalidCredentials
            | Self::InvalidPassword
            | Self::NoAccessToken
            | Self::InvalidAccessToken
            | Self::NoRefreshToken
            | Self::InvalidRefreshToken
            | Self::UnknownVerificationToken => {
                write!(f, "{self}")
            }
            Self::Unexpected(e) => e.fmt(f),
        }
    }
}

impl Error {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::EmailTaken => StatusCode::CONFLICT,
            Self::InvalidCredentials
            | Self::InvalidPassword
            | Self::NoAccessToken
            | Self::InvalidAccessToken
            | Self::NoRefreshToken
            | Self::InvalidRefreshToken => StatusCode::UNAUTHORIZED,
            Self::UnknownVerificationToken => StatusCode::NOT_FOUND,
            Self::Unexpected(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        ErrorResponse::new(self.status_code(), self.to_string()).into_response()
    }
}

#[derive(Serialize)]
pub struct ErrorResponse {
    #[serde(skip)]
    status_code: StatusCode,
    error: String,
}

impl ErrorResponse {
    pub fn new(status_code: StatusCode, error: String) -> Self {
        Self { status_code, error }
    }
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        (self.status_code, Json(self)).into_response()
    }
}
