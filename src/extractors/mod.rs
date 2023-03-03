mod user;
pub mod validated;

pub use user::User;

use axum::{
    extract::rejection::{FormRejection, JsonRejection},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use validator::ValidationErrors;

use crate::error::ErrorResponse;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Form(#[from] FormRejection),
    #[error(transparent)]
    Json(#[from] JsonRejection),
    #[error(transparent)]
    Validation(#[from] ValidationErrors),
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        if let Self::Validation(errors) = self {
            #[derive(Serialize)]
            struct __ErrorResponse {
                errors: ValidationErrors,
            }
            let error = __ErrorResponse { errors };
            (StatusCode::UNPROCESSABLE_ENTITY, Json(error)).into_response()
        } else {
            ErrorResponse::new(StatusCode::BAD_REQUEST, self.to_string())
                .into_response()
        }
    }
}
