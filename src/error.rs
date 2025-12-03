use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    detail: Option<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("cloudflare error: {0}")]
    Cf(String),
    #[error("internal error")]
    #[allow(dead_code)]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, msg, detail) = match self {
            AppError::Cf(d) => (
                StatusCode::BAD_REQUEST,
                "cloudflare_headers_invalid".to_string(),
                Some(d),
            ),
            AppError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error".to_string(),
                None,
            ),
        };

        let body = Json(ErrorBody { error: msg, detail });

        (status, body).into_response()
    }
}
