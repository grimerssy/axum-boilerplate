use axum::http::StatusCode;

use crate::extractors::User;

pub async fn handler(_user: User) -> StatusCode {
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request, http::StatusCode};

    use crate::{test_helpers::TestServer, Pool};

    #[sqlx::test]
    async fn fails_for_logged_out_user(pool: Pool) {
        let req = request();
        let res = TestServer::new(pool).await.call(req).await;
        assert!(res.status().is_client_error());
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    fn request() -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri("/health_check/protected")
            .body(Body::empty())
            .unwrap()
    }
}
