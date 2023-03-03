use axum::http::StatusCode;

pub async fn handler() -> StatusCode {
    StatusCode::OK
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request, http::StatusCode};

    use crate::{test_helpers::TestServer, Pool};

    #[sqlx::test]
    async fn returns_ok(pool: Pool) {
        let req = Request::builder()
            .method("GET")
            .uri("/health_check")
            .body(Body::empty())
            .unwrap();
        let res = TestServer::new(pool).await.call(req).await;
        assert_eq!(res.status(), StatusCode::OK);
    }
}
