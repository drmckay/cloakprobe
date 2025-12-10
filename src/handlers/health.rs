use axum::response::Json;

pub async fn health_handler() -> impl axum::response::IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn test_health_handler() {
        let response = health_handler().await;
        let response = response.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Check content type
        let content_type = response.headers().get("content-type");
        assert!(content_type.is_some());

        // Extract body and verify JSON
        let (_, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["status"], "ok");
    }
}
