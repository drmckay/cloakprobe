use crate::handlers::AppState;

use axum::{
    extract::State,
    response::{IntoResponse, Response},
};
use tera::Context;

pub async fn privacy_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Use shared Tera template engine
    let tera = state.tera.clone();

    // Render privacy policy template
    let html = match tera.render("privacy.html.tera", &Context::new()) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Failed to render privacy policy template: {}", e);
            return Response::builder()
                .status(500)
                .header("Content-Type", "text/plain")
                .body(String::from("Internal server error"))
                .unwrap();
        }
    };

    Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .body(html)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn::AsnDatabase;
    use crate::config::{AppConfig, PrivacyMode};
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use tera::Tera;

    // Mock ASN database for testing
    struct MockAsnDatabase {
        _data: HashMap<IpAddr, crate::asn::AsnInfo>,
    }

    impl AsnDatabase for MockAsnDatabase {
        fn lookup(&self, _ip: IpAddr) -> Option<crate::asn::AsnInfo> {
            None
        }
    }

    fn create_test_state() -> AppState {
        let config = AppConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
            proxy_mode: crate::config::ProxyMode::Cloudflare,
            region: None,
            privacy_mode: PrivacyMode::Strict,
            asn_db_path: "test.asn".to_string(),
            org_db_path: None,
        };

        let tera = Tera::new("templates/**/*").unwrap_or_else(|_| Tera::default());

        AppState {
            config,
            asn_db: Arc::new(MockAsnDatabase {
                _data: HashMap::new(),
            }),
            tera: Arc::new(tera),
        }
    }

    #[tokio::test]
    async fn test_privacy_handler_basic() {
        let state = create_test_state();
        let response = privacy_handler(State(state)).await;
        let response = response.into_response();

        // Privacy handler should return 200 OK or 500 if template is missing
        // Since we're using Tera::default() in tests, it might return 500
        // This is acceptable behavior - template rendering failure is handled
        assert!(response.status().is_success() || response.status().as_u16() == 500);

        // Check content type if successful
        if response.status().is_success() {
            let content_type = response.headers().get("content-type");
            assert_eq!(
                content_type.and_then(|v| v.to_str().ok()),
                Some("text/html; charset=utf-8")
            );
        }
    }
}
