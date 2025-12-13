use crate::cf::extract_client_context;
use crate::config::ProxyMode;
use crate::formatters::html::context_builder;
use crate::handlers::AppState;
use crate::headers::client::extract_client_info;
use crate::headers::cloudflare::extract_cloudflare_headers;
use crate::headers::connection::extract_connection_headers;
use crate::headers::nginx::extract_nginx_headers;
use crate::model::*;
use crate::utils::ip::{get_ip_details, IpDetails};

use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use std::time::Instant;
use tera::Context;

pub async fn html_handler(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let start = Instant::now();

    let ctx = extract_client_context(&headers, &state.config.proxy_mode).ok();
    let ip_display = ctx
        .as_ref()
        .map(|c| c.ip.to_string())
        .unwrap_or_else(|| "unknown".into());
    let ip_version = ctx.as_ref().map(|c| c.ip_version).unwrap_or(0);

    let ip_details = ctx
        .as_ref()
        .map(|c| get_ip_details(&c.ip))
        .unwrap_or_else(|| IpDetails {
            primary: "—".into(),
            hex: "—".into(),
            expanded: "—".into(),
            binary: "—".into(),
            numeric: "—".into(),
            ip_type: "—".into(),
        });

    let asn_info = ctx.as_ref().and_then(|c| state.asn_db.lookup(c.ip));

    let network = NetworkInfo::from_asn(asn_info);

    // Extract connection headers based on proxy mode (early extraction)
    let (x_tls_version_early, x_tls_cipher_early, x_http_protocol_early) =
        extract_connection_headers(&headers, &state.config.proxy_mode);
    let is_cloudflare_mode_early = state.config.proxy_mode == ProxyMode::Cloudflare;

    // Extract nginx-specific headers when in nginx mode
    let nginx_headers = if !is_cloudflare_mode_early {
        Some(extract_nginx_headers(&headers))
    } else {
        None
    };

    let connection = ctx.as_ref().map(|c| ConnectionInfo {
        tls_version: x_tls_version_early
            .clone()
            .filter(|v| !v.is_empty())
            .or(c.tls_version.clone()),
        http_protocol: x_http_protocol_early
            .clone()
            .filter(|v| !v.is_empty())
            .or(c.http_protocol.clone()),
        tls_cipher: x_tls_cipher_early.clone(),
        cf_ray: if is_cloudflare_mode_early {
            c.cf_ray.clone()
        } else {
            None
        },
        datacenter: if is_cloudflare_mode_early {
            c.cf_datacenter.clone()
        } else {
            None
        },
        request_id: nginx_headers.as_ref().and_then(|h| h.request_id.clone()),
        remote_port: nginx_headers.as_ref().and_then(|h| h.remote_port.clone()),
        connection_id: nginx_headers.as_ref().and_then(|h| h.connection_id.clone()),
    });

    let client = extract_client_info(&headers);
    let privacy = PrivacyInfo::from(&state.config.privacy_mode);
    let response_time_ms = start.elapsed().as_secs_f64() * 1000.0;
    let server = ServerInfo {
        timestamp_utc: Utc::now().to_rfc3339(),
        region: std::env::var("CLOAKPROBE_REGION")
            .or_else(|_| std::env::var("CFDEBUG_REGION"))
            .ok(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        response_time_ms: Some(response_time_ms),
    };

    // Extract connection headers based on proxy mode
    let (x_tls_version, x_tls_cipher, x_http_protocol) =
        extract_connection_headers(&headers, &state.config.proxy_mode);

    // Check if we're in cloudflare mode for conditional display
    let is_cloudflare_mode = state.config.proxy_mode == ProxyMode::Cloudflare;

    // Extract Cloudflare headers (reuse references to reduce cloning)
    let cloudflare_headers = extract_cloudflare_headers(&headers);

    // Use references instead of cloning - only clone when needed for formatter functions
    let geo_ref = cloudflare_headers.geo.as_ref();
    let network_ref = cloudflare_headers.network.as_ref();
    let connection_ref = cloudflare_headers.connection.as_ref();
    let security_ref = cloudflare_headers.security.as_ref();
    let proxy_ref = cloudflare_headers.proxy.as_ref();

    // Use shared Tera template engine
    let tera = state.tera.clone();

    // Build template context with sanitized header values
    // Pre-size context to reduce reallocations (estimate ~80 entries)
    let mut context = Context::new();

    // Use formatter helpers to build context sections
    context_builder::add_ip_info(&mut context, &ip_display, ip_version, &ip_details);
    context_builder::add_network_info(&mut context, &network);
    context_builder::add_connection_info(
        &mut context,
        connection.as_ref().unwrap_or(&ConnectionInfo {
            tls_version: None,
            http_protocol: None,
            tls_cipher: None,
            cf_ray: None,
            datacenter: None,
            request_id: None,
            remote_port: None,
            connection_id: None,
        }),
        is_cloudflare_mode,
        x_tls_version.as_deref(),
        x_http_protocol.as_deref(),
        x_tls_cipher.as_ref(),
        connection_ref.and_then(|c| c.cf_request_id.as_ref()),
        connection_ref.and_then(|c| c.cf_cache_status.as_ref()),
    );
    context_builder::add_nginx_geoip_info(&mut context, nginx_headers.as_ref());

    // Build Cloudflare Headers sections using formatter helpers (use references to reduce cloning)
    let geo_location_items = context_builder::build_geo_location_items(
        geo_ref.and_then(|g| g.country.as_ref()),
        geo_ref.and_then(|g| g.city.as_ref()),
        geo_ref.and_then(|g| g.region.as_ref()),
        geo_ref.and_then(|g| g.region_code.as_ref()),
        geo_ref.and_then(|g| g.continent.as_ref()),
        geo_ref.and_then(|g| g.latitude.as_ref()),
        geo_ref.and_then(|g| g.longitude.as_ref()),
        geo_ref.and_then(|g| g.postal_code.as_ref()),
        geo_ref.and_then(|g| g.timezone.as_ref()),
    );
    context.insert("geo_location_items", &geo_location_items);

    let network_items = context_builder::build_network_items(
        network_ref.and_then(|n| n.asn.as_ref()),
        network_ref.and_then(|n| n.as_organization.as_ref()),
        network_ref.and_then(|n| n.colo.as_ref()),
    );
    context.insert("network_items", &network_items);

    let connection_items = context_builder::build_connection_items(
        connection_ref.and_then(|c| c.cf_visitor.as_ref()),
        connection_ref.and_then(|c| c.x_forwarded_proto.as_ref()),
        connection_ref.and_then(|c| c.http_protocol.as_ref()),
        x_tls_version.as_ref(),
        x_tls_cipher.as_ref(),
    );
    context.insert("connection_items", &connection_items);

    let security_items = context_builder::build_security_items(
        security_ref.and_then(|s| s.trust_score.as_ref()),
        security_ref.and_then(|s| s.bot_score.as_ref()),
        security_ref.and_then(|s| s.verified_bot.as_ref()),
    );
    context.insert("security_items", &security_items);

    let proxy_items = context_builder::build_proxy_items(
        proxy_ref.and_then(|p| p.x_forwarded_for.as_ref()),
        proxy_ref.and_then(|p| p.x_real_ip.as_ref()),
    );
    context.insert("proxy_items", &proxy_items);

    // Use formatter helpers for client and server info
    context_builder::add_client_info(&mut context, &client);
    context_builder::add_server_info(&mut context, &server, &privacy);

    // Render template
    let html = match tera.render("index.html.tera", &context) {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Failed to render template: {}", e);
            return Response::builder()
                .status(500)
                .header("Content-Type", "text/plain")
                .body(String::from("Internal server error"))
                .unwrap();
        }
    };

    Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .header(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, max-age=0",
        )
        .header("Pragma", "no-cache")
        .header("Expires", "0")
        .body(html)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn::{AsnDatabase, AsnInfo, OrgDetails};
    use crate::config::{AppConfig, PrivacyMode};
    use axum::http::HeaderValue;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use tera::Tera;

    // Mock ASN database for testing
    struct MockAsnDatabase {
        data: HashMap<IpAddr, AsnInfo>,
    }

    impl AsnDatabase for MockAsnDatabase {
        fn lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
            self.data.get(&ip).cloned()
        }
    }

    fn create_test_state(proxy_mode: ProxyMode) -> AppState {
        let mut mock_db = HashMap::new();

        // Add test ASN data
        let test_ip: IpAddr = "8.8.8.8".parse().unwrap();
        mock_db.insert(
            test_ip,
            AsnInfo {
                asn: 15169,
                as_name: "Google LLC".to_string(),
                prefix: "8.8.8.0/24".to_string(),
                rir: "ARIN".to_string(),
                country: Some("US".to_string()),
                org: Some(OrgDetails {
                    org_id: Some("GOGL".to_string()),
                    org_name: Some("Google LLC".to_string()),
                    country: Some("US".to_string()),
                    rir: Some("ARIN".to_string()),
                    org_type: Some("Content".to_string()),
                    abuse_contact: Some("abuse@google.com".to_string()),
                    last_updated: Some("2024-01-01".to_string()),
                }),
            },
        );

        let config = AppConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 8080,
            proxy_mode,
            region: None,
            privacy_mode: PrivacyMode::Strict,
            asn_db_path: "test.asn".to_string(),
            org_db_path: None,
        };

        let tera = Tera::new("templates/**/*").unwrap_or_else(|_| Tera::default());

        AppState {
            config,
            asn_db: Arc::new(MockAsnDatabase { data: mock_db }),
            tera: Arc::new(tera),
        }
    }

    fn create_header_map(headers: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (key, value) in headers {
            if let (Ok(key), Ok(val)) = (
                axum::http::HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                map.insert(key, val);
            }
        }
        map
    }

    #[tokio::test]
    async fn test_html_handler_basic() {
        let state = create_test_state(ProxyMode::Cloudflare);
        let headers = create_header_map(&[
            ("CF-Connecting-IP", "8.8.8.8"),
            ("User-Agent", "Test Agent"),
        ]);

        let response = html_handler(State(state), headers).await;
        let response = response.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Check content type
        let content_type = response.headers().get("content-type");
        assert_eq!(
            content_type.and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );

        // Check cache headers
        assert!(response.headers().get("cache-control").is_some());
        assert!(response.headers().get("pragma").is_some());
        assert!(response.headers().get("expires").is_some());
    }

    #[tokio::test]
    async fn test_html_handler_with_asn_data() {
        let state = create_test_state(ProxyMode::Cloudflare);
        let headers = create_header_map(&[("CF-Connecting-IP", "8.8.8.8"), ("CF-IPCountry", "US")]);

        let response = html_handler(State(state), headers).await;
        let response = response.into_response();
        let (_parts, body) = response.into_parts();
        let body_str = String::from_utf8(
            axum::body::to_bytes(body, usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        // Verify HTML contains IP
        assert!(body_str.contains("8.8.8.8"));

        // Note: Full HTML content verification would require template files
        // For now, just verify response is successful
    }

    #[tokio::test]
    async fn test_html_handler_nginx_mode() {
        let state = create_test_state(ProxyMode::Nginx);
        let headers = create_header_map(&[
            ("X-Real-IP", "8.8.8.8"),
            ("X-TLS-Version", "TLSv1.3"),
            ("X-HTTP-Protocol", "HTTP/2"),
        ]);

        let response = html_handler(State(state), headers).await;
        let response = response.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Verify response is successful
        // Full content verification would require template files
    }

    #[tokio::test]
    async fn test_html_handler_missing_ip() {
        let state = create_test_state(ProxyMode::Cloudflare);
        let headers = create_header_map(&[("User-Agent", "Test Agent")]);

        // Should handle missing IP gracefully
        let response = html_handler(State(state), headers).await;
        let response = response.into_response();
        // Should still return 200 OK even without IP
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
}
