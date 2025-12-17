use crate::cf::extract_client_context;
use crate::config::ProxyMode;
use crate::error::AppError;
use crate::formatters::json::format_json_response;
use crate::handlers::AppState;
use crate::headers::client::extract_client_info;
use crate::headers::cloudflare::extract_cloudflare_headers;
use crate::headers::connection::extract_connection_headers;
use crate::headers::nginx::extract_nginx_headers;
use crate::model::*;
use crate::utils::sanitize::sanitize_for_json;

use axum::{extract::State, http::HeaderMap, response::Response};
use chrono::Utc;
use std::time::Instant;

pub async fn info_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response<String>, AppError> {
    let start = Instant::now();

    let ctx = extract_client_context(&headers, &state.config.proxy_mode)
        .map_err(|e| AppError::Cf(e.to_string()))?;

    let asn_info = state.asn_db.lookup(ctx.ip);

    let network = NetworkInfo::from_asn(asn_info);

    // Extract connection headers based on proxy mode
    let (x_tls_version, x_tls_cipher, x_http_protocol) =
        extract_connection_headers(&headers, &state.config.proxy_mode);

    // Build connection info - include mode-specific fields
    let is_cloudflare_mode = state.config.proxy_mode == ProxyMode::Cloudflare;

    // Extract nginx-specific headers when in nginx mode
    let nginx_headers = if !is_cloudflare_mode {
        Some(extract_nginx_headers(&headers))
    } else {
        None
    };

    let connection = ConnectionInfo {
        tls_version: sanitize_for_json(
            x_tls_version
                .as_deref()
                .filter(|v| !v.is_empty())
                .or(ctx.tls_version.as_deref()),
        ),
        http_protocol: sanitize_for_json(
            x_http_protocol
                .as_deref()
                .filter(|v| !v.is_empty())
                .or(ctx.http_protocol.as_deref()),
        ),
        tls_cipher: sanitize_for_json(x_tls_cipher.as_deref()),
        cf_ray: if is_cloudflare_mode {
            sanitize_for_json(ctx.cf_ray.as_deref())
        } else {
            None
        },
        datacenter: if is_cloudflare_mode {
            sanitize_for_json(ctx.cf_datacenter.as_deref())
        } else {
            None
        },
        request_id: nginx_headers
            .as_ref()
            .and_then(|h| sanitize_for_json(h.request_id.as_deref())),
        remote_port: nginx_headers
            .as_ref()
            .and_then(|h| sanitize_for_json(h.remote_port.as_deref())),
        connection_id: nginx_headers
            .as_ref()
            .and_then(|h| sanitize_for_json(h.connection_id.as_deref())),
    };

    // Extract and sanitize client info
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

    // Extract Cloudflare headers
    let cloudflare_headers = extract_cloudflare_headers(&headers);

    // Extract proxy headers for nginx mode (clone before moving cloudflare_headers)
    let proxy = cloudflare_headers.proxy.clone();

    let cloudflare = if is_cloudflare_mode {
        // Only include if at least one section has data
        if cloudflare_headers.geo.is_some()
            || cloudflare_headers.network.is_some()
            || cloudflare_headers.connection.is_some()
            || cloudflare_headers.security.is_some()
            || cloudflare_headers.proxy.is_some()
        {
            Some(cloudflare_headers)
        } else {
            None
        }
    } else {
        None
    };

    let nginx = if !is_cloudflare_mode {
        nginx_headers.map(|h| NginxHeaders {
            geo: if h.geoip_country.is_some()
                || h.geoip_city.is_some()
                || h.geoip_region.is_some()
                || h.geoip_latitude.is_some()
                || h.geoip_longitude.is_some()
                || h.geoip_postal_code.is_some()
                || h.geoip_org.is_some()
            {
                Some(NginxGeoHeaders {
                    country: sanitize_for_json(h.geoip_country.as_deref()),
                    city: sanitize_for_json(h.geoip_city.as_deref()),
                    region: sanitize_for_json(h.geoip_region.as_deref()),
                    latitude: sanitize_for_json(h.geoip_latitude.as_deref()),
                    longitude: sanitize_for_json(h.geoip_longitude.as_deref()),
                    postal_code: sanitize_for_json(h.geoip_postal_code.as_deref()),
                    org: sanitize_for_json(h.geoip_org.as_deref()),
                })
            } else {
                None
            },
            proxy: proxy.clone(),
        })
    } else {
        None
    };

    let resp = InfoResponse {
        ip: ctx.ip.to_string(),
        ip_version: ctx.ip_version,
        reverse_dns: None,
        network,
        connection,
        client,
        privacy,
        server,
        cloudflare,
        nginx,
    };

    let json = format_json_response(&resp).map_err(|e| AppError::Cf(e.to_string()))?;

    Ok(Response::builder()
        .header("Content-Type", "application/json")
        .header(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, max-age=0",
        )
        .header("Pragma", "no-cache")
        .header("Expires", "0")
        .body(json)
        .unwrap())
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
                    as_name: Some("GOOGLE".to_string()),
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

        let tera = Tera::new("templates/**/*").unwrap_or_else(|_| {
            // Create minimal Tera instance for testing
            Tera::default()
        });

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
    async fn test_info_handler_basic() {
        let state = create_test_state(ProxyMode::Cloudflare);
        let headers = create_header_map(&[
            ("CF-Connecting-IP", "8.8.8.8"),
            ("User-Agent", "Test Agent"),
        ]);

        let result = info_handler(State(state), headers).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Check content type
        let content_type = response.headers().get("content-type");
        assert_eq!(
            content_type.and_then(|v| v.to_str().ok()),
            Some("application/json")
        );

        // Check cache headers
        assert!(response.headers().get("cache-control").is_some());
        assert!(response.headers().get("pragma").is_some());
        assert!(response.headers().get("expires").is_some());
    }

    #[tokio::test]
    async fn test_info_handler_with_asn_data() {
        let state = create_test_state(ProxyMode::Cloudflare);
        let headers = create_header_map(&[("CF-Connecting-IP", "8.8.8.8"), ("CF-IPCountry", "US")]);

        let result = info_handler(State(state), headers).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        let (_parts, body) = response.into_parts();
        let body_str = body;

        let json: serde_json::Value = serde_json::from_str(&body_str).unwrap();

        // Verify IP
        assert_eq!(json["ip"], "8.8.8.8");
        assert_eq!(json["ip_version"], 4);

        // Verify network info
        assert_eq!(json["network"]["asn"], 15169);
        assert_eq!(json["network"]["as_name"], "Google LLC");

        // Verify server info
        assert!(json["server"]["timestamp_utc"].is_string());
        assert!(json["server"]["response_time_ms"].is_number());
    }

    #[tokio::test]
    async fn test_info_handler_nginx_mode() {
        let state = create_test_state(ProxyMode::Nginx);
        let headers = create_header_map(&[
            ("X-Real-IP", "8.8.8.8"),
            ("X-TLS-Version", "TLSv1.3"),
            ("X-HTTP-Protocol", "HTTP/2"),
        ]);

        let result = info_handler(State(state), headers).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        let (_parts, body) = response.into_parts();
        let body_str = body;

        let json: serde_json::Value = serde_json::from_str(&body_str).unwrap();

        // Verify connection info uses nginx headers
        assert_eq!(json["connection"]["tls_version"], "TLSv1.3");
        assert_eq!(json["connection"]["http_protocol"], "HTTP/2");

        // Cloudflare should be None in nginx mode
        assert!(json["cloudflare"].is_null());
    }

    #[tokio::test]
    async fn test_info_handler_invalid_ip() {
        let state = create_test_state(ProxyMode::Cloudflare);
        let headers = create_header_map(&[("CF-Connecting-IP", "invalid-ip")]);

        let result = info_handler(State(state), headers).await;
        assert!(result.is_err());
    }
}
