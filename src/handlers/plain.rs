use crate::cf::extract_client_context;
use crate::config::ProxyMode;
use crate::error::AppError;
use crate::formatters::plain::text_builder as plain_text_builder;
use crate::handlers::AppState;
use crate::headers::cloudflare::extract_cloudflare_headers;
use crate::headers::connection::extract_connection_headers;
use crate::utils::dnt::format_dnt;

use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use std::fmt::Write;
use std::time::Instant;

pub async fn plain_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let start = Instant::now();

    let ctx = extract_client_context(&headers, &state.config.proxy_mode)
        .map_err(|e| AppError::Cf(e.to_string()))?;

    let asn_info = state.asn_db.lookup(ctx.ip);

    // Extract connection headers based on proxy mode
    let (x_tls_version, x_tls_cipher, x_http_protocol) =
        extract_connection_headers(&headers, &state.config.proxy_mode);
    let is_cloudflare_mode = state.config.proxy_mode == ProxyMode::Cloudflare;

    // Suppress unused variable warning
    let _ = x_tls_cipher;

    // Extract Cloudflare headers (reuse references to reduce cloning)
    let cloudflare_headers = extract_cloudflare_headers(&headers);

    // Use references instead of cloning - only clone when needed for display
    let geo_ref = cloudflare_headers.geo.as_ref();
    let network_ref = cloudflare_headers.network.as_ref();
    let connection_ref = cloudflare_headers.connection.as_ref();
    let security_ref = cloudflare_headers.security.as_ref();
    let proxy_ref = cloudflare_headers.proxy.as_ref();

    let mut out = String::new();

    // Use formatter helpers for plain text output
    plain_text_builder::write_ip_info(&mut out, &ctx.ip.to_string(), ctx.ip_version);

    if let Some(a) = asn_info.as_ref() {
        // Use org_rir if available, otherwise fall back to a.rir
        let rir_display = a
            .org
            .as_ref()
            .and_then(|o| o.rir.as_ref())
            .map(|s| s.as_str())
            .unwrap_or_else(|| a.rir.as_str());

        plain_text_builder::write_asn_info(
            &mut out,
            a.asn,
            &a.as_name,
            &a.prefix,
            rir_display,
            a.country.as_deref(),
        );

        plain_text_builder::write_org_info(
            &mut out,
            a.org.as_ref().and_then(|o| o.org_name.as_deref()),
            a.org.as_ref().and_then(|o| o.org_id.as_deref()),
            a.org.as_ref().and_then(|o| o.org_type.as_deref()),
            a.org.as_ref().and_then(|o| o.abuse_contact.as_deref()),
            a.org.as_ref().and_then(|o| o.last_updated.as_deref()),
        );
    }

    // Connection details - use mode-aware headers
    let tls_version = x_tls_version
        .as_deref()
        .filter(|v| !v.is_empty())
        .or(ctx.tls_version.as_deref());
    let http_protocol = x_http_protocol
        .as_deref()
        .filter(|v| !v.is_empty())
        .or(ctx.http_protocol.as_deref());

    plain_text_builder::write_tls_info(&mut out, tls_version, http_protocol);

    // CF-Ray and Datacenter only shown in Cloudflare mode
    if is_cloudflare_mode {
        if let Some(ray) = ctx.cf_ray.as_ref() {
            writeln!(&mut out, "CF-Ray: {}", ray).ok();
        }

        if let Some(dc) = ctx.cf_datacenter.as_ref() {
            writeln!(&mut out, "Datacenter: {}", dc).ok();
        }
    }

    if let Some(req_id) = connection_ref.and_then(|c| c.cf_request_id.as_ref()) {
        writeln!(&mut out, "CF-Request-ID: {}", req_id).ok();
    }

    if let Some(cache) = connection_ref.and_then(|c| c.cf_cache_status.as_ref()) {
        writeln!(&mut out, "CF-Cache-Status: {}", cache).ok();
    }

    // Cloudflare Headers - only show in cloudflare mode
    if is_cloudflare_mode {
        // Geo Location
        if geo_ref.and_then(|g| g.country.as_ref()).is_some()
            || geo_ref.and_then(|g| g.city.as_ref()).is_some()
        {
            writeln!(&mut out, "\n=== Cloudflare Client Info ===").ok();
            writeln!(&mut out, "--- Geo Location ---").ok();
            if let Some(c) = geo_ref.and_then(|g| g.country.as_ref()) {
                writeln!(&mut out, "Country: {}", c).ok();
            }
            if let Some(c) = geo_ref.and_then(|g| g.city.as_ref()) {
                writeln!(&mut out, "City: {}", c).ok();
            }
            if let Some(c) = geo_ref.and_then(|g| g.region.as_ref()) {
                writeln!(&mut out, "Region: {}", c).ok();
            }
            if let Some(c) = geo_ref.and_then(|g| g.region_code.as_ref()) {
                writeln!(&mut out, "Region-Code: {}", c).ok();
            }
            if let Some(c) = geo_ref.and_then(|g| g.continent.as_ref()) {
                writeln!(&mut out, "Continent: {}", c).ok();
            }
            if let Some(c) = geo_ref.and_then(|g| g.latitude.as_ref()) {
                writeln!(&mut out, "Latitude: {}", c).ok();
            }
            if let Some(c) = geo_ref.and_then(|g| g.longitude.as_ref()) {
                writeln!(&mut out, "Longitude: {}", c).ok();
            }
            if let Some(c) = geo_ref.and_then(|g| g.postal_code.as_ref()) {
                writeln!(&mut out, "Postal-Code: {}", c).ok();
            }
            if let Some(c) = geo_ref.and_then(|g| g.timezone.as_ref()) {
                writeln!(&mut out, "Timezone: {}", c).ok();
            }
        }

        // Network
        if network_ref.and_then(|n| n.asn.as_ref()).is_some()
            || network_ref
                .and_then(|n| n.as_organization.as_ref())
                .is_some()
            || network_ref.and_then(|n| n.colo.as_ref()).is_some()
        {
            writeln!(&mut out, "--- Network ---").ok();
            if let Some(a) = network_ref.and_then(|n| n.asn.as_ref()) {
                writeln!(&mut out, "ASN: {}", a).ok();
            }
            if let Some(a) = network_ref.and_then(|n| n.as_organization.as_ref()) {
                writeln!(&mut out, "AS-Organization: {}", a).ok();
            }
            if let Some(c) = network_ref.and_then(|n| n.colo.as_ref()) {
                writeln!(&mut out, "Colo: {}", c).ok();
            }
        }
    }

    // Connection (only in Cloudflare mode)
    if is_cloudflare_mode
        && (connection_ref.and_then(|c| c.cf_visitor.as_ref()).is_some()
            || connection_ref
                .and_then(|c| c.x_forwarded_proto.as_ref())
                .is_some()
            || connection_ref
                .and_then(|c| c.http_protocol.as_ref())
                .is_some())
    {
        writeln!(&mut out, "--- Connection ---").ok();
        if let Some(v) = connection_ref.and_then(|c| c.cf_visitor.as_ref()) {
            writeln!(&mut out, "CF-Visitor: {}", v).ok();
        }
        if let Some(p) = connection_ref.and_then(|c| c.x_forwarded_proto.as_ref()) {
            writeln!(&mut out, "X-Forwarded-Proto: {}", p).ok();
        }
        if let Some(p) = connection_ref.and_then(|c| c.http_protocol.as_ref()) {
            writeln!(&mut out, "HTTP-Protocol: {}", p).ok();
        }
        if let Some(t) = x_tls_version.as_ref() {
            writeln!(&mut out, "TLS-Version: {}", t).ok();
        }
        if let Some(c) = x_tls_cipher.as_ref() {
            writeln!(&mut out, "TLS-Cipher: {}", c).ok();
        }
    }

    // Security (only in Cloudflare mode)
    if is_cloudflare_mode
        && (security_ref.and_then(|s| s.trust_score.as_ref()).is_some()
            || security_ref.and_then(|s| s.bot_score.as_ref()).is_some()
            || security_ref.and_then(|s| s.verified_bot.as_ref()).is_some())
    {
        writeln!(&mut out, "--- Security ---").ok();
        if let Some(s) = security_ref.and_then(|s| s.trust_score.as_ref()) {
            writeln!(&mut out, "Trust-Score: {}", s).ok();
        }
        if let Some(s) = security_ref.and_then(|s| s.bot_score.as_ref()) {
            writeln!(&mut out, "Bot-Score: {}", s).ok();
        }
        if let Some(s) = security_ref.and_then(|s| s.verified_bot.as_ref()) {
            writeln!(&mut out, "Verified-Bot: {}", s).ok();
        }
    }

    // Proxy Headers
    if proxy_ref.and_then(|p| p.x_forwarded_for.as_ref()).is_some()
        || proxy_ref.and_then(|p| p.x_real_ip.as_ref()).is_some()
    {
        writeln!(&mut out, "--- Proxy Headers ---").ok();
        if let Some(f) = proxy_ref.and_then(|p| p.x_forwarded_for.as_ref()) {
            writeln!(&mut out, "X-Forwarded-For: {}", f).ok();
        }
        if let Some(r) = proxy_ref.and_then(|p| p.x_real_ip.as_ref()) {
            writeln!(&mut out, "X-Real-IP: {}", r).ok();
        }
    }

    // Client information
    if let Some(ua) = headers.get("User-Agent").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "\nUser-Agent: {}", ua).ok();
    }
    if let Some(lang) = headers.get("Accept-Language").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Accept-Language: {}", lang).ok();
    }
    if let Some(enc) = headers.get("Accept-Encoding").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Accept-Encoding: {}", enc).ok();
    }
    if let Some(referer) = headers.get("Referer").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Referer: {}", referer).ok();
    }
    if let Some(origin) = headers.get("Origin").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Origin: {}", origin).ok();
    }

    // Privacy headers
    if let Some(dnt) = format_dnt(
        headers
            .get("DNT")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
    ) {
        writeln!(&mut out, "DNT: {}", dnt).ok();
    }
    if let Some(gpc) = format_dnt(
        headers
            .get("Sec-GPC")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
    ) {
        writeln!(&mut out, "Sec-GPC: {}", gpc).ok();
    }
    if let Some(save_data) = headers.get("Save-Data").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Save-Data: {}", save_data).ok();
    }
    if let Some(uir) = headers
        .get("Upgrade-Insecure-Requests")
        .and_then(|v| v.to_str().ok())
    {
        writeln!(&mut out, "Upgrade-Insecure-Requests: {}", uir).ok();
    }

    // Client Hints
    if let Some(sec_ch_ua) = headers.get("Sec-CH-UA").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Sec-CH-UA: {}", sec_ch_ua).ok();
    }
    if let Some(v) = headers
        .get("Sec-CH-UA-Platform")
        .and_then(|v| v.to_str().ok())
    {
        writeln!(&mut out, "Sec-CH-UA-Platform: {}", v).ok();
    }
    if let Some(v) = headers
        .get("Sec-CH-UA-Mobile")
        .and_then(|v| v.to_str().ok())
    {
        writeln!(&mut out, "Sec-CH-UA-Mobile: {}", v).ok();
    }
    if let Some(v) = headers
        .get("Sec-CH-UA-Full-Version-List")
        .and_then(|v| v.to_str().ok())
    {
        writeln!(&mut out, "Sec-CH-UA-Full-Version-List: {}", v).ok();
    }
    if let Some(v) = headers.get("Device-Memory").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Device-Memory: {}", v).ok();
    }
    if let Some(v) = headers.get("Viewport-Width").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Viewport-Width: {}", v).ok();
    }
    if let Some(v) = headers.get("Downlink").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Downlink: {}", v).ok();
    }
    if let Some(v) = headers.get("RTT").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "RTT: {}", v).ok();
    }
    if let Some(v) = headers.get("ECT").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "ECT: {}", v).ok();
    }

    // Sec-Fetch headers
    if let Some(v) = headers.get("Sec-Fetch-Site").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Sec-Fetch-Site: {}", v).ok();
    }
    if let Some(v) = headers.get("Sec-Fetch-Mode").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Sec-Fetch-Mode: {}", v).ok();
    }
    if let Some(v) = headers.get("Sec-Fetch-Dest").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Sec-Fetch-Dest: {}", v).ok();
    }
    if let Some(v) = headers.get("Sec-Fetch-User").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Sec-Fetch-User: {}", v).ok();
    }

    // Server information
    let response_time_ms = start.elapsed().as_secs_f64() * 1000.0;
    plain_text_builder::write_response_time(&mut out, response_time_ms);

    Ok(Response::builder()
        .header("Content-Type", "text/plain; charset=utf-8")
        .header(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, max-age=0",
        )
        .header("Pragma", "no-cache")
        .header("Expires", "0")
        .body(out)
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
    async fn test_plain_handler_basic() {
        let state = create_test_state(ProxyMode::Cloudflare);
        let headers = create_header_map(&[
            ("CF-Connecting-IP", "8.8.8.8"),
            ("User-Agent", "Test Agent"),
        ]);

        let result = plain_handler(State(state), headers).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        let response = response.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        // Check content type
        let content_type = response.headers().get("content-type");
        assert_eq!(
            content_type.and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );

        // Check cache headers
        assert!(response.headers().get("cache-control").is_some());
    }

    #[tokio::test]
    async fn test_plain_handler_with_asn_data() {
        let state = create_test_state(ProxyMode::Cloudflare);
        let headers = create_header_map(&[("CF-Connecting-IP", "8.8.8.8"), ("CF-IPCountry", "US")]);

        let result = plain_handler(State(state), headers).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        let response = response.into_response();
        let (_parts, body) = response.into_parts();
        let body_str = String::from_utf8(
            axum::body::to_bytes(body, usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        // Verify IP info is present
        assert!(body_str.contains("8.8.8.8"));
        assert!(body_str.contains("IPv4"));

        // Verify ASN info is present
        assert!(body_str.contains("15169"));
        assert!(body_str.contains("Google LLC"));

        // Verify response time is present (check for "ms" or response time format)
        assert!(body_str.contains("ms") || body_str.contains("Response"));
    }

    #[tokio::test]
    async fn test_plain_handler_nginx_mode() {
        let state = create_test_state(ProxyMode::Nginx);
        let headers = create_header_map(&[
            ("X-Real-IP", "8.8.8.8"),
            ("X-TLS-Version", "TLSv1.3"),
            ("X-HTTP-Protocol", "HTTP/2"),
        ]);

        let result = plain_handler(State(state), headers).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        let response = response.into_response();
        let (_parts, body) = response.into_parts();
        let body_str = String::from_utf8(
            axum::body::to_bytes(body, usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        // Verify TLS info uses nginx headers
        assert!(body_str.contains("TLSv1.3"));
        assert!(body_str.contains("HTTP/2"));

        // CF-Ray should not be present in nginx mode
        assert!(!body_str.contains("CF-Ray"));
    }

    #[tokio::test]
    async fn test_plain_handler_invalid_ip() {
        let state = create_test_state(ProxyMode::Cloudflare);
        let headers = create_header_map(&[("CF-Connecting-IP", "invalid-ip")]);

        let result = plain_handler(State(state), headers).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_plain_handler_with_client_hints() {
        let state = create_test_state(ProxyMode::Cloudflare);
        let headers = create_header_map(&[
            ("CF-Connecting-IP", "8.8.8.8"),
            ("Sec-CH-UA", "\"Chromium\";v=\"110\""),
            ("Sec-CH-UA-Platform", "\"Linux\""),
            ("DNT", "1"),
        ]);

        let result = plain_handler(State(state), headers).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        let response = response.into_response();
        let (_parts, body) = response.into_parts();
        let body_str = String::from_utf8(
            axum::body::to_bytes(body, usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        // Verify client hints are present
        assert!(body_str.contains("Sec-CH-UA"));
        assert!(body_str.contains("DNT"));
        assert!(body_str.contains("Enabled"));
    }
}
