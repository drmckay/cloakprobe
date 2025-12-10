use crate::model::*;
use crate::utils::sanitize::sanitize_for_json;
use axum::http::HeaderMap;

/// Extracts all Cloudflare-specific headers from the request
pub fn extract_cloudflare_headers(headers: &HeaderMap) -> CloudflareHeaders {
    // Extract Cloudflare Worker headers - Geo Location
    let cf_ipcountry = headers
        .get("CF-IPCountry")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_city = headers
        .get("X-CF-City")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_region = headers
        .get("X-CF-Region")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_region_code = headers
        .get("X-CF-Region-Code")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_continent = headers
        .get("X-CF-Continent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_latitude = headers
        .get("X-CF-Latitude")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_longitude = headers
        .get("X-CF-Longitude")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_postal_code = headers
        .get("X-CF-Postal-Code")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_timezone = headers
        .get("X-CF-Timezone")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract Cloudflare Worker headers - Network
    let x_cf_asn = headers
        .get("X-CF-ASN")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_as_organization = headers
        .get("X-CF-AS-Organization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_colo = headers
        .get("X-CF-Colo")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract Cloudflare Worker headers - Security
    let x_cf_trust_score = headers
        .get("X-CF-Trust-Score")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_bot_score = headers
        .get("X-CF-Bot-Score")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_verified_bot = headers
        .get("X-CF-Verified-Bot")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract Cloudflare Worker headers - Connection
    let cf_visitor = headers
        .get("CF-Visitor")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_forwarded_proto = headers
        .get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_http_protocol = headers
        .get("X-CF-HTTP-Protocol")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_tls_version = headers
        .get("X-CF-TLS-Version")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_tls_cipher = headers
        .get("X-CF-TLS-Cipher")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let cf_request_id = headers
        .get("CF-Request-ID")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let cf_cache_status = headers
        .get("CF-Cache-Status")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_forwarded_for = headers
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_real_ip = headers
        .get("X-Real-IP")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Build Cloudflare headers structure
    let mut geo = CloudflareGeoHeaders::default();
    if cf_ipcountry.is_some() || x_cf_city.is_some() {
        geo.country = sanitize_for_json(cf_ipcountry.as_deref());
        geo.city = sanitize_for_json(x_cf_city.as_deref());
        geo.region = sanitize_for_json(x_cf_region.as_deref());
        geo.region_code = sanitize_for_json(x_cf_region_code.as_deref());
        geo.continent = sanitize_for_json(x_cf_continent.as_deref());
        geo.latitude = sanitize_for_json(x_cf_latitude.as_deref());
        geo.longitude = sanitize_for_json(x_cf_longitude.as_deref());
        geo.postal_code = sanitize_for_json(x_cf_postal_code.as_deref());
        geo.timezone = sanitize_for_json(x_cf_timezone.as_deref());
    }

    let mut network_headers = CloudflareNetworkHeaders::default();
    if x_cf_asn.is_some() || x_cf_as_organization.is_some() || x_cf_colo.is_some() {
        network_headers.asn = sanitize_for_json(x_cf_asn.as_deref());
        network_headers.as_organization = sanitize_for_json(x_cf_as_organization.as_deref());
        network_headers.colo = sanitize_for_json(x_cf_colo.as_deref());
    }

    let mut connection_headers = CloudflareConnectionHeaders::default();
    if cf_visitor.is_some()
        || x_forwarded_proto.is_some()
        || x_http_protocol.is_some()
        || x_tls_version.is_some()
        || x_tls_cipher.is_some()
        || cf_request_id.is_some()
        || cf_cache_status.is_some()
    {
        connection_headers.cf_visitor = sanitize_for_json(cf_visitor.as_deref());
        connection_headers.x_forwarded_proto = sanitize_for_json(x_forwarded_proto.as_deref());
        connection_headers.http_protocol = sanitize_for_json(x_http_protocol.as_deref());
        connection_headers.tls_version = sanitize_for_json(x_tls_version.as_deref());
        connection_headers.tls_cipher = sanitize_for_json(x_tls_cipher.as_deref());
        connection_headers.cf_request_id = sanitize_for_json(cf_request_id.as_deref());
        connection_headers.cf_cache_status = sanitize_for_json(cf_cache_status.as_deref());
    }

    let mut security = CloudflareSecurityHeaders::default();
    if x_cf_trust_score.is_some() || x_cf_bot_score.is_some() || x_cf_verified_bot.is_some() {
        security.trust_score = sanitize_for_json(x_cf_trust_score.as_deref());
        security.bot_score = sanitize_for_json(x_cf_bot_score.as_deref());
        security.verified_bot = sanitize_for_json(x_cf_verified_bot.as_deref());
    }

    let mut proxy = CloudflareProxyHeaders::default();
    if x_forwarded_for.is_some() || x_real_ip.is_some() {
        proxy.x_forwarded_for = sanitize_for_json(x_forwarded_for.as_deref());
        proxy.x_real_ip = sanitize_for_json(x_real_ip.as_deref());
    }

    CloudflareHeaders {
        geo: if geo != CloudflareGeoHeaders::default() {
            Some(geo)
        } else {
            None
        },
        network: if network_headers != CloudflareNetworkHeaders::default() {
            Some(network_headers)
        } else {
            None
        },
        connection: if connection_headers != CloudflareConnectionHeaders::default() {
            Some(connection_headers)
        } else {
            None
        },
        security: if security != CloudflareSecurityHeaders::default() {
            Some(security)
        } else {
            None
        },
        proxy: if proxy != CloudflareProxyHeaders::default() {
            Some(proxy)
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

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

    #[test]
    fn test_extract_cloudflare_headers_geo() {
        let headers = create_header_map(&[
            ("CF-IPCountry", "US"),
            ("X-CF-City", "New York"),
            ("X-CF-Region", "New York"),
            ("X-CF-Latitude", "40.7128"),
            ("X-CF-Longitude", "-74.0060"),
        ]);
        let result = extract_cloudflare_headers(&headers);
        assert!(result.geo.is_some());
        let geo = result.geo.unwrap();
        assert_eq!(geo.country, Some("US".to_string()));
        assert_eq!(geo.city, Some("New York".to_string()));
        assert_eq!(geo.region, Some("New York".to_string()));
        assert_eq!(geo.latitude, Some("40.7128".to_string()));
        assert_eq!(geo.longitude, Some("-74.0060".to_string()));
    }

    #[test]
    fn test_extract_cloudflare_headers_network() {
        let headers = create_header_map(&[
            ("X-CF-ASN", "AS13335"),
            ("X-CF-AS-Organization", "Cloudflare, Inc."),
            ("X-CF-Colo", "IAD"),
        ]);
        let result = extract_cloudflare_headers(&headers);
        assert!(result.network.is_some());
        let network = result.network.unwrap();
        assert_eq!(network.asn, Some("AS13335".to_string()));
        assert_eq!(
            network.as_organization,
            Some("Cloudflare, Inc.".to_string())
        );
        assert_eq!(network.colo, Some("IAD".to_string()));
    }

    #[test]
    fn test_extract_cloudflare_headers_security() {
        let headers = create_header_map(&[
            ("X-CF-Trust-Score", "100"),
            ("X-CF-Bot-Score", "0"),
            ("X-CF-Verified-Bot", "false"),
        ]);
        let result = extract_cloudflare_headers(&headers);
        assert!(result.security.is_some());
        let security = result.security.unwrap();
        assert_eq!(security.trust_score, Some("100".to_string()));
        assert_eq!(security.bot_score, Some("0".to_string()));
        assert_eq!(security.verified_bot, Some("false".to_string()));
    }

    #[test]
    fn test_extract_cloudflare_headers_connection() {
        let headers = create_header_map(&[
            ("CF-Visitor", "{\"scheme\":\"https\"}"),
            ("X-CF-HTTP-Protocol", "HTTP/2"),
            ("X-CF-TLS-Version", "TLSv1.3"),
            ("CF-Request-ID", "req-123"),
            ("CF-Cache-Status", "HIT"),
        ]);
        let result = extract_cloudflare_headers(&headers);
        assert!(result.connection.is_some());
        let conn = result.connection.unwrap();
        assert_eq!(
            conn.cf_visitor,
            Some("{\\\"scheme\\\":\\\"https\\\"}".to_string())
        );
        assert_eq!(conn.http_protocol, Some("HTTP/2".to_string()));
        assert_eq!(conn.tls_version, Some("TLSv1.3".to_string()));
        assert_eq!(conn.cf_request_id, Some("req-123".to_string()));
        assert_eq!(conn.cf_cache_status, Some("HIT".to_string()));
    }

    #[test]
    fn test_extract_cloudflare_headers_proxy() {
        let headers = create_header_map(&[
            ("X-Forwarded-For", "192.168.1.1"),
            ("X-Real-IP", "10.0.0.1"),
        ]);
        let result = extract_cloudflare_headers(&headers);
        assert!(result.proxy.is_some());
        let proxy = result.proxy.unwrap();
        assert_eq!(proxy.x_forwarded_for, Some("192.168.1.1".to_string()));
        assert_eq!(proxy.x_real_ip, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_extract_cloudflare_headers_empty() {
        let headers = HeaderMap::new();
        let result = extract_cloudflare_headers(&headers);
        assert_eq!(result.geo, None);
        assert_eq!(result.network, None);
        assert_eq!(result.connection, None);
        assert_eq!(result.security, None);
        assert_eq!(result.proxy, None);
    }

    #[test]
    fn test_extract_cloudflare_headers_sanitization() {
        let headers =
            create_header_map(&[("CF-IPCountry", "US<script>"), ("X-CF-City", "New\"York")]);
        let result = extract_cloudflare_headers(&headers);
        assert!(result.geo.is_some());
        let geo = result.geo.unwrap();
        // Should be sanitized (no script tags, escaped quotes)
        assert!(geo.country.is_some());
        assert!(geo.city.is_some());
    }
}
