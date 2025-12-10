use axum::http::HeaderMap;

/// Nginx-specific extracted headers (internal use)
pub struct NginxExtractedHeaders {
    pub request_id: Option<String>,
    pub remote_port: Option<String>,
    pub connection_id: Option<String>,
    pub geoip_country: Option<String>,
    pub geoip_city: Option<String>,
    pub geoip_region: Option<String>,
    pub geoip_latitude: Option<String>,
    pub geoip_longitude: Option<String>,
    pub geoip_postal_code: Option<String>,
    pub geoip_org: Option<String>,
}

/// Extracts nginx-specific headers (only used in nginx mode)
pub fn extract_nginx_headers(headers: &HeaderMap) -> NginxExtractedHeaders {
    NginxExtractedHeaders {
        request_id: headers
            .get("X-Request-ID")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        remote_port: headers
            .get("X-Remote-Port")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        connection_id: headers
            .get("X-Connection-ID")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        geoip_country: headers
            .get("X-GeoIP-Country")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        geoip_city: headers
            .get("X-GeoIP-City")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        geoip_region: headers
            .get("X-GeoIP-Region")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        geoip_latitude: headers
            .get("X-GeoIP-Latitude")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        geoip_longitude: headers
            .get("X-GeoIP-Longitude")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        geoip_postal_code: headers
            .get("X-GeoIP-Postal-Code")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        geoip_org: headers
            .get("X-GeoIP-Org")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
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
    fn test_extract_nginx_headers_all() {
        let headers = create_header_map(&[
            ("X-Request-ID", "req-123"),
            ("X-Remote-Port", "54321"),
            ("X-Connection-ID", "conn-456"),
            ("X-GeoIP-Country", "US"),
            ("X-GeoIP-City", "New York"),
            ("X-GeoIP-Region", "NY"),
            ("X-GeoIP-Latitude", "40.7128"),
            ("X-GeoIP-Longitude", "-74.0060"),
            ("X-GeoIP-Postal-Code", "10001"),
            ("X-GeoIP-Org", "AS12345 Example Org"),
        ]);
        let result = extract_nginx_headers(&headers);
        assert_eq!(result.request_id, Some("req-123".to_string()));
        assert_eq!(result.remote_port, Some("54321".to_string()));
        assert_eq!(result.connection_id, Some("conn-456".to_string()));
        assert_eq!(result.geoip_country, Some("US".to_string()));
        assert_eq!(result.geoip_city, Some("New York".to_string()));
        assert_eq!(result.geoip_region, Some("NY".to_string()));
        assert_eq!(result.geoip_latitude, Some("40.7128".to_string()));
        assert_eq!(result.geoip_longitude, Some("-74.0060".to_string()));
        assert_eq!(result.geoip_postal_code, Some("10001".to_string()));
        assert_eq!(result.geoip_org, Some("AS12345 Example Org".to_string()));
    }

    #[test]
    fn test_extract_nginx_headers_empty() {
        let headers = HeaderMap::new();
        let result = extract_nginx_headers(&headers);
        assert_eq!(result.request_id, None);
        assert_eq!(result.remote_port, None);
        assert_eq!(result.connection_id, None);
        assert_eq!(result.geoip_country, None);
    }

    #[test]
    fn test_extract_nginx_headers_partial() {
        let headers = create_header_map(&[("X-Request-ID", "req-123"), ("X-GeoIP-Country", "US")]);
        let result = extract_nginx_headers(&headers);
        assert_eq!(result.request_id, Some("req-123".to_string()));
        assert_eq!(result.geoip_country, Some("US".to_string()));
        assert_eq!(result.remote_port, None);
        assert_eq!(result.geoip_city, None);
    }
}
