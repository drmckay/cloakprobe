use crate::config::ProxyMode;
use axum::http::HeaderMap;

/// Extracts connection headers based on proxy mode.
/// Nginx mode: X-TLS-Version, X-TLS-Cipher, X-HTTP-Protocol
/// Cloudflare mode: X-CF-TLS-Version, X-CF-TLS-Cipher, X-CF-HTTP-Protocol
pub fn extract_connection_headers(
    headers: &HeaderMap,
    proxy_mode: &ProxyMode,
) -> (Option<String>, Option<String>, Option<String>) {
    let (tls_header, cipher_header, proto_header) = match proxy_mode {
        ProxyMode::Nginx => ("X-TLS-Version", "X-TLS-Cipher", "X-HTTP-Protocol"),
        ProxyMode::Cloudflare => ("X-CF-TLS-Version", "X-CF-TLS-Cipher", "X-CF-HTTP-Protocol"),
    };

    let tls_version = headers
        .get(tls_header)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let tls_cipher = headers
        .get(cipher_header)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let http_protocol = headers
        .get(proto_header)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    (tls_version, tls_cipher, http_protocol)
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
    fn test_extract_connection_headers_nginx_mode() {
        let headers = create_header_map(&[
            ("X-TLS-Version", "TLSv1.3"),
            ("X-TLS-Cipher", "ECDHE-RSA-AES256-GCM-SHA384"),
            ("X-HTTP-Protocol", "HTTP/2"),
        ]);
        let (tls, cipher, proto) = extract_connection_headers(&headers, &ProxyMode::Nginx);
        assert_eq!(tls, Some("TLSv1.3".to_string()));
        assert_eq!(cipher, Some("ECDHE-RSA-AES256-GCM-SHA384".to_string()));
        assert_eq!(proto, Some("HTTP/2".to_string()));
    }

    #[test]
    fn test_extract_connection_headers_cloudflare_mode() {
        let headers = create_header_map(&[
            ("X-CF-TLS-Version", "TLSv1.3"),
            ("X-CF-TLS-Cipher", "ECDHE-RSA-AES256-GCM-SHA384"),
            ("X-CF-HTTP-Protocol", "HTTP/2"),
        ]);
        let (tls, cipher, proto) = extract_connection_headers(&headers, &ProxyMode::Cloudflare);
        assert_eq!(tls, Some("TLSv1.3".to_string()));
        assert_eq!(cipher, Some("ECDHE-RSA-AES256-GCM-SHA384".to_string()));
        assert_eq!(proto, Some("HTTP/2".to_string()));
    }

    #[test]
    fn test_extract_connection_headers_missing() {
        let headers = HeaderMap::new();
        let (tls, cipher, proto) = extract_connection_headers(&headers, &ProxyMode::Nginx);
        assert_eq!(tls, None);
        assert_eq!(cipher, None);
        assert_eq!(proto, None);
    }

    #[test]
    fn test_extract_connection_headers_partial() {
        let headers = create_header_map(&[("X-TLS-Version", "TLSv1.3")]);
        let (tls, cipher, proto) = extract_connection_headers(&headers, &ProxyMode::Nginx);
        assert_eq!(tls, Some("TLSv1.3".to_string()));
        assert_eq!(cipher, None);
        assert_eq!(proto, None);
    }
}
