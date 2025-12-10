use axum::http::HeaderMap;

use crate::model::{ClientHints, ClientInfo, SecFetchHeaders};
use crate::utils::dnt::format_dnt;
use crate::utils::sanitize::sanitize_for_json;

/// Extract and sanitize client info from headers.
pub fn extract_client_info(headers: &HeaderMap) -> ClientInfo {
    let ua = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let accept_language = headers
        .get("Accept-Language")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let accept_encoding = headers
        .get("Accept-Encoding")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let dnt = headers
        .get("DNT")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let sec_gpc = headers
        .get("Sec-GPC")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let save_data = headers
        .get("Save-Data")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let upgrade_insecure_requests = headers
        .get("Upgrade-Insecure-Requests")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let referer = headers
        .get("Referer")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let origin = headers
        .get("Origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let sec_ch_ua = headers
        .get("Sec-CH-UA")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let sec_ch_ua_platform = headers
        .get("Sec-CH-UA-Platform")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let sec_ch_ua_mobile = headers
        .get("Sec-CH-UA-Mobile")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let sec_ch_ua_full_version_list = headers
        .get("Sec-CH-UA-Full-Version-List")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let device_memory = headers
        .get("Device-Memory")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let viewport_width = headers
        .get("Viewport-Width")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let downlink = headers
        .get("Downlink")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let rtt = headers
        .get("RTT")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let ect = headers
        .get("ECT")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let sec_fetch_site = headers
        .get("Sec-Fetch-Site")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let sec_fetch_mode = headers
        .get("Sec-Fetch-Mode")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let sec_fetch_dest = headers
        .get("Sec-Fetch-Dest")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let sec_fetch_user = headers
        .get("Sec-Fetch-User")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    ClientInfo {
        user_agent: sanitize_for_json(ua.as_deref()),
        accept_language: sanitize_for_json(accept_language.as_deref()),
        accept_encoding: sanitize_for_json(accept_encoding.as_deref()),
        dnt: format_dnt(dnt),
        sec_gpc: format_dnt(sec_gpc),
        save_data: sanitize_for_json(save_data.as_deref()),
        upgrade_insecure_requests: sanitize_for_json(upgrade_insecure_requests.as_deref()),
        referer: sanitize_for_json(referer.as_deref()),
        origin: sanitize_for_json(origin.as_deref()),
        client_hints: ClientHints {
            sec_ch_ua: sanitize_for_json(sec_ch_ua.as_deref()),
            sec_ch_ua_platform: sanitize_for_json(sec_ch_ua_platform.as_deref()),
            sec_ch_ua_mobile: sanitize_for_json(sec_ch_ua_mobile.as_deref()),
            sec_ch_ua_full_version_list: sanitize_for_json(sec_ch_ua_full_version_list.as_deref()),
            device_memory: sanitize_for_json(device_memory.as_deref()),
            viewport_width: sanitize_for_json(viewport_width.as_deref()),
            downlink: sanitize_for_json(downlink.as_deref()),
            rtt: sanitize_for_json(rtt.as_deref()),
            ect: sanitize_for_json(ect.as_deref()),
        },
        sec_fetch: SecFetchHeaders {
            site: sanitize_for_json(sec_fetch_site.as_deref()),
            mode: sanitize_for_json(sec_fetch_mode.as_deref()),
            dest: sanitize_for_json(sec_fetch_dest.as_deref()),
            user: sanitize_for_json(sec_fetch_user.as_deref()),
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
    fn test_extract_client_info_basic() {
        let headers = create_header_map(&[
            ("User-Agent", "Mozilla/5.0"),
            ("Accept-Language", "en-US,en;q=0.9"),
            ("Accept-Encoding", "gzip, deflate"),
        ]);
        let info = extract_client_info(&headers);
        assert_eq!(info.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(info.accept_language, Some("en-US,en;q=0.9".to_string()));
        assert_eq!(info.accept_encoding, Some("gzip, deflate".to_string()));
    }

    #[test]
    fn test_extract_client_info_dnt() {
        let headers = create_header_map(&[("DNT", "1")]);
        let info = extract_client_info(&headers);
        assert_eq!(info.dnt, Some("Enabled".to_string()));
    }

    #[test]
    fn test_extract_client_info_dnt_disabled() {
        let headers = create_header_map(&[("DNT", "0")]);
        let info = extract_client_info(&headers);
        assert_eq!(info.dnt, Some("Disabled".to_string()));
    }

    #[test]
    fn test_extract_client_info_sec_gpc() {
        let headers = create_header_map(&[("Sec-GPC", "1")]);
        let info = extract_client_info(&headers);
        assert_eq!(info.sec_gpc, Some("Enabled".to_string()));
    }

    #[test]
    fn test_extract_client_info_client_hints() {
        let headers = create_header_map(&[
            ("Sec-CH-UA", "\"Chromium\";v=\"110\""),
            ("Sec-CH-UA-Platform", "\"Linux\""),
            ("Sec-CH-UA-Mobile", "?0"),
            ("Device-Memory", "8"),
            ("Viewport-Width", "1920"),
        ]);
        let info = extract_client_info(&headers);
        assert_eq!(
            info.client_hints.sec_ch_ua,
            Some("\\\"Chromium\\\";v=\\\"110\\\"".to_string())
        );
        assert_eq!(
            info.client_hints.sec_ch_ua_platform,
            Some("\\\"Linux\\\"".to_string())
        );
        assert_eq!(info.client_hints.sec_ch_ua_mobile, Some("?0".to_string()));
        assert_eq!(info.client_hints.device_memory, Some("8".to_string()));
        assert_eq!(info.client_hints.viewport_width, Some("1920".to_string()));
    }

    #[test]
    fn test_extract_client_info_sec_fetch() {
        let headers = create_header_map(&[
            ("Sec-Fetch-Site", "same-origin"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Dest", "document"),
            ("Sec-Fetch-User", "?1"),
        ]);
        let info = extract_client_info(&headers);
        assert_eq!(info.sec_fetch.site, Some("same-origin".to_string()));
        assert_eq!(info.sec_fetch.mode, Some("navigate".to_string()));
        assert_eq!(info.sec_fetch.dest, Some("document".to_string()));
        assert_eq!(info.sec_fetch.user, Some("?1".to_string()));
    }

    #[test]
    fn test_extract_client_info_empty() {
        let headers = HeaderMap::new();
        let info = extract_client_info(&headers);
        assert_eq!(info.user_agent, None);
        assert_eq!(info.dnt, None);
        assert_eq!(info.client_hints.sec_ch_ua, None);
    }
}
