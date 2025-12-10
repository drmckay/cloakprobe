use crate::model::InfoResponse;
use serde_json;

/// Formats an InfoResponse as pretty-printed JSON string.
/// This is a helper function that can be used by handlers.
pub fn format_json_response(response: &InfoResponse) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;

    #[test]
    fn test_format_json_response() {
        let response = InfoResponse {
            ip: "8.8.8.8".to_string(),
            ip_version: 4,
            reverse_dns: Some("dns.google".to_string()),
            network: NetworkInfo {
                asn: Some(15169),
                as_name: Some("Google LLC".to_string()),
                prefix: Some("8.8.8.0/24".to_string()),
                rir: Some("ARIN".to_string()),
                country: Some("US".to_string()),
                org_name: None,
                org_id: None,
                org_country: None,
                org_rir: None,
                org_type: None,
                abuse_contact: None,
                org_last_updated: None,
                tor_exit: false,
                vpn_or_hosting: false,
            },
            connection: ConnectionInfo {
                tls_version: Some("TLSv1.3".to_string()),
                http_protocol: Some("HTTP/2".to_string()),
                tls_cipher: Some("ECDHE-RSA-AES256-GCM-SHA384".to_string()),
                cf_ray: None,
                datacenter: None,
                request_id: None,
                remote_port: None,
                connection_id: None,
            },
            client: ClientInfo {
                user_agent: Some("Mozilla/5.0".to_string()),
                accept_language: None,
                accept_encoding: None,
                dnt: None,
                sec_gpc: None,
                save_data: None,
                upgrade_insecure_requests: None,
                referer: None,
                origin: None,
                client_hints: ClientHints {
                    sec_ch_ua: None,
                    sec_ch_ua_platform: None,
                    sec_ch_ua_mobile: None,
                    sec_ch_ua_full_version_list: None,
                    device_memory: None,
                    viewport_width: None,
                    downlink: None,
                    rtt: None,
                    ect: None,
                },
                sec_fetch: SecFetchHeaders {
                    site: None,
                    mode: None,
                    dest: None,
                    user: None,
                },
            },
            privacy: PrivacyInfo {
                mode: "strict".to_string(),
                logs_retained: false,
            },
            server: ServerInfo {
                timestamp_utc: "2025-01-10T12:00:00Z".to_string(),
                region: None,
                version: "0.1.3".to_string(),
                response_time_ms: Some(0.42),
            },
            cloudflare: None,
            nginx: None,
        };

        let json = format_json_response(&response).unwrap();
        assert!(json.contains("\"ip\": \"8.8.8.8\""));
        assert!(json.contains("\"ip_version\": 4"));
        assert!(json.contains("\"asn\": 15169"));
    }
}
