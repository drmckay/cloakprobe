use tera::Context;

/// Helper functions for building HTML template contexts.
/// These can be used by handlers to build template contexts more easily.
pub mod context_builder {
    use super::*;
    use crate::model::*;
    use crate::utils::sanitize::sanitize_header;

    /// Adds IP information to the template context.
    pub fn add_ip_info(
        context: &mut Context,
        ip: &str,
        ip_version: u8,
        ip_details: &crate::utils::ip::IpDetails,
    ) {
        context.insert("ip", &sanitize_header(Some(ip.to_string())));
        context.insert("ip_version", &ip_version);
        context.insert("ip_type", &ip_details.ip_type);
        context.insert("ip_primary", &ip_details.primary);
        context.insert("ip_hex", &ip_details.hex);
        context.insert("ip_expanded", &ip_details.expanded);
        context.insert("ip_binary", &ip_details.binary);
        context.insert("ip_numeric", &ip_details.numeric);
        context.insert("ip_subnet", &ip_details.subnet);
        context.insert("ip_subnet_size", &ip_details.subnet_size);
    }

    /// Adds network information to the template context.
    pub fn add_network_info(context: &mut Context, network: &NetworkInfo) {
        context.insert(
            "asn",
            &network
                .asn
                .map(|a| format!("AS{}", a))
                .unwrap_or_else(|| "—".to_string()),
        );
        context.insert(
            "as_name",
            &network.as_name.as_ref().unwrap_or(&"—".to_string()),
        );
        context.insert("prefix", &network.prefix.as_deref().unwrap_or("—"));
        context.insert("country", &network.country.as_deref().unwrap_or("—"));
        context.insert("org_name", &network.org_name.as_deref().unwrap_or("—"));
        context.insert("org_id", &network.org_id.as_deref().unwrap_or("—"));
        context.insert("org_rir", &network.org_rir.as_deref().unwrap_or("—"));
        context.insert("org_type", &network.org_type.as_deref().unwrap_or("—"));
        context.insert(
            "abuse_contact",
            &network.abuse_contact.as_deref().unwrap_or("—"),
        );
        context.insert(
            "org_last_updated",
            &network.org_last_updated.as_deref().unwrap_or("—"),
        );
    }

    /// Adds server information to the template context.
    pub fn add_server_info(context: &mut Context, server: &ServerInfo, privacy: &PrivacyInfo) {
        context.insert("timestamp", &server.timestamp_utc);
        context.insert("version", &server.version);
        context.insert("region", &server.region.as_deref().unwrap_or("—"));
        context.insert(
            "response_time_ms",
            &format!("{:.2}", server.response_time_ms.unwrap_or(0.0)),
        );
        context.insert("privacy_mode", &privacy.mode);
    }

    /// Header item structure for template rendering
    #[derive(serde::Serialize)]
    pub struct HeaderItem {
        pub label: String,
        pub value: String,
    }

    /// Builds Cloudflare geo location header items
    #[allow(clippy::too_many_arguments)]
    pub fn build_geo_location_items(
        country: Option<&String>,
        city: Option<&String>,
        region: Option<&String>,
        region_code: Option<&String>,
        continent: Option<&String>,
        latitude: Option<&String>,
        longitude: Option<&String>,
        postal_code: Option<&String>,
        timezone: Option<&String>,
    ) -> Vec<HeaderItem> {
        let mut items = Vec::new();
        if let Some(c) = country.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "Country".to_string(),
                value: sanitize_header(Some(c.clone())),
            });
        }
        if let Some(c) = city.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "City".to_string(),
                value: sanitize_header(Some(c.clone())),
            });
        }
        if let Some(r) = region.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "Region".to_string(),
                value: sanitize_header(Some(r.clone())),
            });
        }
        if let Some(rc) = region_code.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "Region-Code".to_string(),
                value: sanitize_header(Some(rc.clone())),
            });
        }
        if let Some(c) = continent.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "Continent".to_string(),
                value: sanitize_header(Some(c.clone())),
            });
        }
        if let Some(lat) = latitude.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "Latitude".to_string(),
                value: sanitize_header(Some(lat.clone())),
            });
        }
        if let Some(lon) = longitude.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "Longitude".to_string(),
                value: sanitize_header(Some(lon.clone())),
            });
        }
        if let Some(pc) = postal_code.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "Postal-Code".to_string(),
                value: sanitize_header(Some(pc.clone())),
            });
        }
        if let Some(tz) = timezone.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "Timezone".to_string(),
                value: sanitize_header(Some(tz.clone())),
            });
        }
        items
    }

    /// Builds Cloudflare network header items
    pub fn build_network_items(
        asn: Option<&String>,
        as_organization: Option<&String>,
        colo: Option<&String>,
    ) -> Vec<HeaderItem> {
        let mut items = Vec::new();
        if let Some(a) = asn.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "ASN".to_string(),
                value: sanitize_header(Some(a.clone())),
            });
        }
        if let Some(a) = as_organization.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "AS-Organization".to_string(),
                value: sanitize_header(Some(a.clone())),
            });
        }
        if let Some(c) = colo.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "Colo".to_string(),
                value: sanitize_header(Some(c.clone())),
            });
        }
        items
    }

    /// Builds Cloudflare connection header items
    pub fn build_connection_items(
        cf_visitor: Option<&String>,
        x_forwarded_proto: Option<&String>,
        x_http_protocol: Option<&String>,
        x_tls_version: Option<&String>,
        x_tls_cipher: Option<&String>,
    ) -> Vec<HeaderItem> {
        let mut items = Vec::new();
        if let Some(v) = cf_visitor.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "CF-Visitor".to_string(),
                value: sanitize_header(Some(v.clone())),
            });
        }
        if let Some(p) = x_forwarded_proto.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "X-Forwarded-Proto".to_string(),
                value: sanitize_header(Some(p.clone())),
            });
        }
        if let Some(p) = x_http_protocol.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "HTTP-Protocol".to_string(),
                value: sanitize_header(Some(p.clone())),
            });
        }
        if let Some(t) = x_tls_version.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "TLS-Version".to_string(),
                value: sanitize_header(Some(t.clone())),
            });
        }
        if let Some(c) = x_tls_cipher.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "TLS-Cipher".to_string(),
                value: sanitize_header(Some(c.clone())),
            });
        }
        items
    }

    /// Builds Cloudflare security header items
    pub fn build_security_items(
        trust_score: Option<&String>,
        bot_score: Option<&String>,
        verified_bot: Option<&String>,
    ) -> Vec<HeaderItem> {
        let mut items = Vec::new();
        if let Some(s) = trust_score.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "Trust-Score".to_string(),
                value: sanitize_header(Some(s.clone())),
            });
        }
        if let Some(s) = bot_score.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "Bot-Score".to_string(),
                value: sanitize_header(Some(s.clone())),
            });
        }
        if let Some(s) = verified_bot.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "Verified-Bot".to_string(),
                value: sanitize_header(Some(s.clone())),
            });
        }
        items
    }

    /// Builds proxy header items
    pub fn build_proxy_items(
        x_forwarded_for: Option<&String>,
        x_real_ip: Option<&String>,
    ) -> Vec<HeaderItem> {
        let mut items = Vec::new();
        if let Some(f) = x_forwarded_for.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "X-Forwarded-For".to_string(),
                value: sanitize_header(Some(f.clone())),
            });
        }
        if let Some(r) = x_real_ip.filter(|s| !s.is_empty()) {
            items.push(HeaderItem {
                label: "X-Real-IP".to_string(),
                value: sanitize_header(Some(r.clone())),
            });
        }
        items
    }

    /// Adds client information to the template context
    pub fn add_client_info(context: &mut Context, client: &ClientInfo) {
        context.insert("user_agent", &sanitize_header(client.user_agent.clone()));
        context.insert(
            "accept_language",
            &sanitize_header(client.accept_language.clone()),
        );
        context.insert(
            "accept_encoding",
            &sanitize_header(client.accept_encoding.clone()),
        );
        context.insert("dnt", &sanitize_header(client.dnt.clone()));
        context.insert("sec_gpc", &sanitize_header(client.sec_gpc.clone()));
        context.insert("save_data", &sanitize_header(client.save_data.clone()));
        context.insert(
            "upgrade_insecure_requests",
            &sanitize_header(client.upgrade_insecure_requests.clone()),
        );
        context.insert("referer", &sanitize_header(client.referer.clone()));
        context.insert("origin", &sanitize_header(client.origin.clone()));
        context.insert(
            "sec_ch_ua",
            &sanitize_header(client.client_hints.sec_ch_ua.clone()),
        );
        context.insert(
            "sec_ch_ua_platform",
            &sanitize_header(client.client_hints.sec_ch_ua_platform.clone()),
        );
        context.insert(
            "sec_ch_ua_mobile",
            &sanitize_header(client.client_hints.sec_ch_ua_mobile.clone()),
        );
        context.insert(
            "sec_ch_ua_full_version_list",
            &sanitize_header(client.client_hints.sec_ch_ua_full_version_list.clone()),
        );
        context.insert(
            "device_memory",
            &sanitize_header(client.client_hints.device_memory.clone()),
        );
        context.insert(
            "viewport_width",
            &sanitize_header(client.client_hints.viewport_width.clone()),
        );
        context.insert(
            "downlink",
            &sanitize_header(client.client_hints.downlink.clone()),
        );
        context.insert("rtt", &sanitize_header(client.client_hints.rtt.clone()));
        context.insert("ect", &sanitize_header(client.client_hints.ect.clone()));
        context.insert(
            "sec_fetch_site",
            &sanitize_header(client.sec_fetch.site.clone()),
        );
        context.insert(
            "sec_fetch_mode",
            &sanitize_header(client.sec_fetch.mode.clone()),
        );
        context.insert(
            "sec_fetch_dest",
            &sanitize_header(client.sec_fetch.dest.clone()),
        );
        context.insert(
            "sec_fetch_user",
            &sanitize_header(client.sec_fetch.user.clone()),
        );
    }

    /// Adds connection information to the template context
    #[allow(clippy::too_many_arguments)]
    pub fn add_connection_info(
        context: &mut Context,
        connection: &ConnectionInfo,
        is_cloudflare_mode: bool,
        x_tls_version: Option<&str>,
        x_http_protocol: Option<&str>,
        x_tls_cipher: Option<&String>,
        cf_request_id: Option<&String>,
        cf_cache_status: Option<&String>,
    ) {
        let tls_version_display = x_tls_version
            .filter(|v| !v.is_empty())
            .map(|v| sanitize_header(Some(v.to_string())))
            .or_else(|| {
                connection
                    .tls_version
                    .as_ref()
                    .map(|v| sanitize_header(Some(v.clone())))
            })
            .unwrap_or_else(|| "—".to_string());

        let http_protocol_display = x_http_protocol
            .filter(|v| !v.is_empty())
            .map(|v| sanitize_header(Some(v.to_string())))
            .or_else(|| {
                connection
                    .http_protocol
                    .as_ref()
                    .map(|v| sanitize_header(Some(v.clone())))
            })
            .unwrap_or_else(|| "—".to_string());

        context.insert("tls_version", &tls_version_display);
        context.insert("http_protocol", &http_protocol_display);
        context.insert("tls_cipher", &sanitize_header(x_tls_cipher.cloned()));

        context.insert("is_cloudflare_mode", &is_cloudflare_mode);

        context.insert(
            "cf_ray",
            &if is_cloudflare_mode {
                connection
                    .cf_ray
                    .as_ref()
                    .map(|v| sanitize_header(Some(v.clone())))
                    .unwrap_or_else(|| "—".to_string())
            } else {
                "—".to_string()
            },
        );
        context.insert(
            "datacenter",
            &if is_cloudflare_mode {
                connection
                    .datacenter
                    .as_ref()
                    .map(|v| sanitize_header(Some(v.clone())))
                    .unwrap_or_else(|| "—".to_string())
            } else {
                "—".to_string()
            },
        );

        context.insert(
            "cf_request_id",
            &sanitize_header(cf_request_id.filter(|s| !s.is_empty()).cloned()),
        );
        context.insert(
            "cf_cache_status",
            &sanitize_header(cf_cache_status.filter(|s| !s.is_empty()).cloned()),
        );

        context.insert(
            "request_id",
            &connection
                .request_id
                .as_ref()
                .map(|v| sanitize_header(Some(v.clone())))
                .unwrap_or_else(|| "—".to_string()),
        );
        context.insert(
            "remote_port",
            &connection
                .remote_port
                .as_ref()
                .map(|v| sanitize_header(Some(v.clone())))
                .unwrap_or_else(|| "—".to_string()),
        );
        context.insert(
            "connection_id",
            &connection
                .connection_id
                .as_ref()
                .map(|v| sanitize_header(Some(v.clone())))
                .unwrap_or_else(|| "—".to_string()),
        );
    }

    /// Adds Nginx GeoIP information to the template context
    pub fn add_nginx_geoip_info(
        context: &mut Context,
        nginx_headers: Option<&crate::headers::nginx::NginxExtractedHeaders>,
    ) {
        let default = "—".to_string();
        context.insert(
            "geoip_country",
            &nginx_headers
                .and_then(|h| h.geoip_country.as_ref())
                .map(|v| sanitize_header(Some(v.clone())))
                .unwrap_or_else(|| default.clone()),
        );
        context.insert(
            "geoip_city",
            &nginx_headers
                .and_then(|h| h.geoip_city.as_ref())
                .map(|v| sanitize_header(Some(v.clone())))
                .unwrap_or_else(|| default.clone()),
        );
        context.insert(
            "geoip_region",
            &nginx_headers
                .and_then(|h| h.geoip_region.as_ref())
                .map(|v| sanitize_header(Some(v.clone())))
                .unwrap_or_else(|| default.clone()),
        );
        context.insert(
            "geoip_latitude",
            &nginx_headers
                .and_then(|h| h.geoip_latitude.as_ref())
                .map(|v| sanitize_header(Some(v.clone())))
                .unwrap_or_else(|| default.clone()),
        );
        context.insert(
            "geoip_longitude",
            &nginx_headers
                .and_then(|h| h.geoip_longitude.as_ref())
                .map(|v| sanitize_header(Some(v.clone())))
                .unwrap_or_else(|| default.clone()),
        );
        context.insert(
            "geoip_postal_code",
            &nginx_headers
                .and_then(|h| h.geoip_postal_code.as_ref())
                .map(|v| sanitize_header(Some(v.clone())))
                .unwrap_or_else(|| default.clone()),
        );
        context.insert(
            "geoip_org",
            &nginx_headers
                .and_then(|h| h.geoip_org.as_ref())
                .map(|v| sanitize_header(Some(v.clone())))
                .unwrap_or_else(|| default.clone()),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::NetworkInfo;
    use crate::utils::ip::get_ip_details;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_add_ip_info() {
        let mut context = Context::new();
        let ip = IpAddr::from_str("8.8.8.8").unwrap();
        let details = get_ip_details(&ip);
        context_builder::add_ip_info(&mut context, "8.8.8.8", 4, &details);
        assert!(context.get("ip").is_some());
        assert_eq!(
            context.get("ip_version"),
            Some(&tera::Value::Number(4.into()))
        );
    }

    #[test]
    fn test_add_network_info() {
        let mut context = Context::new();
        let network = NetworkInfo {
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
        };
        context_builder::add_network_info(&mut context, &network);
        assert!(context.get("asn").is_some());
        assert!(context.get("as_name").is_some());
    }
}
