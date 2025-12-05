use crate::asn::AsnDatabase;
use crate::cf::extract_client_context;
use crate::config::AppConfig;
use crate::error::AppError;
use crate::model::*;

use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use std::sync::Arc;
use tera::{Context, Tera};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub asn_db: Arc<dyn AsnDatabase>,
}

/// Sanitizes a header value for safe HTML output.
/// Escapes HTML special characters to prevent XSS attacks.
fn sanitize_header(value: Option<String>) -> String {
    value
        .map(|v| {
            v.chars()
                .flat_map(|c| match c {
                    '<' => "&lt;".chars().collect(),
                    '>' => "&gt;".chars().collect(),
                    '&' => "&amp;".chars().collect(),
                    '"' => "&quot;".chars().collect(),
                    '\'' => "&#x27;".chars().collect(),
                    '/' => "&#x2F;".chars().collect(),
                    c if c.is_control() && c != '\n' && c != '\r' && c != '\t' => {
                        Vec::new() // Remove control characters except newlines and tabs
                    }
                    c => vec![c], // Keep valid characters
                })
                .collect::<String>()
        })
        .unwrap_or_else(|| "—".to_string())
}

/// Sanitizes a header value for safe JSON output.
/// Removes control characters and ensures JSON-safe string.
fn sanitize_for_json(value: Option<String>) -> Option<String> {
    value.map(|v| {
        v.chars()
            .filter(|c| {
                // Keep printable characters, newlines, tabs, carriage returns
                c.is_ascii_graphic()
                    || *c == '\n'
                    || *c == '\r'
                    || *c == '\t'
                    || c.is_alphanumeric()
                    || c.is_whitespace()
            })
            .collect::<String>()
    })
}

pub async fn info_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<InfoResponse>, AppError> {
    let ctx = extract_client_context(&headers).map_err(|e| AppError::Cf(e.to_string()))?;

    let asn_info = state.asn_db.lookup(ctx.ip);

    let network = NetworkInfo::from_asn(asn_info);

    // Extract Cloudflare Worker headers
    let x_cf_http_protocol = headers
        .get("X-CF-HTTP-Protocol")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_tls_version = headers
        .get("X-CF-TLS-Version")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_tls_cipher = headers
        .get("X-CF-TLS-Cipher")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Prioritize CF worker headers for connection info
    let connection = ConnectionInfo {
        tls_version: x_cf_tls_version
            .as_ref()
            .filter(|v| !v.is_empty())
            .or(ctx.tls_version.as_ref())
            .and_then(|v| sanitize_for_json(Some(v.clone()))),
        http_protocol: x_cf_http_protocol
            .as_ref()
            .filter(|v| !v.is_empty())
            .or(ctx.http_protocol.as_ref())
            .and_then(|v| sanitize_for_json(Some(v.clone()))),
        cf_ray: sanitize_for_json(ctx.cf_ray.clone()),
        datacenter: sanitize_for_json(ctx.cf_datacenter.clone()),
    };

    // Extract and sanitize client info
    let client = {
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
        let sec_ch_ua = headers
            .get("Sec-CH-UA")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let sec_ch_ua_platform = headers
            .get("Sec-CH-UA-Platform")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        ClientInfo {
            user_agent: sanitize_for_json(ua),
            accept_language: sanitize_for_json(accept_language),
            accept_encoding: sanitize_for_json(accept_encoding),
            client_hints: ClientHints {
                sec_ch_ua: sanitize_for_json(sec_ch_ua),
                sec_ch_ua_platform: sanitize_for_json(sec_ch_ua_platform),
            },
        }
    };

    let privacy = PrivacyInfo::from(&state.config.privacy_mode);
    let server = ServerInfo {
        timestamp_utc: Utc::now().to_rfc3339(),
        region: std::env::var("CLOAKPROBE_REGION")
            .or_else(|_| std::env::var("CFDEBUG_REGION"))
            .ok(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    // Extract Cloudflare headers
    let cf_visitor = headers
        .get("CF-Visitor")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let cf_ipcountry = headers
        .get("CF-IPCountry")
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
    let x_forwarded_proto = headers
        .get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract Cloudflare Worker headers - Geo Location
    let x_cf_country = headers
        .get("X-CF-Country")
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

    // Build Cloudflare headers structure
    let mut geo = CloudflareGeoHeaders::default();
    if cf_ipcountry.is_some() || x_cf_country.is_some() || x_cf_city.is_some() {
        geo.cf_ipcountry = sanitize_for_json(cf_ipcountry);
        geo.country = sanitize_for_json(x_cf_country);
        geo.city = sanitize_for_json(x_cf_city);
        geo.region = sanitize_for_json(x_cf_region);
        geo.region_code = sanitize_for_json(x_cf_region_code);
        geo.continent = sanitize_for_json(x_cf_continent);
        geo.latitude = sanitize_for_json(x_cf_latitude);
        geo.longitude = sanitize_for_json(x_cf_longitude);
        geo.postal_code = sanitize_for_json(x_cf_postal_code);
        geo.timezone = sanitize_for_json(x_cf_timezone);
    }

    let mut network_headers = CloudflareNetworkHeaders::default();
    if x_cf_asn.is_some() || x_cf_as_organization.is_some() || x_cf_colo.is_some() {
        network_headers.asn = sanitize_for_json(x_cf_asn);
        network_headers.as_organization = sanitize_for_json(x_cf_as_organization);
        network_headers.colo = sanitize_for_json(x_cf_colo);
    }

    let mut connection_headers = CloudflareConnectionHeaders::default();
    if cf_visitor.is_some()
        || x_forwarded_proto.is_some()
        || x_cf_http_protocol.is_some()
        || x_cf_tls_version.is_some()
        || x_cf_tls_cipher.is_some()
        || cf_request_id.is_some()
        || cf_cache_status.is_some()
    {
        connection_headers.cf_visitor = sanitize_for_json(cf_visitor);
        connection_headers.x_forwarded_proto = sanitize_for_json(x_forwarded_proto);
        connection_headers.http_protocol = sanitize_for_json(x_cf_http_protocol);
        connection_headers.tls_version = sanitize_for_json(x_cf_tls_version);
        connection_headers.tls_cipher = sanitize_for_json(x_cf_tls_cipher);
        connection_headers.cf_request_id = sanitize_for_json(cf_request_id);
        connection_headers.cf_cache_status = sanitize_for_json(cf_cache_status);
    }

    let mut security = CloudflareSecurityHeaders::default();
    if x_cf_trust_score.is_some() || x_cf_bot_score.is_some() || x_cf_verified_bot.is_some() {
        security.trust_score = sanitize_for_json(x_cf_trust_score);
        security.bot_score = sanitize_for_json(x_cf_bot_score);
        security.verified_bot = sanitize_for_json(x_cf_verified_bot);
    }

    let mut proxy = CloudflareProxyHeaders::default();
    if x_forwarded_for.is_some() || x_real_ip.is_some() {
        proxy.x_forwarded_for = sanitize_for_json(x_forwarded_for);
        proxy.x_real_ip = sanitize_for_json(x_real_ip);
    }

    let cloudflare = if geo.cf_ipcountry.is_some()
        || network_headers.asn.is_some()
        || connection_headers.cf_visitor.is_some()
        || security.trust_score.is_some()
        || proxy.x_forwarded_for.is_some()
    {
        Some(CloudflareHeaders {
            geo: if geo.cf_ipcountry.is_some() {
                Some(geo)
            } else {
                None
            },
            network: if network_headers.asn.is_some() {
                Some(network_headers)
            } else {
                None
            },
            connection: if connection_headers.cf_visitor.is_some() {
                Some(connection_headers)
            } else {
                None
            },
            security: if security.trust_score.is_some() {
                Some(security)
            } else {
                None
            },
            proxy: if proxy.x_forwarded_for.is_some() {
                Some(proxy)
            } else {
                None
            },
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
    };

    Ok(Json(resp))
}

fn extract_client_info(headers: &HeaderMap) -> ClientInfo {
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

    let sec_ch_ua = headers
        .get("Sec-CH-UA")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let sec_ch_ua_platform = headers
        .get("Sec-CH-UA-Platform")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    ClientInfo {
        user_agent: ua,
        accept_language,
        accept_encoding,
        client_hints: ClientHints {
            sec_ch_ua,
            sec_ch_ua_platform,
        },
    }
}

fn is_private_v4(ip: &std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 10
        || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
        || (octets[0] == 192 && octets[1] == 168)
}

fn is_link_local_v4(ip: &std::net::Ipv4Addr) -> bool {
    ip.octets()[0] == 169 && ip.octets()[1] == 254
}

fn is_multicast_v4(ip: &std::net::Ipv4Addr) -> bool {
    ip.octets()[0] >= 224 && ip.octets()[0] <= 239
}

fn is_link_local_v6(ip: &std::net::Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

fn is_multicast_v6(ip: &std::net::Ipv6Addr) -> bool {
    ip.segments()[0] & 0xff00 == 0xff00
}

fn get_ip_details(ip: &std::net::IpAddr) -> (String, String, String, String, String) {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            let decimal = v4.to_string();
            let hex = format!(
                "{:02X}.{:02X}.{:02X}.{:02X}",
                octets[0], octets[1], octets[2], octets[3]
            );
            let binary = format!(
                "{:08b}.{:08b}.{:08b}.{:08b}",
                octets[0], octets[1], octets[2], octets[3]
            );
            let u32_val = u32::from_be_bytes(octets);
            let ip_type = if v4.is_loopback() {
                "Loopback"
            } else if is_private_v4(v4) {
                "Private"
            } else if is_multicast_v4(v4) {
                "Multicast"
            } else if is_link_local_v4(v4) {
                "Link-Local"
            } else if v4.is_broadcast() {
                "Broadcast"
            } else if v4.is_unspecified() {
                "Unspecified"
            } else {
                "Public"
            };
            (
                decimal,
                hex,
                binary,
                format!("{}", u32_val),
                ip_type.to_string(),
            )
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();
            let hex = v6.to_string();
            let binary = segments
                .iter()
                .map(|s| format!("{:016b}", s))
                .collect::<Vec<_>>()
                .join(":");
            let ip_type = if v6.is_loopback() {
                "Loopback"
            } else if is_multicast_v6(v6) {
                "Multicast"
            } else if v6.is_unspecified() {
                "Unspecified"
            } else if is_link_local_v6(v6) {
                "Link-Local"
            } else {
                "Global Unicast"
            };
            (
                hex.clone(),
                hex,
                binary,
                format!("{:032X}", u128::from_be_bytes(v6.octets())),
                ip_type.to_string(),
            )
        }
    }
}

pub async fn html_handler(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let ctx = extract_client_context(&headers).ok();
    let ip_display = ctx
        .as_ref()
        .map(|c| c.ip.to_string())
        .unwrap_or_else(|| "unknown".into());
    let ip_version = ctx.as_ref().map(|c| c.ip_version).unwrap_or(0);

    let (ip_decimal, ip_hex, ip_binary, ip_numeric, ip_type) = ctx
        .as_ref()
        .map(|c| get_ip_details(&c.ip))
        .unwrap_or_else(|| ("—".into(), "—".into(), "—".into(), "—".into(), "—".into()));

    let asn_info = ctx.as_ref().and_then(|c| state.asn_db.lookup(c.ip));

    let network = NetworkInfo::from_asn(asn_info);
    let connection = ctx.as_ref().map(|c| ConnectionInfo {
        tls_version: c.tls_version.clone(),
        http_protocol: c.http_protocol.clone(),
        cf_ray: c.cf_ray.clone(),
        datacenter: c.cf_datacenter.clone(),
    });

    let client = extract_client_info(&headers);
    let privacy = PrivacyInfo::from(&state.config.privacy_mode);
    let server = ServerInfo {
        timestamp_utc: Utc::now().to_rfc3339(),
        region: std::env::var("CLOAKPROBE_REGION")
            .or_else(|_| std::env::var("CFDEBUG_REGION"))
            .ok(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };

    // Extract additional Cloudflare headers
    let cf_visitor = headers
        .get("CF-Visitor")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let cf_ipcountry = headers
        .get("CF-IPCountry")
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
    let x_forwarded_proto = headers
        .get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract Cloudflare Worker headers - Geo Location
    let x_cf_country = headers
        .get("X-CF-Country")
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

    // Extract Cloudflare Worker headers - Connection
    let x_cf_http_protocol = headers
        .get("X-CF-HTTP-Protocol")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_tls_version = headers
        .get("X-CF-TLS-Version")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_tls_cipher = headers
        .get("X-CF-TLS-Cipher")
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

    // Initialize Tera template engine
    let tera = match Tera::new("templates/**/*.tera") {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to initialize Tera: {}", e);
            return Response::builder()
                .status(500)
                .header("Content-Type", "text/plain")
                .body(String::from("Internal server error"))
                .unwrap();
        }
    };

    // Build template context with sanitized header values
    let mut context = Context::new();

    // IP information
    context.insert("ip", &sanitize_header(Some(ip_display)));
    context.insert("ip_version", &ip_version);
    context.insert("ip_type", &ip_type);
    context.insert("ip_decimal", &ip_decimal);
    context.insert("ip_hex", &ip_hex);
    context.insert("ip_binary", &ip_binary);
    context.insert("ip_numeric", &ip_numeric);

    // Network information
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
    context.insert("rir", &network.rir.as_ref().unwrap_or(&"—".to_string()));
    context.insert("country", &network.country.as_deref().unwrap_or("—"));
    context.insert("org_name", &network.org_name.as_deref().unwrap_or("—"));

    // Connection details - prioritize CF worker headers if available
    let tls_version_display = x_cf_tls_version
        .as_deref()
        .filter(|v| *v != "—" && !v.is_empty())
        .map(|v| sanitize_header(Some(v.to_string())))
        .or_else(|| {
            connection
                .as_ref()
                .and_then(|c| c.tls_version.as_ref())
                .map(|v| sanitize_header(Some(v.clone())))
        })
        .unwrap_or_else(|| "—".to_string());

    let http_protocol_display = x_cf_http_protocol
        .as_deref()
        .filter(|v| *v != "—" && !v.is_empty())
        .map(|v| sanitize_header(Some(v.to_string())))
        .or_else(|| {
            connection
                .as_ref()
                .and_then(|c| c.http_protocol.as_ref())
                .map(|v| sanitize_header(Some(v.clone())))
        })
        .unwrap_or_else(|| "—".to_string());

    context.insert("tls_version", &tls_version_display);
    context.insert("http_protocol", &http_protocol_display);
    context.insert("tls_cipher", &sanitize_header(x_cf_tls_cipher.clone()));
    context.insert(
        "cf_ray",
        &connection
            .as_ref()
            .and_then(|c| c.cf_ray.as_ref())
            .map(|v| sanitize_header(Some(v.clone())))
            .unwrap_or_else(|| "—".to_string()),
    );
    context.insert(
        "datacenter",
        &connection
            .as_ref()
            .and_then(|c| c.datacenter.as_ref())
            .map(|v| sanitize_header(Some(v.clone())))
            .unwrap_or_else(|| "—".to_string()),
    );
    // Only include CF-Request-ID and CF-Cache-Status if they have non-empty values
    context.insert(
        "cf_request_id",
        &sanitize_header(cf_request_id.filter(|s| !s.is_empty())),
    );
    context.insert(
        "cf_cache_status",
        &sanitize_header(cf_cache_status.filter(|s| !s.is_empty())),
    );

    // Build Cloudflare Headers sections with sanitized values
    #[derive(serde::Serialize)]
    struct HeaderItem {
        label: String,
        value: String,
    }

    let mut geo_location_items = Vec::new();
    if cf_ipcountry.as_deref().unwrap_or("—") != "—" {
        geo_location_items.push(HeaderItem {
            label: "CF-IPCountry".to_string(),
            value: sanitize_header(cf_ipcountry.clone()),
        });
    }
    if x_cf_country.as_deref().unwrap_or("—") != "—" {
        geo_location_items.push(HeaderItem {
            label: "Country".to_string(),
            value: sanitize_header(x_cf_country.clone()),
        });
    }
    if x_cf_city.as_deref().unwrap_or("—") != "—" {
        geo_location_items.push(HeaderItem {
            label: "City".to_string(),
            value: sanitize_header(x_cf_city.clone()),
        });
    }
    if x_cf_region.as_deref().unwrap_or("—") != "—" {
        geo_location_items.push(HeaderItem {
            label: "Region".to_string(),
            value: sanitize_header(x_cf_region.clone()),
        });
    }
    if x_cf_region_code.as_deref().unwrap_or("—") != "—" {
        geo_location_items.push(HeaderItem {
            label: "Region-Code".to_string(),
            value: sanitize_header(x_cf_region_code.clone()),
        });
    }
    if x_cf_continent.as_deref().unwrap_or("—") != "—" {
        geo_location_items.push(HeaderItem {
            label: "Continent".to_string(),
            value: sanitize_header(x_cf_continent.clone()),
        });
    }
    if x_cf_latitude.as_deref().unwrap_or("—") != "—" {
        geo_location_items.push(HeaderItem {
            label: "Latitude".to_string(),
            value: sanitize_header(x_cf_latitude.clone()),
        });
    }
    if x_cf_longitude.as_deref().unwrap_or("—") != "—" {
        geo_location_items.push(HeaderItem {
            label: "Longitude".to_string(),
            value: sanitize_header(x_cf_longitude.clone()),
        });
    }
    if x_cf_postal_code.as_deref().unwrap_or("—") != "—" {
        geo_location_items.push(HeaderItem {
            label: "Postal-Code".to_string(),
            value: sanitize_header(x_cf_postal_code.clone()),
        });
    }
    if x_cf_timezone.as_deref().unwrap_or("—") != "—" {
        geo_location_items.push(HeaderItem {
            label: "Timezone".to_string(),
            value: sanitize_header(x_cf_timezone.clone()),
        });
    }
    context.insert("geo_location_items", &geo_location_items);

    let mut network_items = Vec::new();
    if x_cf_asn.as_deref().unwrap_or("—") != "—" {
        network_items.push(HeaderItem {
            label: "ASN".to_string(),
            value: sanitize_header(x_cf_asn.clone()),
        });
    }
    if x_cf_as_organization.as_deref().unwrap_or("—") != "—" {
        network_items.push(HeaderItem {
            label: "AS-Organization".to_string(),
            value: sanitize_header(x_cf_as_organization.clone()),
        });
    }
    if x_cf_colo.as_deref().unwrap_or("—") != "—" {
        network_items.push(HeaderItem {
            label: "Colo".to_string(),
            value: sanitize_header(x_cf_colo.clone()),
        });
    }
    context.insert("network_items", &network_items);

    let mut connection_items = Vec::new();
    if cf_visitor.as_deref().unwrap_or("—") != "—" {
        connection_items.push(HeaderItem {
            label: "CF-Visitor".to_string(),
            value: sanitize_header(cf_visitor.clone()),
        });
    }
    if x_forwarded_proto.as_deref().unwrap_or("—") != "—" {
        connection_items.push(HeaderItem {
            label: "X-Forwarded-Proto".to_string(),
            value: sanitize_header(x_forwarded_proto.clone()),
        });
    }
    if x_cf_http_protocol.as_deref().unwrap_or("—") != "—" {
        connection_items.push(HeaderItem {
            label: "HTTP-Protocol".to_string(),
            value: sanitize_header(x_cf_http_protocol.clone()),
        });
    }
    if x_cf_tls_version.as_deref().unwrap_or("—") != "—" {
        connection_items.push(HeaderItem {
            label: "TLS-Version".to_string(),
            value: sanitize_header(x_cf_tls_version.clone()),
        });
    }
    if x_cf_tls_cipher.as_deref().unwrap_or("—") != "—" {
        connection_items.push(HeaderItem {
            label: "TLS-Cipher".to_string(),
            value: sanitize_header(x_cf_tls_cipher.clone()),
        });
    }
    context.insert("connection_items", &connection_items);

    let mut security_items = Vec::new();
    if x_cf_trust_score.as_deref().unwrap_or("—") != "—" {
        security_items.push(HeaderItem {
            label: "Trust-Score".to_string(),
            value: sanitize_header(x_cf_trust_score.clone()),
        });
    }
    if x_cf_bot_score.as_deref().unwrap_or("—") != "—" {
        security_items.push(HeaderItem {
            label: "Bot-Score".to_string(),
            value: sanitize_header(x_cf_bot_score.clone()),
        });
    }
    if x_cf_verified_bot.as_deref().unwrap_or("—") != "—" {
        security_items.push(HeaderItem {
            label: "Verified-Bot".to_string(),
            value: sanitize_header(x_cf_verified_bot.clone()),
        });
    }
    context.insert("security_items", &security_items);

    let mut proxy_items = Vec::new();
    if x_forwarded_for.as_deref().unwrap_or("—") != "—" {
        proxy_items.push(HeaderItem {
            label: "X-Forwarded-For".to_string(),
            value: sanitize_header(x_forwarded_for.clone()),
        });
    }
    if x_real_ip.as_deref().unwrap_or("—") != "—" {
        proxy_items.push(HeaderItem {
            label: "X-Real-IP".to_string(),
            value: sanitize_header(x_real_ip.clone()),
        });
    }
    context.insert("proxy_items", &proxy_items);

    // Client information
    context.insert("user_agent", &sanitize_header(client.user_agent.clone()));
    context.insert(
        "accept_language",
        &sanitize_header(client.accept_language.clone()),
    );
    context.insert(
        "accept_encoding",
        &sanitize_header(client.accept_encoding.clone()),
    );
    context.insert(
        "sec_ch_ua",
        &sanitize_header(client.client_hints.sec_ch_ua.clone()),
    );
    context.insert(
        "sec_ch_ua_platform",
        &sanitize_header(client.client_hints.sec_ch_ua_platform.clone()),
    );

    // Server information
    context.insert("timestamp", &server.timestamp_utc);
    context.insert("version", &server.version);
    context.insert("region", &server.region.as_deref().unwrap_or("—"));
    context.insert("privacy_mode", &privacy.mode);

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
        .body(html)
        .unwrap()
}

pub async fn privacy_handler() -> impl IntoResponse {
    // Initialize Tera template engine
    let tera = match Tera::new("templates/**/*.tera") {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to initialize Tera: {}", e);
            return Response::builder()
                .status(500)
                .header("Content-Type", "text/plain")
                .body(String::from("Internal server error"))
                .unwrap();
        }
    };

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

pub async fn plain_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let ctx = extract_client_context(&headers).map_err(|e| AppError::Cf(e.to_string()))?;

    let asn_info = state.asn_db.lookup(ctx.ip);

    // Extract Cloudflare Worker headers
    let x_cf_http_protocol = headers
        .get("X-CF-HTTP-Protocol")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_tls_version = headers
        .get("X-CF-TLS-Version")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let x_cf_tls_cipher = headers
        .get("X-CF-TLS-Cipher")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let cf_visitor = headers
        .get("CF-Visitor")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let cf_ipcountry = headers
        .get("CF-IPCountry")
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
    let x_forwarded_proto = headers
        .get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Extract Cloudflare Worker headers - Geo Location
    let x_cf_country = headers
        .get("X-CF-Country")
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

    let mut out = String::new();
    use std::fmt::Write;

    writeln!(&mut out, "IP: {} (IPv{})", ctx.ip, ctx.ip_version).ok();

    if let Some(a) = asn_info {
        writeln!(
            &mut out,
            "ASN: AS{} {} ({}, {}, {})",
            a.asn,
            a.as_name,
            a.prefix,
            a.rir,
            a.country.unwrap_or_else(|| "-".into())
        )
        .ok();
    }

    // Connection details - prioritize CF worker headers
    let tls_version = x_cf_tls_version
        .as_ref()
        .filter(|v| !v.is_empty())
        .or(ctx.tls_version.as_ref());
    let http_protocol = x_cf_http_protocol
        .as_ref()
        .filter(|v| !v.is_empty())
        .or(ctx.http_protocol.as_ref());

    if let Some(tls) = tls_version {
        let proto = http_protocol.map(|s| s.as_str()).unwrap_or("-");
        writeln!(&mut out, "TLS: {} over {}", tls, proto).ok();
    }

    if let Some(cipher) = x_cf_tls_cipher.as_ref() {
        if !cipher.is_empty() {
            writeln!(&mut out, "TLS-Cipher: {}", cipher).ok();
        }
    }

    if let Some(ray) = ctx.cf_ray.as_ref() {
        writeln!(&mut out, "CF-Ray: {}", ray).ok();
    }

    if let Some(dc) = ctx.cf_datacenter.as_ref() {
        writeln!(&mut out, "Datacenter: {}", dc).ok();
    }

    if let Some(req_id) = cf_request_id.as_ref() {
        writeln!(&mut out, "CF-Request-ID: {}", req_id).ok();
    }

    if let Some(cache) = cf_cache_status.as_ref() {
        writeln!(&mut out, "CF-Cache-Status: {}", cache).ok();
    }

    // Cloudflare Headers - Geo Location
    if cf_ipcountry.is_some() || x_cf_country.is_some() || x_cf_city.is_some() {
        writeln!(&mut out, "\n=== Cloudflare Client Info ===").ok();
        writeln!(&mut out, "--- Geo Location ---").ok();
        if let Some(c) = cf_ipcountry.as_ref() {
            writeln!(&mut out, "Country: {}", c).ok();
        }
        if let Some(c) = x_cf_country.as_ref() {
            writeln!(&mut out, "Country: {}", c).ok();
        }
        if let Some(c) = x_cf_city.as_ref() {
            writeln!(&mut out, "City: {}", c).ok();
        }
        if let Some(c) = x_cf_region.as_ref() {
            writeln!(&mut out, "Region: {}", c).ok();
        }
        if let Some(c) = x_cf_region_code.as_ref() {
            writeln!(&mut out, "Region-Code: {}", c).ok();
        }
        if let Some(c) = x_cf_continent.as_ref() {
            writeln!(&mut out, "Continent: {}", c).ok();
        }
        if let Some(c) = x_cf_latitude.as_ref() {
            writeln!(&mut out, "Latitude: {}", c).ok();
        }
        if let Some(c) = x_cf_longitude.as_ref() {
            writeln!(&mut out, "Longitude: {}", c).ok();
        }
        if let Some(c) = x_cf_postal_code.as_ref() {
            writeln!(&mut out, "Postal-Code: {}", c).ok();
        }
        if let Some(c) = x_cf_timezone.as_ref() {
            writeln!(&mut out, "Timezone: {}", c).ok();
        }
    }

    // Network
    if x_cf_asn.is_some() || x_cf_as_organization.is_some() || x_cf_colo.is_some() {
        writeln!(&mut out, "--- Network ---").ok();
        if let Some(a) = x_cf_asn.as_ref() {
            writeln!(&mut out, "ASN: {}", a).ok();
        }
        if let Some(a) = x_cf_as_organization.as_ref() {
            writeln!(&mut out, "AS-Organization: {}", a).ok();
        }
        if let Some(c) = x_cf_colo.as_ref() {
            writeln!(&mut out, "Colo: {}", c).ok();
        }
    }

    // Connection
    if cf_visitor.is_some() || x_forwarded_proto.is_some() || x_cf_http_protocol.is_some() {
        writeln!(&mut out, "--- Connection ---").ok();
        if let Some(v) = cf_visitor.as_ref() {
            writeln!(&mut out, "CF-Visitor: {}", v).ok();
        }
        if let Some(p) = x_forwarded_proto.as_ref() {
            writeln!(&mut out, "X-Forwarded-Proto: {}", p).ok();
        }
        if let Some(p) = x_cf_http_protocol.as_ref() {
            writeln!(&mut out, "HTTP-Protocol: {}", p).ok();
        }
        if let Some(t) = x_cf_tls_version.as_ref() {
            writeln!(&mut out, "TLS-Version: {}", t).ok();
        }
        if let Some(c) = x_cf_tls_cipher.as_ref() {
            writeln!(&mut out, "TLS-Cipher: {}", c).ok();
        }
    }

    // Security
    if x_cf_trust_score.is_some() || x_cf_bot_score.is_some() || x_cf_verified_bot.is_some() {
        writeln!(&mut out, "--- Security ---").ok();
        if let Some(s) = x_cf_trust_score.as_ref() {
            writeln!(&mut out, "Trust-Score: {}", s).ok();
        }
        if let Some(s) = x_cf_bot_score.as_ref() {
            writeln!(&mut out, "Bot-Score: {}", s).ok();
        }
        if let Some(s) = x_cf_verified_bot.as_ref() {
            writeln!(&mut out, "Verified-Bot: {}", s).ok();
        }
    }

    // Proxy Headers
    if x_forwarded_for.is_some() || x_real_ip.is_some() {
        writeln!(&mut out, "--- Proxy Headers ---").ok();
        if let Some(f) = x_forwarded_for.as_ref() {
            writeln!(&mut out, "X-Forwarded-For: {}", f).ok();
        }
        if let Some(r) = x_real_ip.as_ref() {
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
    if let Some(sec_ch_ua) = headers.get("Sec-CH-UA").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "Sec-CH-UA: {}", sec_ch_ua).ok();
    }
    if let Some(sec_ch_ua_platform) = headers
        .get("Sec-CH-UA-Platform")
        .and_then(|v| v.to_str().ok())
    {
        writeln!(&mut out, "Sec-CH-UA-Platform: {}", sec_ch_ua_platform).ok();
    }

    Ok(out)
}

pub async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}
