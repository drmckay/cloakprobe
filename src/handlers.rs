use crate::asn::AsnDatabase;
use crate::cf::extract_client_context;
use crate::config::{AppConfig, ProxyMode};
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
use std::time::Instant;
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

/// Extracts connection headers based on proxy mode.
/// Nginx mode: X-TLS-Version, X-TLS-Cipher, X-HTTP-Protocol
/// Cloudflare mode: X-CF-TLS-Version, X-CF-TLS-Cipher, X-CF-HTTP-Protocol
fn extract_connection_headers(
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

/// Nginx-specific extracted headers container (internal use)
struct NginxExtractedHeaders {
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
fn extract_nginx_headers(headers: &HeaderMap) -> NginxExtractedHeaders {
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

/// Converts DNT header value to human-readable format.
/// "1" -> "Enabled", "0" -> "Disabled", other/missing -> None
fn format_dnt(value: Option<String>) -> Option<String> {
    value.and_then(|v| match v.trim() {
        "1" => Some("Enabled".to_string()),
        "0" => Some("Disabled".to_string()),
        _ => None,
    })
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
        tls_version: x_tls_version
            .as_ref()
            .filter(|v| !v.is_empty())
            .or(ctx.tls_version.as_ref())
            .and_then(|v| sanitize_for_json(Some(v.clone()))),
        http_protocol: x_http_protocol
            .as_ref()
            .filter(|v| !v.is_empty())
            .or(ctx.http_protocol.as_ref())
            .and_then(|v| sanitize_for_json(Some(v.clone()))),
        tls_cipher: sanitize_for_json(x_tls_cipher.clone()),
        cf_ray: if is_cloudflare_mode {
            sanitize_for_json(ctx.cf_ray.clone())
        } else {
            None
        },
        datacenter: if is_cloudflare_mode {
            sanitize_for_json(ctx.cf_datacenter.clone())
        } else {
            None
        },
        request_id: nginx_headers
            .as_ref()
            .and_then(|h| sanitize_for_json(h.request_id.clone())),
        remote_port: nginx_headers
            .as_ref()
            .and_then(|h| sanitize_for_json(h.remote_port.clone())),
        connection_id: nginx_headers
            .as_ref()
            .and_then(|h| sanitize_for_json(h.connection_id.clone())),
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
            user_agent: sanitize_for_json(ua),
            accept_language: sanitize_for_json(accept_language),
            accept_encoding: sanitize_for_json(accept_encoding),
            dnt: format_dnt(dnt),
            sec_gpc: format_dnt(sec_gpc),
            save_data: sanitize_for_json(save_data),
            upgrade_insecure_requests: sanitize_for_json(upgrade_insecure_requests),
            referer: sanitize_for_json(referer),
            origin: sanitize_for_json(origin),
            client_hints: ClientHints {
                sec_ch_ua: sanitize_for_json(sec_ch_ua),
                sec_ch_ua_platform: sanitize_for_json(sec_ch_ua_platform),
                sec_ch_ua_mobile: sanitize_for_json(sec_ch_ua_mobile),
                sec_ch_ua_full_version_list: sanitize_for_json(sec_ch_ua_full_version_list),
                device_memory: sanitize_for_json(device_memory),
                viewport_width: sanitize_for_json(viewport_width),
                downlink: sanitize_for_json(downlink),
                rtt: sanitize_for_json(rtt),
                ect: sanitize_for_json(ect),
            },
            sec_fetch: SecFetchHeaders {
                site: sanitize_for_json(sec_fetch_site),
                mode: sanitize_for_json(sec_fetch_mode),
                dest: sanitize_for_json(sec_fetch_dest),
                user: sanitize_for_json(sec_fetch_user),
            },
        }
    };

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
    if cf_ipcountry.is_some() || x_cf_city.is_some() {
        geo.country = sanitize_for_json(cf_ipcountry);
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
        || x_http_protocol.is_some()
        || x_tls_version.is_some()
        || x_tls_cipher.is_some()
        || cf_request_id.is_some()
        || cf_cache_status.is_some()
    {
        connection_headers.cf_visitor = sanitize_for_json(cf_visitor);
        connection_headers.x_forwarded_proto = sanitize_for_json(x_forwarded_proto);
        connection_headers.http_protocol = sanitize_for_json(x_http_protocol);
        connection_headers.tls_version = sanitize_for_json(x_tls_version);
        connection_headers.tls_cipher = sanitize_for_json(x_tls_cipher);
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

    // Save proxy values for nginx use before moving into cloudflare
    let proxy_forwarded_for = proxy.x_forwarded_for.clone();
    let proxy_real_ip = proxy.x_real_ip.clone();

    let cloudflare = if geo.country.is_some()
        || network_headers.asn.is_some()
        || connection_headers.cf_visitor.is_some()
        || security.trust_score.is_some()
        || proxy.x_forwarded_for.is_some()
    {
        Some(CloudflareHeaders {
            geo: if geo.country.is_some() {
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

    // Build nginx headers structure (only in nginx mode)
    let nginx = if !is_cloudflare_mode {
        let nginx_h = nginx_headers.as_ref();

        // Build GeoIP structure if any geo headers present
        let has_geoip = nginx_h.is_some_and(|h| {
            h.geoip_country.is_some()
                || h.geoip_city.is_some()
                || h.geoip_region.is_some()
                || h.geoip_latitude.is_some()
                || h.geoip_longitude.is_some()
                || h.geoip_postal_code.is_some()
                || h.geoip_org.is_some()
        });

        let nginx_geo = if has_geoip {
            Some(NginxGeoHeaders {
                country: nginx_h.and_then(|h| sanitize_for_json(h.geoip_country.clone())),
                city: nginx_h.and_then(|h| sanitize_for_json(h.geoip_city.clone())),
                region: nginx_h.and_then(|h| sanitize_for_json(h.geoip_region.clone())),
                latitude: nginx_h.and_then(|h| sanitize_for_json(h.geoip_latitude.clone())),
                longitude: nginx_h.and_then(|h| sanitize_for_json(h.geoip_longitude.clone())),
                postal_code: nginx_h.and_then(|h| sanitize_for_json(h.geoip_postal_code.clone())),
                org: nginx_h.and_then(|h| sanitize_for_json(h.geoip_org.clone())),
            })
        } else {
            None
        };

        // Use saved proxy values
        let nginx_proxy = if proxy_forwarded_for.is_some() || proxy_real_ip.is_some() {
            Some(CloudflareProxyHeaders {
                x_forwarded_for: proxy_forwarded_for.clone(),
                x_real_ip: proxy_real_ip.clone(),
            })
        } else {
            None
        };

        if nginx_geo.is_some() || nginx_proxy.is_some() {
            Some(NginxHeaders {
                geo: nginx_geo,
                proxy: nginx_proxy,
            })
        } else {
            None
        }
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

    let json = serde_json::to_string_pretty(&resp).map_err(|e| AppError::Cf(e.to_string()))?;

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
        user_agent: ua,
        accept_language,
        accept_encoding,
        dnt: format_dnt(dnt),
        sec_gpc: format_dnt(sec_gpc),
        save_data,
        upgrade_insecure_requests,
        referer,
        origin,
        client_hints: ClientHints {
            sec_ch_ua,
            sec_ch_ua_platform,
            sec_ch_ua_mobile,
            sec_ch_ua_full_version_list,
            device_memory,
            viewport_width,
            downlink,
            rtt,
            ect,
        },
        sec_fetch: SecFetchHeaders {
            site: sec_fetch_site,
            mode: sec_fetch_mode,
            dest: sec_fetch_dest,
            user: sec_fetch_user,
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

/// IP address details with version-appropriate fields
struct IpDetails {
    /// Primary display format (dotted decimal for IPv4, standard notation for IPv6)
    primary: String,
    /// Hexadecimal format
    hex: String,
    /// Full expanded format (for IPv6 only, same as primary for IPv4)
    expanded: String,
    /// Binary format
    binary: String,
    /// Numeric value (u32 decimal for IPv4, empty for IPv6)
    numeric: String,
    /// /24 subnet for IPv4 or /64 network for IPv6
    subnet: String,
    /// Human-readable subnet size
    subnet_size: String,
    /// Address type (Public, Private, Global Unicast, etc.)
    ip_type: String,
}

fn get_ip_details(ip: &std::net::IpAddr) -> IpDetails {
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

            // Calculate /24 subnet
            let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);

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

            IpDetails {
                primary: decimal,
                hex,
                expanded: "".to_string(), // Not used for IPv4
                binary,
                numeric: format!("{}", u32_val),
                subnet,
                subnet_size: "256 addresses".to_string(),
                ip_type: ip_type.to_string(),
            }
        }
        std::net::IpAddr::V6(v6) => {
            let segments = v6.segments();

            // Standard (compressed) notation
            let standard = v6.to_string();

            // Full expanded notation
            let expanded = segments
                .iter()
                .map(|s| format!("{:04x}", s))
                .collect::<Vec<_>>()
                .join(":");

            let binary = segments
                .iter()
                .map(|s| format!("{:016b}", s))
                .collect::<Vec<_>>()
                .join(":");

            // Calculate /64 network (standard IPv6 subnet)
            let subnet = format!(
                "{:04x}:{:04x}:{:04x}:{:04x}::/64",
                segments[0], segments[1], segments[2], segments[3]
            );

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

            IpDetails {
                primary: standard,
                hex: "".to_string(), // Not meaningful for IPv6 (already hex)
                expanded,
                binary,
                numeric: "".to_string(), // 39-digit number not useful
                subnet,
                subnet_size: "18.4 quintillion addresses".to_string(),
                ip_type: ip_type.to_string(),
            }
        }
    }
}

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
            subnet: "—".into(),
            subnet_size: "—".into(),
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

    // Extract connection headers based on proxy mode
    let (x_tls_version, x_tls_cipher, x_http_protocol) =
        extract_connection_headers(&headers, &state.config.proxy_mode);

    // Check if we're in cloudflare mode for conditional display
    let is_cloudflare_mode = state.config.proxy_mode == ProxyMode::Cloudflare;

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
    context.insert("ip_type", &ip_details.ip_type);
    context.insert("ip_primary", &ip_details.primary);
    context.insert("ip_hex", &ip_details.hex);
    context.insert("ip_expanded", &ip_details.expanded);
    context.insert("ip_binary", &ip_details.binary);
    context.insert("ip_numeric", &ip_details.numeric);
    context.insert("ip_subnet", &ip_details.subnet);
    context.insert("ip_subnet_size", &ip_details.subnet_size);

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
    // RIR now uses org_rir value (no separate rir field needed)
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

    // Connection details - use mode-aware headers
    let tls_version_display = x_tls_version
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

    let http_protocol_display = x_http_protocol
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
    context.insert("tls_cipher", &sanitize_header(x_tls_cipher.clone()));

    // Pass proxy mode to template for conditional display
    context.insert("is_cloudflare_mode", &is_cloudflare_mode);

    // CF-Ray and Datacenter are only meaningful in Cloudflare mode
    context.insert(
        "cf_ray",
        &if is_cloudflare_mode {
            connection
                .as_ref()
                .and_then(|c| c.cf_ray.as_ref())
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
                .as_ref()
                .and_then(|c| c.datacenter.as_ref())
                .map(|v| sanitize_header(Some(v.clone())))
                .unwrap_or_else(|| "—".to_string())
        } else {
            "—".to_string()
        },
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

    // Nginx-specific context variables (only populated in nginx mode)
    context.insert(
        "request_id",
        &connection
            .as_ref()
            .and_then(|c| c.request_id.as_ref())
            .map(|v| sanitize_header(Some(v.clone())))
            .unwrap_or_else(|| "—".to_string()),
    );
    context.insert(
        "remote_port",
        &connection
            .as_ref()
            .and_then(|c| c.remote_port.as_ref())
            .map(|v| sanitize_header(Some(v.clone())))
            .unwrap_or_else(|| "—".to_string()),
    );
    context.insert(
        "connection_id",
        &connection
            .as_ref()
            .and_then(|c| c.connection_id.as_ref())
            .map(|v| sanitize_header(Some(v.clone())))
            .unwrap_or_else(|| "—".to_string()),
    );

    // Nginx GeoIP context variables
    context.insert(
        "geoip_country",
        &nginx_headers
            .as_ref()
            .and_then(|h| h.geoip_country.as_ref())
            .map(|v| sanitize_header(Some(v.clone())))
            .unwrap_or_else(|| "—".to_string()),
    );
    context.insert(
        "geoip_city",
        &nginx_headers
            .as_ref()
            .and_then(|h| h.geoip_city.as_ref())
            .map(|v| sanitize_header(Some(v.clone())))
            .unwrap_or_else(|| "—".to_string()),
    );
    context.insert(
        "geoip_region",
        &nginx_headers
            .as_ref()
            .and_then(|h| h.geoip_region.as_ref())
            .map(|v| sanitize_header(Some(v.clone())))
            .unwrap_or_else(|| "—".to_string()),
    );
    context.insert(
        "geoip_latitude",
        &nginx_headers
            .as_ref()
            .and_then(|h| h.geoip_latitude.as_ref())
            .map(|v| sanitize_header(Some(v.clone())))
            .unwrap_or_else(|| "—".to_string()),
    );
    context.insert(
        "geoip_longitude",
        &nginx_headers
            .as_ref()
            .and_then(|h| h.geoip_longitude.as_ref())
            .map(|v| sanitize_header(Some(v.clone())))
            .unwrap_or_else(|| "—".to_string()),
    );
    context.insert(
        "geoip_postal_code",
        &nginx_headers
            .as_ref()
            .and_then(|h| h.geoip_postal_code.as_ref())
            .map(|v| sanitize_header(Some(v.clone())))
            .unwrap_or_else(|| "—".to_string()),
    );
    context.insert(
        "geoip_org",
        &nginx_headers
            .as_ref()
            .and_then(|h| h.geoip_org.as_ref())
            .map(|v| sanitize_header(Some(v.clone())))
            .unwrap_or_else(|| "—".to_string()),
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
            label: "Country".to_string(),
            value: sanitize_header(cf_ipcountry.clone()),
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
    if x_http_protocol.as_deref().unwrap_or("—") != "—" {
        connection_items.push(HeaderItem {
            label: "HTTP-Protocol".to_string(),
            value: sanitize_header(x_http_protocol.clone()),
        });
    }
    if x_tls_version.as_deref().unwrap_or("—") != "—" {
        connection_items.push(HeaderItem {
            label: "TLS-Version".to_string(),
            value: sanitize_header(x_tls_version.clone()),
        });
    }
    if x_tls_cipher.as_deref().unwrap_or("—") != "—" {
        connection_items.push(HeaderItem {
            label: "TLS-Cipher".to_string(),
            value: sanitize_header(x_tls_cipher.clone()),
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

    // Server information
    context.insert("timestamp", &server.timestamp_utc);
    context.insert("version", &server.version);
    context.insert("region", &server.region.as_deref().unwrap_or("—"));
    context.insert(
        "response_time_ms",
        &format!("{:.2}", server.response_time_ms.unwrap_or(0.0)),
    );
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
        .header(
            "Cache-Control",
            "no-store, no-cache, must-revalidate, max-age=0",
        )
        .header("Pragma", "no-cache")
        .header("Expires", "0")
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

    if let Some(a) = asn_info.as_ref() {
        // Use org_rir if available, otherwise fall back to a.rir
        let rir_display = a
            .org
            .as_ref()
            .and_then(|o| o.rir.as_ref())
            .map(|s| s.as_str())
            .unwrap_or_else(|| a.rir.as_str());

        writeln!(
            &mut out,
            "ASN: AS{} {} ({}, {}, {})",
            a.asn,
            a.as_name,
            a.prefix,
            rir_display,
            a.country.clone().unwrap_or_else(|| "-".into())
        )
        .ok();

        if let Some(org) = a.org.as_ref() {
            if let Some(name) = org.org_name.as_ref() {
                writeln!(&mut out, "Org: {}", name).ok();
            }
            if let Some(id) = org.org_id.as_ref() {
                writeln!(&mut out, "Org-ID: {}", id).ok();
            }
            // Org-RIR removed (now shown in main ASN line)
            // Org-Country removed (duplicates Country Code)
            if let Some(org_type) = org.org_type.as_ref() {
                writeln!(&mut out, "Org-Type: {}", org_type).ok();
            }
            if let Some(abuse) = org.abuse_contact.as_ref() {
                writeln!(&mut out, "Abuse: {}", abuse).ok();
            }
            if let Some(updated) = org.last_updated.as_ref() {
                writeln!(&mut out, "Org-Updated: {}", updated).ok();
            }
        }
    }

    // Connection details - use mode-aware headers
    let tls_version = x_tls_version
        .as_ref()
        .filter(|v| !v.is_empty())
        .or(ctx.tls_version.as_ref());
    let http_protocol = x_http_protocol
        .as_ref()
        .filter(|v| !v.is_empty())
        .or(ctx.http_protocol.as_ref());

    if let Some(tls) = tls_version {
        let proto = http_protocol.map(|s| s.as_str()).unwrap_or("-");
        writeln!(&mut out, "TLS: {} over {}", tls, proto).ok();
    }

    // CF-Ray and Datacenter only shown in Cloudflare mode
    if is_cloudflare_mode {
        if let Some(ray) = ctx.cf_ray.as_ref() {
            writeln!(&mut out, "CF-Ray: {}", ray).ok();
        }

        if let Some(dc) = ctx.cf_datacenter.as_ref() {
            writeln!(&mut out, "Datacenter: {}", dc).ok();
        }
    }

    if let Some(req_id) = cf_request_id.as_ref() {
        writeln!(&mut out, "CF-Request-ID: {}", req_id).ok();
    }

    if let Some(cache) = cf_cache_status.as_ref() {
        writeln!(&mut out, "CF-Cache-Status: {}", cache).ok();
    }

    // Cloudflare Headers - only show in cloudflare mode
    if is_cloudflare_mode {
        // Geo Location
        if cf_ipcountry.is_some() || x_cf_city.is_some() {
            writeln!(&mut out, "\n=== Cloudflare Client Info ===").ok();
            writeln!(&mut out, "--- Geo Location ---").ok();
            if let Some(c) = cf_ipcountry.as_ref() {
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
    }

    // Connection (only in Cloudflare mode)
    if is_cloudflare_mode
        && (cf_visitor.is_some() || x_forwarded_proto.is_some() || x_http_protocol.is_some())
    {
        writeln!(&mut out, "--- Connection ---").ok();
        if let Some(v) = cf_visitor.as_ref() {
            writeln!(&mut out, "CF-Visitor: {}", v).ok();
        }
        if let Some(p) = x_forwarded_proto.as_ref() {
            writeln!(&mut out, "X-Forwarded-Proto: {}", p).ok();
        }
        if let Some(p) = x_http_protocol.as_ref() {
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
        && (x_cf_trust_score.is_some() || x_cf_bot_score.is_some() || x_cf_verified_bot.is_some())
    {
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
    writeln!(&mut out, "\nResponse-Time: {:.2} ms", response_time_ms).ok();

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

pub async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}
