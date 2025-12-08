use crate::config::ProxyMode;
use axum::http::HeaderMap;
use serde::Deserialize;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub struct ClientContext {
    pub ip: IpAddr,
    pub ip_version: u8,
    pub cf_ray: Option<String>,
    pub cf_datacenter: Option<String>,
    #[allow(dead_code)]
    pub country: Option<String>,
    pub tls_version: Option<String>,
    pub http_protocol: Option<String>,
}

#[derive(Deserialize)]
struct CfVisitor {
    #[serde(default)]
    tls: Option<String>,
    #[serde(default, rename = "http_protocol")]
    http_protocol: Option<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum CfError {
    #[error("missing client IP header (CF-Connecting-IP for Cloudflare mode, X-Forwarded-For/X-Real-IP for nginx mode)")]
    MissingClientIp,
    #[error("invalid IP address in header")]
    InvalidIp,
}

/// Extract client context based on proxy mode
///
/// - Cloudflare mode: Uses CF-Connecting-IP header
/// - Nginx mode: Uses X-Real-IP or X-Forwarded-For header
pub fn extract_client_context(
    headers: &HeaderMap,
    mode: &ProxyMode,
) -> Result<ClientContext, CfError> {
    let ip = extract_client_ip(headers, mode)?;
    let ip_version = if ip.is_ipv4() { 4 } else { 6 };

    let cf_ray = headers
        .get("CF-Ray")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let cf_datacenter = headers
        .get("CF-RAY")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split('-').nth(1))
        .map(|s| s.to_string());

    let country = headers
        .get("CF-IPCountry")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let (tls_version, http_protocol) = extract_connection_info(headers);

    Ok(ClientContext {
        ip,
        ip_version,
        cf_ray,
        cf_datacenter,
        country,
        tls_version,
        http_protocol,
    })
}

/// Extract client IP address based on proxy mode
fn extract_client_ip(headers: &HeaderMap, mode: &ProxyMode) -> Result<IpAddr, CfError> {
    match mode {
        ProxyMode::Cloudflare => {
            // Trust CF-Connecting-IP header from Cloudflare
            let ip_str = headers
                .get("CF-Connecting-IP")
                .ok_or(CfError::MissingClientIp)?
                .to_str()
                .map_err(|_| CfError::InvalidIp)?;

            ip_str.parse().map_err(|_| CfError::InvalidIp)
        }
        ProxyMode::Nginx => {
            // Trust X-Real-IP first (most common nginx config)
            if let Some(real_ip) = headers.get("X-Real-IP") {
                if let Ok(ip_str) = real_ip.to_str() {
                    if let Ok(ip) = ip_str.trim().parse() {
                        return Ok(ip);
                    }
                }
            }

            // Fall back to X-Forwarded-For (first IP in the chain)
            if let Some(xff) = headers.get("X-Forwarded-For") {
                if let Ok(xff_str) = xff.to_str() {
                    // X-Forwarded-For can be: "client, proxy1, proxy2"
                    // First IP is the original client
                    if let Some(first_ip) = xff_str.split(',').next() {
                        if let Ok(ip) = first_ip.trim().parse() {
                            return Ok(ip);
                        }
                    }
                }
            }

            Err(CfError::MissingClientIp)
        }
    }
}

/// Extract TLS and HTTP protocol information from headers
fn extract_connection_info(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    // Try CF-Visitor header first (Cloudflare)
    if let Some(visitor_hdr) = headers.get("CF-Visitor") {
        if let Ok(v) = visitor_hdr.to_str() {
            if let Ok(parsed) = serde_json::from_str::<CfVisitor>(v) {
                return (parsed.tls, parsed.http_protocol);
            }
        }
    }

    // Fall back to individual headers (from Cloudflare Worker or nginx)
    let tls_version = headers
        .get("X-CF-TLS-Version")
        .or_else(|| headers.get("X-TLS-Version"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let http_protocol = headers
        .get("X-CF-HTTP-Protocol")
        .or_else(|| headers.get("X-HTTP-Protocol"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    (tls_version, http_protocol)
}
