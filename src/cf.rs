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
    #[error("missing CF-Connecting-IP header")]
    MissingConnectingIp,
    #[error("invalid IP in CF-Connecting-IP header")]
    InvalidIp,
}

pub fn extract_client_context(headers: &HeaderMap) -> Result<ClientContext, CfError> {
    let cf_connecting_ip = headers
        .get("CF-Connecting-IP")
        .ok_or(CfError::MissingConnectingIp)?
        .to_str()
        .map_err(|_| CfError::InvalidIp)?;

    let ip: IpAddr = cf_connecting_ip.parse().map_err(|_| CfError::InvalidIp)?;

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

    let (tls_version, http_protocol);

    if let Some(visitor_hdr) = headers.get("CF-Visitor") {
        if let Ok(v) = visitor_hdr.to_str() {
            let parsed: Result<CfVisitor, _> = serde_json::from_str(v);
            if let Ok(v) = parsed {
                tls_version = v.tls;
                http_protocol = v.http_protocol;
            } else {
                tls_version = None;
                http_protocol = None;
            }
        } else {
            tls_version = None;
            http_protocol = None;
        }
    } else {
        tls_version = None;
        http_protocol = None;
    }

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
