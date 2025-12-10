use crate::asn::AsnInfo;
use crate::config::PrivacyMode;
use serde::Serialize;

#[derive(Serialize)]
pub struct NetworkInfo {
    pub asn: Option<u32>,
    pub as_name: Option<String>,
    pub prefix: Option<String>,
    pub rir: Option<String>,
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_rir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abuse_contact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_last_updated: Option<String>,
    pub tor_exit: bool,
    pub vpn_or_hosting: bool,
}

impl NetworkInfo {
    pub fn from_asn(asn: Option<AsnInfo>) -> Self {
        if let Some(a) = asn {
            Self {
                asn: Some(a.asn),
                as_name: Some(a.as_name),
                prefix: Some(a.prefix),
                rir: Some(a.rir),
                country: a.country,
                org_name: a.org.as_ref().and_then(|o| o.org_name.clone()),
                org_id: a.org.as_ref().and_then(|o| o.org_id.clone()),
                org_country: a.org.as_ref().and_then(|o| o.country.clone()),
                org_rir: a.org.as_ref().and_then(|o| o.rir.clone()),
                org_type: a.org.as_ref().and_then(|o| o.org_type.clone()),
                abuse_contact: a.org.as_ref().and_then(|o| o.abuse_contact.clone()),
                org_last_updated: a.org.as_ref().and_then(|o| o.last_updated.clone()),
                tor_exit: false,
                vpn_or_hosting: false,
            }
        } else {
            Self {
                asn: None,
                as_name: None,
                prefix: None,
                rir: None,
                country: None,
                org_name: None,
                org_id: None,
                org_country: None,
                org_rir: None,
                org_type: None,
                abuse_contact: None,
                org_last_updated: None,
                tor_exit: false,
                vpn_or_hosting: false,
            }
        }
    }
}

#[derive(Serialize)]
pub struct ConnectionInfo {
    pub tls_version: Option<String>,
    pub http_protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cipher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cf_ray: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datacenter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
}

#[derive(Serialize)]
pub struct ClientHints {
    pub sec_ch_ua: Option<String>,
    pub sec_ch_ua_platform: Option<String>,
    pub sec_ch_ua_mobile: Option<String>,
    pub sec_ch_ua_full_version_list: Option<String>,
    pub device_memory: Option<String>,
    pub viewport_width: Option<String>,
    pub downlink: Option<String>,
    pub rtt: Option<String>,
    pub ect: Option<String>,
}

#[derive(Serialize)]
pub struct SecFetchHeaders {
    pub site: Option<String>,
    pub mode: Option<String>,
    pub dest: Option<String>,
    pub user: Option<String>,
}

#[derive(Serialize)]
pub struct ClientInfo {
    pub user_agent: Option<String>,
    pub accept_language: Option<String>,
    pub accept_encoding: Option<String>,
    pub dnt: Option<String>,
    pub sec_gpc: Option<String>,
    pub save_data: Option<String>,
    pub upgrade_insecure_requests: Option<String>,
    pub referer: Option<String>,
    pub origin: Option<String>,
    pub client_hints: ClientHints,
    pub sec_fetch: SecFetchHeaders,
}

#[derive(Serialize)]
pub struct PrivacyInfo {
    pub mode: String,
    pub logs_retained: bool,
}

impl From<&PrivacyMode> for PrivacyInfo {
    fn from(mode: &PrivacyMode) -> Self {
        let mode_str = match mode {
            PrivacyMode::Strict => "strict",
            PrivacyMode::Balanced => "balanced",
        }
        .to_string();

        let logs_retained = matches!(mode, PrivacyMode::Balanced);

        Self {
            mode: mode_str,
            logs_retained,
        }
    }
}

#[derive(Serialize)]
pub struct ServerInfo {
    pub timestamp_utc: String,
    pub region: Option<String>,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<f64>,
}

#[derive(Serialize, Default)]
pub struct CloudflareGeoHeaders {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

#[derive(Serialize, Default)]
pub struct CloudflareNetworkHeaders {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub as_organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub colo: Option<String>,
}

#[derive(Serialize, Default)]
pub struct CloudflareConnectionHeaders {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cf_visitor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_forwarded_proto: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cipher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cf_request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cf_cache_status: Option<String>,
}

#[derive(Serialize, Default)]
pub struct CloudflareSecurityHeaders {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_score: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bot_score: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_bot: Option<String>,
}

#[derive(Serialize, Default)]
pub struct CloudflareProxyHeaders {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_forwarded_for: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_real_ip: Option<String>,
}

/// Nginx GeoIP headers (optional, requires nginx geoip module)
#[derive(Serialize, Default)]
pub struct NginxGeoHeaders {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latitude: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub longitude: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
}

/// Nginx-specific headers container for JSON output
#[derive(Serialize, Default)]
pub struct NginxHeaders {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo: Option<NginxGeoHeaders>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<CloudflareProxyHeaders>,
}

#[derive(Serialize, Default)]
pub struct CloudflareHeaders {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub geo: Option<CloudflareGeoHeaders>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<CloudflareNetworkHeaders>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection: Option<CloudflareConnectionHeaders>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security: Option<CloudflareSecurityHeaders>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<CloudflareProxyHeaders>,
}

#[derive(Serialize)]
pub struct InfoResponse {
    pub ip: String,
    pub ip_version: u8,
    pub reverse_dns: Option<String>,
    pub network: NetworkInfo,
    pub connection: ConnectionInfo,
    pub client: ClientInfo,
    pub privacy: PrivacyInfo,
    pub server: ServerInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudflare: Option<CloudflareHeaders>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nginx: Option<NginxHeaders>,
}
