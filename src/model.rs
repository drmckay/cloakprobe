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
                org_name: a.org_name,
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
    pub cf_ray: Option<String>,
    pub datacenter: Option<String>,
}

#[derive(Serialize)]
pub struct ClientHints {
    pub sec_ch_ua: Option<String>,
    pub sec_ch_ua_platform: Option<String>,
}

#[derive(Serialize)]
pub struct ClientInfo {
    pub user_agent: Option<String>,
    pub accept_language: Option<String>,
    pub accept_encoding: Option<String>,
    pub client_hints: ClientHints,
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
}
