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

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub asn_db: Arc<dyn AsnDatabase>,
}

pub async fn info_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<InfoResponse>, AppError> {
    let ctx = extract_client_context(&headers).map_err(|e| AppError::Cf(e.to_string()))?;

    let asn_info = state.asn_db.lookup(ctx.ip);

    let network = NetworkInfo::from_asn(asn_info);
    let connection = ConnectionInfo {
        tls_version: ctx.tls_version,
        http_protocol: ctx.http_protocol,
        cf_ray: ctx.cf_ray,
        datacenter: ctx.cf_datacenter,
    };

    let client = extract_client_info(&headers);
    let privacy = PrivacyInfo::from(&state.config.privacy_mode);
    let server = ServerInfo {
        timestamp_utc: Utc::now().to_rfc3339(),
        region: std::env::var("CLOAKPROBE_REGION")
            .or_else(|_| std::env::var("CFDEBUG_REGION"))
            .ok(),
        version: env!("CARGO_PKG_VERSION").to_string(),
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

    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>CloakProbe - {ip}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="CloakProbe - Your IP address and network information">
  <style>
    * {{
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }}
    :root {{
      color-scheme: dark;
      --bg-gradient-start: #0f172a;
      --bg-gradient-end: #020617;
      --card-bg: rgba(15, 23, 42, 0.95);
      --card-border: rgba(148, 163, 184, 0.2);
      --text-primary: #f9fafb;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --accent-primary: #22c55e;
      --accent-secondary: #0ea5e9;
      --accent-gradient: linear-gradient(135deg, #22c55e, #0ea5e9);
      --section-bg: rgba(30, 41, 59, 0.5);
    }}
    body {{
      background: radial-gradient(ellipse at top, var(--bg-gradient-start), var(--bg-gradient-end));
      color: var(--text-primary);
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      min-height: 100vh;
      padding: 2rem 1rem;
      line-height: 1.6;
    }}
    .container {{
      max-width: 1200px;
      margin: 0 auto;
    }}
    .header {{
      text-align: center;
      margin-bottom: 3rem;
    }}
    .header h1 {{
      font-size: clamp(2rem, 5vw, 3rem);
      font-weight: 800;
      background: var(--accent-gradient);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      margin-bottom: 0.5rem;
    }}
    .header p {{
      color: var(--text-secondary);
      font-size: 1.1rem;
    }}
    .ip-display {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 1.5rem;
      padding: 3rem 2rem;
      text-align: center;
      margin-bottom: 2rem;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
    }}
    .ip-label {{
      text-transform: uppercase;
      letter-spacing: 0.2em;
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-bottom: 1rem;
      font-weight: 600;
    }}
    .ip-value-container {{
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.75rem;
      margin-bottom: 0.5rem;
    }}
    .ip-value {{
      font-size: clamp(2.5rem, 6vw, 4rem);
      font-weight: 700;
      font-family: "SF Mono", "Monaco", "Cascadia Code", monospace;
    }}
    .copy-btn {{
      background: var(--section-bg);
      border: 1px solid var(--card-border);
      border-radius: 0.5rem;
      padding: 0.5rem;
      cursor: pointer;
      color: var(--text-secondary);
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      justify-content: center;
    }}
    .copy-btn:hover {{
      background: var(--card-border);
      color: var(--text-primary);
    }}
    .copy-btn:active {{
      transform: scale(0.95);
    }}
    .copy-btn.copied {{
      background: rgba(34, 197, 94, 0.2);
      color: var(--accent-primary);
      border-color: var(--accent-primary);
    }}
    .copy-btn svg {{
      width: 1.25rem;
      height: 1.25rem;
    }}
    .ip-version {{
      display: inline-block;
      background: var(--section-bg);
      padding: 0.25rem 0.75rem;
      border-radius: 999px;
      font-size: 0.875rem;
      color: var(--text-secondary);
      margin-top: 0.5rem;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 1.5rem;
      margin-bottom: 2rem;
    }}
    .card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 1rem;
      padding: 1.5rem;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
    }}
    .card-title {{
      font-size: 0.875rem;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: var(--text-muted);
      margin-bottom: 1rem;
      font-weight: 600;
    }}
    .info-row {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      padding: 0.75rem 0;
      border-bottom: 1px solid rgba(148, 163, 184, 0.1);
    }}
    .info-row:last-child {{
      border-bottom: none;
    }}
    .info-label {{
      color: var(--text-secondary);
      font-size: 0.9rem;
      flex: 0 0 40%;
    }}
    .info-value {{
      color: var(--text-primary);
      font-size: 0.9rem;
      text-align: right;
      flex: 1;
      font-weight: 500;
      word-break: break-word;
    }}
    .info-value code {{
      background: var(--section-bg);
      padding: 0.125rem 0.375rem;
      border-radius: 0.25rem;
      font-family: "SF Mono", "Monaco", "Cascadia Code", monospace;
      font-size: 0.85em;
    }}
    .badge {{
      display: inline-block;
      padding: 0.25rem 0.75rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      background: var(--section-bg);
      color: var(--text-secondary);
    }}
    .badge-success {{
      background: rgba(34, 197, 94, 0.2);
      color: var(--accent-primary);
    }}
    .badge-info {{
      background: rgba(14, 165, 233, 0.2);
      color: var(--accent-secondary);
    }}
    .footer {{
      text-align: center;
      padding: 2rem 0;
      color: var(--text-muted);
      font-size: 0.875rem;
    }}
    .footer a {{
      color: var(--accent-secondary);
      text-decoration: none;
    }}
    .footer a:hover {{
      text-decoration: underline;
    }}
    .empty-state {{
      color: var(--text-muted);
      font-style: italic;
      font-size: 0.9rem;
    }}
    @media (max-width: 768px) {{
      .grid {{
        grid-template-columns: 1fr;
      }}
      .ip-display {{
        padding: 2rem 1.5rem;
      }}
      body {{
        padding: 1rem 0.5rem;
      }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>CloakProbe</h1>
      <p>Your network details and connection information</p>
    </div>

    <div class="ip-display">
      <div class="ip-label">Your Public IP Address</div>
      <div class="ip-value-container">
        <div class="ip-value" id="ip-value">{ip}</div>
        <button class="copy-btn" onclick="copyIP()" title="Copy to clipboard">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
          </svg>
        </button>
      </div>
      <div class="ip-version">IPv{ip_version} • <span class="badge badge-info">{ip_type}</span></div>
    </div>

    <div class="grid">
      <div class="card">
        <div class="card-title">IP Address Details</div>
        <div class="info-row">
          <span class="info-label">Decimal Format</span>
          <span class="info-value"><code>{ip_decimal}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">Hexadecimal</span>
          <span class="info-value"><code>{ip_hex}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">Binary Format</span>
          <span class="info-value"><code style="font-size: 0.75em;">{ip_binary}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">Numeric Value</span>
          <span class="info-value"><code>{ip_numeric}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">Address Type</span>
          <span class="info-value"><span class="badge badge-info">{ip_type}</span></span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Network Information</div>
        <div class="info-row">
          <span class="info-label">ASN</span>
          <span class="info-value">{asn}</span>
        </div>
        <div class="info-row">
          <span class="info-label">AS Name</span>
          <span class="info-value">{as_name}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Network Prefix</span>
          <span class="info-value"><code>{prefix}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">RIR</span>
          <span class="info-value">{rir}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Country Code</span>
          <span class="info-value">{country}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Organization</span>
          <span class="info-value">{org_name}</span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Connection Details</div>
        <div class="info-row">
          <span class="info-label">TLS Version</span>
          <span class="info-value">{tls_version}</span>
        </div>
        <div class="info-row">
          <span class="info-label">HTTP Protocol</span>
          <span class="info-value"><code>{http_protocol}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">CF-Ray</span>
          <span class="info-value"><code>{cf_ray}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">Datacenter</span>
          <span class="info-value">{datacenter}</span>
        </div>
        <div class="info-row">
          <span class="info-label">CF-Request-ID</span>
          <span class="info-value"><code>{cf_request_id}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">CF-Cache-Status</span>
          <span class="info-value">{cf_cache_status}</span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Cloudflare Headers</div>
        <div class="info-row">
          <span class="info-label">CF-Visitor</span>
          <span class="info-value"><code>{cf_visitor}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">CF-IPCountry</span>
          <span class="info-value">{cf_ipcountry}</span>
        </div>
        <div class="info-row">
          <span class="info-label">X-Forwarded-For</span>
          <span class="info-value"><code>{x_forwarded_for}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">X-Real-IP</span>
          <span class="info-value"><code>{x_real_ip}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">X-Forwarded-Proto</span>
          <span class="info-value"><code>{x_forwarded_proto}</code></span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Client Information</div>
        <div class="info-row">
          <span class="info-label">User-Agent</span>
          <span class="info-value"><code style="font-size: 0.8em;">{user_agent}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">Accept-Language</span>
          <span class="info-value">{accept_language}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Accept-Encoding</span>
          <span class="info-value">{accept_encoding}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Sec-CH-UA</span>
          <span class="info-value"><code>{sec_ch_ua}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">Sec-CH-UA-Platform</span>
          <span class="info-value"><code>{sec_ch_ua_platform}</code></span>
        </div>
      </div>

      <div class="card">
        <div class="card-title">Server Information</div>
        <div class="info-row">
          <span class="info-label">Timestamp</span>
          <span class="info-value"><code>{timestamp}</code></span>
        </div>
        <div class="info-row">
          <span class="info-label">Version</span>
          <span class="info-value">{version}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Region</span>
          <span class="info-value">{region}</span>
        </div>
        <div class="info-row">
          <span class="info-label">Privacy Mode</span>
          <span class="info-value"><span class="badge badge-success">{privacy_mode}</span></span>
        </div>
      </div>
    </div>

    <div class="footer">
      <p>API endpoints: <a href="/api/v1/info">JSON</a> | <a href="/api/v1/plain">Plain text</a> | <a href="/healthz">Health</a></p>
      <p style="margin-top: 0.5rem;">No tracking • No ads • Privacy-focused</p>
    </div>
  </div>
  <script>
    function copyIP() {{
      const ip = document.getElementById('ip-value').textContent;
      navigator.clipboard.writeText(ip).then(function() {{
        const btn = document.querySelector('.copy-btn');
        btn.classList.add('copied');
        setTimeout(function() {{
          btn.classList.remove('copied');
        }}, 1500);
      }});
    }}
  </script>
</body>
</html>
"#,
        ip = ip_display,
        ip_version = ip_version,
        ip_type = ip_type,
        ip_decimal = ip_decimal,
        ip_hex = ip_hex,
        ip_binary = ip_binary,
        ip_numeric = ip_numeric,
        asn = network
            .asn
            .map(|a| format!("AS{}", a))
            .unwrap_or_else(|| "—".to_string()),
        as_name = network.as_name.as_ref().unwrap_or(&"—".to_string()),
        prefix = network.prefix.as_deref().unwrap_or("—"),
        rir = network.rir.as_ref().unwrap_or(&"—".to_string()),
        country = network.country.as_deref().unwrap_or("—"),
        org_name = network.org_name.as_deref().unwrap_or("—"),
        tls_version = connection
            .as_ref()
            .and_then(|c| c.tls_version.as_ref())
            .map(|v| v.as_str())
            .unwrap_or("—"),
        http_protocol = connection
            .as_ref()
            .and_then(|c| c.http_protocol.as_ref())
            .map(|v| v.as_str())
            .unwrap_or("—"),
        cf_ray = connection
            .as_ref()
            .and_then(|c| c.cf_ray.as_ref())
            .map(|v| v.as_str())
            .unwrap_or("—"),
        datacenter = connection
            .as_ref()
            .and_then(|c| c.datacenter.as_ref())
            .map(|v| v.as_str())
            .unwrap_or("—"),
        cf_request_id = cf_request_id.as_deref().unwrap_or("—"),
        cf_cache_status = cf_cache_status.as_deref().unwrap_or("—"),
        cf_visitor = cf_visitor.as_deref().unwrap_or("—"),
        cf_ipcountry = cf_ipcountry.as_deref().unwrap_or("—"),
        x_forwarded_for = x_forwarded_for.as_deref().unwrap_or("—"),
        x_real_ip = x_real_ip.as_deref().unwrap_or("—"),
        x_forwarded_proto = x_forwarded_proto.as_deref().unwrap_or("—"),
        user_agent = client.user_agent.as_deref().unwrap_or("—"),
        accept_language = client.accept_language.as_deref().unwrap_or("—"),
        accept_encoding = client.accept_encoding.as_deref().unwrap_or("—"),
        sec_ch_ua = client.client_hints.sec_ch_ua.as_deref().unwrap_or("—"),
        sec_ch_ua_platform = client
            .client_hints
            .sec_ch_ua_platform
            .as_deref()
            .unwrap_or("—"),
        timestamp = server.timestamp_utc,
        version = server.version,
        region = server.region.as_deref().unwrap_or("—"),
        privacy_mode = privacy.mode,
    );

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

    if let Some(tls) = ctx.tls_version {
        let proto = ctx.http_protocol.unwrap_or_else(|| "-".into());
        writeln!(&mut out, "TLS: {} over {}", tls, proto).ok();
    }

    if let Some(ua) = headers.get("User-Agent").and_then(|v| v.to_str().ok()) {
        writeln!(&mut out, "User-Agent: {}", ua).ok();
    }

    Ok(out)
}

pub async fn health_handler() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}
