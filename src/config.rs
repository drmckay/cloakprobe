use serde::Deserialize;
use std::env;
use std::fs;
use std::path::Path;

/// Proxy mode determines which headers to trust for client IP extraction
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    /// Trust X-Forwarded-For, X-Real-IP headers (standard reverse proxy like nginx)
    Nginx,
    /// Trust CF-Connecting-IP header (Cloudflare origin server)
    #[default]
    Cloudflare,
}

/// Privacy mode determines data retention policy
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivacyMode {
    #[default]
    Strict,
    Balanced,
}

/// Server configuration section
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// IP address to bind to
    pub bind_address: String,
    /// Port number
    pub port: u16,
    /// Proxy mode: "cloudflare" or "nginx"
    pub mode: ProxyMode,
    /// Server region identifier (optional, for display purposes)
    pub region: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            port: 8080,
            mode: ProxyMode::Cloudflare,
            region: None,
        }
    }
}

/// Privacy configuration section
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct PrivacyConfig {
    /// Privacy mode: "strict" or "balanced"
    pub mode: PrivacyMode,
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            mode: PrivacyMode::Strict,
        }
    }
}

/// Database configuration section
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Path to ASN database
    pub asn_db_path: String,
    /// Path to multi-RIR organization database (optional)
    #[serde(alias = "ripe_db_path")]
    pub org_db_path: Option<String>,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            asn_db_path: "data/asn_db.bin".to_string(),
            org_db_path: Some("data/orgs_db.bin".to_string()),
        }
    }
}

/// Root configuration structure
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct TomlConfig {
    pub server: ServerConfig,
    pub privacy: PrivacyConfig,
    pub database: DatabaseConfig,
}

/// Application configuration (resolved from TOML + env vars)
#[derive(Clone, Debug)]
pub struct AppConfig {
    pub bind_address: String,
    pub port: u16,
    pub proxy_mode: ProxyMode,
    pub region: Option<String>,
    pub privacy_mode: PrivacyMode,
    pub asn_db_path: String,
    pub org_db_path: Option<String>,
}

impl AppConfig {
    /// Load configuration from TOML file with environment variable overrides
    ///
    /// Config file search order:
    /// 1. Path provided via `config_path` argument
    /// 2. `./cloakprobe.toml`
    /// 3. `/etc/cloakprobe/cloakprobe.toml`
    ///
    /// Environment variables can override TOML values (for backward compatibility):
    /// - CLOAKPROBE_BIND_ADDRESS / CLOAKPROBE_PORT
    /// - CLOAKPROBE_MODE (cloudflare/nginx)
    /// - CLOAKPROBE_REGION
    /// - CLOAKPROBE_PRIVACY_MODE
    /// - CLOAKPROBE_ASN_DB_PATH / CLOAKPROBE_ORG_DB_PATH
    pub fn load(config_path: Option<&str>) -> Result<Self, String> {
        // Find and load TOML config
        let toml_config = Self::load_toml_config(config_path)?;

        // Apply environment variable overrides
        let bind_address =
            env::var("CLOAKPROBE_BIND_ADDRESS").unwrap_or(toml_config.server.bind_address);

        let port = env::var("CLOAKPROBE_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(toml_config.server.port);

        let proxy_mode = env::var("CLOAKPROBE_MODE")
            .ok()
            .map(|m| match m.to_lowercase().as_str() {
                "nginx" => Ok(ProxyMode::Nginx),
                "cloudflare" => Ok(ProxyMode::Cloudflare),
                other => Err(format!("Unknown proxy mode: {}", other)),
            })
            .transpose()?
            .unwrap_or(toml_config.server.mode);

        let region = env::var("CLOAKPROBE_REGION")
            .ok()
            .or(toml_config.server.region);

        let privacy_mode = env::var("CLOAKPROBE_PRIVACY_MODE")
            .ok()
            .map(|m| match m.to_lowercase().as_str() {
                "strict" => Ok(PrivacyMode::Strict),
                "balanced" => Ok(PrivacyMode::Balanced),
                other => Err(format!("Unknown privacy mode: {}", other)),
            })
            .transpose()?
            .unwrap_or(toml_config.privacy.mode);

        let asn_db_path =
            env::var("CLOAKPROBE_ASN_DB_PATH").unwrap_or(toml_config.database.asn_db_path);

        // Support both new CLOAKPROBE_ORG_DB_PATH and legacy CLOAKPROBE_RIPE_DB_PATH
        let org_db_path = env::var("CLOAKPROBE_ORG_DB_PATH")
            .ok()
            .or_else(|| env::var("CLOAKPROBE_RIPE_DB_PATH").ok())
            .or(toml_config.database.org_db_path);

        // Validate database paths exist
        let asn_db_path = Self::find_database_path(&asn_db_path, "asn_db.bin")?;
        let org_db_path =
            org_db_path.and_then(|p| Self::find_database_path(&p, "orgs_db.bin").ok());

        Ok(Self {
            bind_address,
            port,
            proxy_mode,
            region,
            privacy_mode,
            asn_db_path,
            org_db_path,
        })
    }

    /// Load TOML configuration from file
    fn load_toml_config(config_path: Option<&str>) -> Result<TomlConfig, String> {
        let paths_to_try: Vec<&str> = if let Some(path) = config_path {
            vec![path]
        } else {
            vec!["./cloakprobe.toml", "/etc/cloakprobe/cloakprobe.toml"]
        };

        for path in &paths_to_try {
            if Path::new(path).exists() {
                let content = fs::read_to_string(path)
                    .map_err(|e| format!("Failed to read config file {}: {}", path, e))?;

                let config: TomlConfig = toml::from_str(&content)
                    .map_err(|e| format!("Failed to parse config file {}: {}", path, e))?;

                tracing::info!("Loaded configuration from: {}", path);
                return Ok(config);
            }
        }

        // No config file found, use defaults
        if config_path.is_some() {
            return Err(format!("Config file not found: {}", config_path.unwrap()));
        }

        tracing::info!("No config file found, using defaults");
        Ok(TomlConfig::default())
    }

    /// Find database path, trying common locations
    fn find_database_path(path: &str, filename: &str) -> Result<String, String> {
        if Path::new(path).exists() {
            return Ok(path.to_string());
        }

        // Try common locations
        let candidates = [format!("data/{}", filename), format!("./data/{}", filename)];

        for candidate in &candidates {
            if Path::new(candidate).exists() {
                return Ok(candidate.to_string());
            }
        }

        // Return original path (will fail at load time with better error)
        Ok(path.to_string())
    }
}
