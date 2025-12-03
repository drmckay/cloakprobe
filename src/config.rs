use std::env;

#[derive(Clone)]
pub enum PrivacyMode {
    Strict,
    Balanced,
}

#[derive(Clone)]
pub struct AppConfig {
    pub privacy_mode: PrivacyMode,
    pub asn_db_path: String,
    pub ripe_db_path: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, String> {
        let privacy_mode = match env::var("CLOAKPROBE_PRIVACY_MODE")
            .or_else(|_| env::var("CFDEBUG_PRIVACY_MODE"))
            .unwrap_or_else(|_| "strict".into())
            .to_lowercase()
            .as_str()
        {
            "strict" => PrivacyMode::Strict,
            "balanced" => PrivacyMode::Balanced,
            other => return Err(format!("Unknown privacy mode: {other}")),
        };

        let asn_db_path = env::var("CLOAKPROBE_ASN_DB_PATH")
            .or_else(|_| env::var("CFDEBUG_ASN_DB_PATH"))
            .unwrap_or_else(|_| "data/asn_db.bin".into());

        let ripe_db_path = env::var("CLOAKPROBE_RIPE_DB_PATH")
            .or_else(|_| env::var("CFDEBUG_RIPE_DB_PATH"))
            .ok();

        Ok(Self {
            privacy_mode,
            asn_db_path,
            ripe_db_path,
        })
    }
}
