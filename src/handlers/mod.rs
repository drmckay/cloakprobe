use crate::asn::AsnDatabase;
use crate::config::AppConfig;
use std::sync::Arc;
use tera::Tera;

// Export AppState for use in handler modules
#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub asn_db: Arc<dyn AsnDatabase>,
    pub tera: Arc<Tera>,
}

// Export all handlers
pub mod health;
pub mod html;
pub mod info;
pub mod plain;
pub mod privacy;

// Re-export handlers for convenience
pub use health::health_handler;
pub use html::html_handler;
pub use info::info_handler;
pub use plain::plain_handler;
pub use privacy::privacy_handler;
