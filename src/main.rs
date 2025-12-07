mod asn;
mod cf;
mod config;
mod error;
mod handlers;
mod model;
mod security_headers;

use asn::load_asn_db;
use axum::{routing::get, Router};
use config::AppConfig;
use handlers::{health_handler, html_handler, info_handler, plain_handler, privacy_handler};
use security_headers::security_headers_layer;
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::Level;

use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(Level::INFO)
        .init();

    // Load configuration
    let cfg = AppConfig::from_env().map_err(|e| format!("Failed to load configuration: {e}"))?;

    tracing::info!("Loading ASN database from: {}", cfg.asn_db_path);
    let asn_db = load_asn_db(&cfg).map_err(|e| format!("Failed to load ASN database: {e}"))?;
    tracing::info!("ASN database loaded successfully");

    let shared_state = handlers::AppState {
        config: cfg,
        asn_db: Arc::new(asn_db),
    };

    // Build security headers layers
    let (csp, referrer, xfo, hsts, xcto, perm) = security_headers_layer();

    // Build router with all routes and middleware
    let app = Router::new()
        .route("/", get(html_handler))
        .route("/privacy", get(privacy_handler))
        .route("/api/v1/json", get(info_handler))
        .route("/api/v1/plain", get(plain_handler))
        .route("/healthz", get(health_handler))
        .with_state(shared_state)
        .layer(TraceLayer::new_for_http())
        .layer(csp)
        .layer(referrer)
        .layer(xfo)
        .layer(hsts)
        .layer(xcto)
        .layer(perm);

    // Get bind address from environment or use default
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);
    let addr: SocketAddr = format!("0.0.0.0:{}", port)
        .parse()
        .map_err(|e| format!("Invalid bind address: {e}"))?;

    tracing::info!("Starting server on {}", addr);

    // Create TCP listener
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("Failed to bind to {}: {e}", addr))?;

    // Setup graceful shutdown
    let shutdown_signal = async {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }

        tracing::info!("Shutdown signal received, starting graceful shutdown...");
    };

    // Start server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .map_err(|e| format!("Server error: {e}"))?;

    tracing::info!("Server shutdown complete");
    Ok(())
}
