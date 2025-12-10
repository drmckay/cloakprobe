mod asn;
mod cf;
mod config;
mod error;
mod formatters;
mod handlers;
mod headers;
mod model;
mod security_headers;
mod utils;

use asn::load_asn_db;
use axum::{routing::get, Router};
use config::AppConfig;
use handlers::{health_handler, html_handler, info_handler, plain_handler, privacy_handler};
use security_headers::security_headers_layer;
use std::sync::Arc;
use tera::Tera;
use tower_http::trace::TraceLayer;
use tracing::Level;

use std::env;
use std::net::SocketAddr;

/// Parse command line arguments
fn parse_args() -> Option<String> {
    let args: Vec<String> = env::args().collect();
    let mut config_path = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                if i + 1 < args.len() {
                    config_path = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("Error: {} requires a path argument", args[i]);
                    std::process::exit(1);
                }
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-v" | "--version" => {
                println!("cloakprobe {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            arg => {
                eprintln!("Unknown argument: {}", arg);
                print_help();
                std::process::exit(1);
            }
        }
    }

    config_path
}

fn print_help() {
    println!(
        r#"cloakprobe {} - Privacy-first IP information service

USAGE:
    cloakprobe [OPTIONS]

OPTIONS:
    -c, --config <PATH>    Path to configuration file (TOML)
    -h, --help             Print help information
    -v, --version          Print version information

CONFIG FILE:
    Default locations (in order of priority):
    1. Path specified with -c/--config
    2. ./cloakprobe.toml
    3. /etc/cloakprobe/cloakprobe.toml

    Environment variables can override config file values.
    See cloakprobe.example.toml for configuration options.
"#,
        env!("CARGO_PKG_VERSION")
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(Level::INFO)
        .init();

    // Parse command line arguments
    let config_path = parse_args();

    // Load configuration from TOML file
    let cfg = AppConfig::load(config_path.as_deref())
        .map_err(|e| format!("Failed to load configuration: {e}"))?;

    tracing::info!("Proxy mode: {:?}", cfg.proxy_mode);
    if let Some(ref region) = cfg.region {
        tracing::info!("Server region: {}", region);
    }

    tracing::info!("Loading ASN database from: {}", cfg.asn_db_path);
    let asn_db = load_asn_db(&cfg).map_err(|e| format!("Failed to load ASN database: {e}"))?;
    tracing::info!("ASN database loaded successfully");

    // Initialize Tera templates once
    let tera = Arc::new(
        Tera::new("templates/**/*.tera")
            .map_err(|e| format!("Failed to initialize templates: {e}"))?,
    );

    // Build bind address from config
    let addr: SocketAddr = format!("{}:{}", cfg.bind_address, cfg.port)
        .parse()
        .map_err(|e| format!("Invalid bind address: {e}"))?;

    let shared_state = handlers::AppState {
        config: cfg,
        asn_db: Arc::new(asn_db),
        tera: tera.clone(),
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
