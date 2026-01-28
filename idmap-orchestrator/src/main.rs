use axum::Router;
use std::net::SocketAddr;
use tracing::info;

mod redis;
mod dlp;
mod sdrf;
mod solana;
mod api;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Starting IdMap Orchestrator...");

    let redis_url = std::env::var("REDIS_URL").unwrap_or("redis://127.0.0.1/".to_string());
    let state = api::AppState {
        redis: redis::RedisClient::new(&redis_url).await.unwrap(),
        solana: solana::SolanaClientWrapper::new("https://api.devnet.solana.com"),
        committee_session: std::sync::Arc::new(tokio::sync::Mutex::new(String::new())),
    };

    let app = Router::new()
        .route("/internal/setup", axum::routing::post(api::setup_committee))
        .route("/internal/auditor-key", axum::routing::post(api::generate_auditor_key))
        .route("/internal/proof", axum::routing::post(api::generate_proof))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("Orchestrator Internal API listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
