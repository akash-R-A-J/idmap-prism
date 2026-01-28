use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Router, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
use tower_http::trace::TraceLayer;
use tracing::{info, error};
use redis::{Client as RedisClient, AsyncCommands};
use solana_sdk::signature::Signature;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

mod auth;
mod demo;

#[derive(Clone)]
pub struct AppState {
    pub redis: RedisClient,
    pub http_client: reqwest::Client,
    pub orchestrator_url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting IdMap API Gateway...");

    // Config
    let redis_url = std::env::var("REDIS_URL").unwrap_or("redis://127.0.0.1/".to_string());
    let orchestrator_url = std::env::var("ORCHESTRATOR_URL").unwrap_or("http://127.0.0.1:3000".to_string());

    // Clients
    let redis_client = redis::Client::open(redis_url)?;
    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .pool_idle_timeout(Duration::from_secs(90))
        .build()?;

    let state = AppState {
        redis: redis_client,
        http_client,
        orchestrator_url,
    };

    let app = Router::new()
        // Public Ends
        .route("/v1/get_prism_proof", post(v1_get_prism_proof))
        .route("/v1/verify", post(v1_verify_proof))
        .route("/v1/predicates", get(v1_list_predicates)) // New Discovery Endpoint
        .layer(middleware::from_fn_with_state(state.clone(), auth::auth_middleware)) // Auth Middleware for V1
        // Auth / Consent
        // Auth / Consent
        .route("/auth/challenge", get(auth_challenge))
        // Demo / Simulation (WARNING: Demo Only)
        .route("/demo/setup-mint", post(demo::demo_setup_mint))
        .route("/demo/create-wallet", post(demo::demo_create_wallet))
        .route("/demo/mint-tokens", post(demo::demo_mint_tokens))
        .route("/demo/encrypted-transfer", post(demo::demo_encrypted_transfer))
        // System
        .route("/health", get(health_check))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    info!("Gateway listening on 0.0.0.0:8080");
    axum::serve(listener, app).await?;

    Ok(())
}

// --- HANDLERS PLACEHOLDERS ---

async fn health_check() -> impl IntoResponse {
    json!({ "status": "ok", "service": "idmap-gateway" }).to_string()
}

// V1
async fn v1_get_prism_proof(
    State(state): State<AppState>,
    Json(payload): Json<Value>
) -> impl IntoResponse {
    // 1. Extract params
    let wallet = payload["subject_wallet"].as_str().unwrap_or("").to_string();
    let mint = payload["mint"].as_str().unwrap_or("").to_string();
    let signature = payload["signature"].as_str().unwrap_or("").to_string();
    let predicate = payload["predicate"].clone();
    
    // 2. Verify Consent Signature (Demo Logic)
    if let Err(code) = auth::verify_challenge_signature(&state, &wallet, &signature, &mint).await {
         return (code, Json(json!({"error": "Invalid or expired consent signature"}))).into_response();
    }

    // 3. Inject Request ID
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut orchestrator_payload = payload.clone();
    orchestrator_payload["request_id"] = json!(request_id);

    // 4. Proxy to Orchestrator
    let client = &state.http_client;
    let url = format!("{}/internal/proof", state.orchestrator_url);

    match client.post(&url).json(&orchestrator_payload).send().await {
        Ok(res) => {
            let status = res.status();
            let mut body: Value = res.json().await.unwrap_or(json!({"error": "Orchestrator invalid response"}));
            
            // Inject trace_id if missing (should be there from Orchestrator)
            if body.get("trace_id").is_none() {
                body["trace_id"] = json!(request_id);
            }
            
            (StatusCode::from_u16(status.as_u16()).unwrap(), Json(body)).into_response()
        },
        Err(e) => {
             error!("Orchestrator unavailable: {}", e);
             (StatusCode::BAD_GATEWAY, Json(json!({"error": "Orchestrator unavailable", "trace_id": request_id}))).into_response()
        }
    }
}

async fn v1_verify_proof(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> impl IntoResponse {
    // 1. Extract Attestation
    let attestation = match payload.get("attestation") {
        Some(a) => a,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"valid": false, "error": "Missing attestation field"}))).into_response(),
    };

    // 2. Fetch Committee PK (Mock/Fetch)
    // In a real system, we'd fetch from Mesh state or Config.
    // For Demo: We assume the Committee PK is known or provided in request for validation check (though insecure).
    // BETTER: The Gateway should have it configured.
    // Let's check if 'committee_key' is in payload for demo validation flexibility, default to env/placeholder.
    let committee_pk_str = payload["committee_key"].as_str().unwrap_or("");
    
    if committee_pk_str.is_empty() {
         return (StatusCode::BAD_REQUEST, Json(json!({"valid": false, "error": "Missing committee_key for verification context"}))).into_response();
    }
    
    let committee_pk = match Pubkey::from_str(committee_pk_str) {
        Ok(pk) => pk,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({"valid": false, "error": "Invalid committee_key format"}))).into_response(),
    };

    // 3. Reconstruct Signed Message
    // The Orchestrator signs: BASE64_STANDARD.encode(serde_json::to_vec(&sdrf_without_sig))
    // We need to clone the attestation and clear the signature to match the signing input.
    let mut unsigned_sdrf = attestation.clone();
    
    // Ensure signature field exists/is handled. 
    // If it's the SdrfPayload struct, we set signature = "".
    // Since we parsed as Value, we set field "signature" to "".
    if let Some(obj) = unsigned_sdrf.as_object_mut() {
        obj.insert("signature".to_string(), json!(""));
    } else {
         return (StatusCode::BAD_REQUEST, Json(json!({"valid": false, "error": "Invalid attestation structure"}))).into_response();
    }

    // Serialize to canonical bytes (must match Orchestrator's serialization exactness)
    // Note: JSON serialization stability is tricky. In Prod, we use deterministic serialization (like Canonical JSON or BCS).
    // For this Rust-to-Rust demo using serde_json default on both ends, it *usually* matches if struct order matches.
    let sdrf_bytes = serde_json::to_vec(&unsigned_sdrf).unwrap_or_default();
    let message_b64 = BASE64_STANDARD.encode(sdrf_bytes);

    // 4. Extract Signature
    let sig_str = attestation["signature"].as_str().unwrap_or("");
    let signature = match Signature::from_str(sig_str) {
        Ok(s) => s,
        Err(_) => return (StatusCode::OK, Json(json!({"valid": false, "error": "Invalid signature format"}))).into_response(),
    };

    // 5. Verify Ed25519
    // The MPC node signs the *bytes* of the message string? 
    // Orchestrator: `let sign_cmd = json!({ "message": sdrf_b64 ... })`
    // MPC Node (simulated): Signs `sdrf_b64.as_bytes()`.
    
    if signature.verify(committee_pk.as_ref(), message_b64.as_bytes()) {
         Json(json!({ 
             "valid": true, 
             "subject": attestation["subject"]["address"],
             "predicate_result": attestation["result"]
         })).into_response()
    } else {
         Json(json!({ 
             "valid": false, 
             "error": "Signature verification failed" 
         })).into_response()
    }
}


async fn v1_list_predicates() -> impl IntoResponse {
    // Return list of supported predicates (Demo: Static List)
    Json(json!({
        "predicates": [
            {
                "id": "balance_gt",
                "name": "Balance Threshold",
                "description": "Succinctly proves that a detailed encrypted balance is greater than a public threshold.",
                "params_schema": {
                    "amount": "u64 (The threshold value)"
                },
                "inputs": ["mint", "subject_wallet"]
            }
        ]
    })).into_response()
}

// Auth
#[derive(Deserialize)]
struct ChallengeReq {
    wallet: String,
    mint: String,
    predicate: Option<Value>,
}

async fn auth_challenge(
    State(state): State<AppState>,
    axum::extract::Query(req): axum::extract::Query<ChallengeReq>,
) -> impl IntoResponse {
    let nonce = uuid::Uuid::new_v4().to_string();
    let predicate_summary = json!(req.predicate).to_string();
    
    // Construct strict challenge
    let challenge = format!(
        "Sign to approve proof request:\nwallet={}\nmint={}\npredicate={}\nnonce={}",
        req.wallet, req.mint, predicate_summary, nonce
    );

    let redis_key = format!("challenge:{}", req.wallet);
    
    // Store in Redis (TTL 5 mins)
    let mut conn = match state.redis.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "Redis unavailable").into_response(),
    };

    if let Err(e) = conn.set_ex::<_, _, ()>(&redis_key, &challenge, 300).await {
        error!("Redis set failed: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to store challenge").into_response();
    }

    Json(json!({ "challenge": challenge, "nonce": nonce })).into_response()
}


// Removed local placeholders in favor of mod demo::*
