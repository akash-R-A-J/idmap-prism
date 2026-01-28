use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::Response,
};
use redis::AsyncCommands;
use crate::AppState;
use tracing::{warn, info};

// --- MIDDLEWARE ---

/// Middleware to validate Bearer Token (API Key)
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // 1. Extract Header
    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token = &auth_header[7..];

    // 2. Validate against Redis (Simple lookup for MVP)
    // In strict prod, we'd hash the token. For now, assume token is random high-entropy string.
    let redis_key = format!("apikey:{}", token);
    
    let mut conn = state.redis.get_multiplexed_async_connection().await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let exists: bool = conn.exists(&redis_key).await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    if !exists {
        warn!("Invalid API Key attempt: {}", token);
        return Err(StatusCode::UNAUTHORIZED);
    }
    
    // 3. Rate Limit Check (Simple Fixed Window)
    let limit_key = format!("ratelimit:{}", token);
    let count: u64 = conn.incr(&limit_key, 1).await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    
    if count == 1 {
        let _ = conn.expire::<_, ()>(&limit_key, 60).await; // 1 min window
    }

    if count > 100 { // 100 req/min for demo
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(req).await)
}


// --- DEMO AUTH LOGIC ---

use solana_sdk::signature::Signature;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

/// Verifies a signature against a challenge stored in Redis.
/// Returns Ok(()) if valid, Err(StatusCode) if not.
pub async fn verify_challenge_signature(
    state: &AppState,
    wallet: &str,
    signature_b58: &str,
    expected_mint: &str,
) -> Result<(), StatusCode> {
    // 1. Fetch Challenge from Redis
    let mut conn = state.redis.get_multiplexed_async_connection().await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    let challenge_key = format!("challenge:{}", wallet);
    let challenge: String = conn.get(&challenge_key).await
        .map_err(|_| StatusCode::UNAUTHORIZED)?; // Challenge expired or invalid

    // 2. Verify Intent Binding (Simple check)
    if !challenge.contains(expected_mint) {
         warn!("Challenge intent mismatch for wallet {}", wallet);
         return Err(StatusCode::UNAUTHORIZED);
    }

    // 3. Verify Signature
    let pubkey = Pubkey::from_str(wallet)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let signature = Signature::from_str(signature_b58)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    if !signature.verify(pubkey.as_ref(), challenge.as_bytes()) {
        warn!("Invalid signature for wallet {}", wallet);
        return Err(StatusCode::UNAUTHORIZED);
    }

    // 4. Invalidate Challenge (Replay Protection)
    let _ = conn.del::<_, ()>(&challenge_key).await;

    Ok(())
}
