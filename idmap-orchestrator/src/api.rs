use axum::{
    extract::State,
    Json,
    response::IntoResponse,
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use uuid::Uuid;
use crate::redis::RedisClient;
use crate::solana::SolanaClientWrapper;
use crate::sdrf::{AttestationResponse, SdrfPayload, ApiError, SdrfMetadata, SdrfSubject, SdrfPredicate};
// use crate::dlp;
use curve25519_dalek::ristretto::CompressedRistretto;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

#[derive(Clone)]
pub struct AppState {
    pub redis: RedisClient,
    pub solana: SolanaClientWrapper,
    pub committee_session: Arc<tokio::sync::Mutex<String>>, // Stores active committee session ID
}

// REQUEST MODELS
#[derive(Deserialize)]
pub struct GenerateAuditorKeyReq {
    pub mint_alias: String,
}

#[derive(Deserialize)]
pub struct GenerateProofReq {
    pub request_id: String,
    pub subject_wallet: String,
    pub mint: String,
    pub predicate: SdrfPredicate,
    pub context: Value,
}

// HANDLERS

pub async fn setup_committee(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let session_id = Uuid::new_v4().to_string();
    
    // Publish dkg-start
    let cmd = json!({
        "action": "startdkg",
        "session": session_id
    });

    if let Err(e) = state.redis.publish("dkg-start", &cmd).await {
         return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))); 
    }

    // Wait for dkg-result
    let mut rx = state.redis.subscribe_internal();
    let result = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok((channel, val)) = rx.recv().await {
                if channel == "dkg-result" {
                    // In a real impl, verify ID matches if strictly required, 
                    // but dkg-start is usually a global sync event.
                    return Some(val);
                }
            }
        }
    }).await;

    match result {
        Ok(Some(val)) => {
            let mut session_store = state.committee_session.lock().await;
            *session_store = session_id.clone();
            (StatusCode::OK, Json(json!({"success": true, "session": session_id, "data": val})))
        }
        _ => (StatusCode::GATEWAY_TIMEOUT, Json(json!({"error": "DKG timed out"})))
    }
}

pub async fn generate_auditor_key(
    State(state): State<AppState>,
    Json(payload): Json<GenerateAuditorKeyReq>,
) -> impl IntoResponse {
    let cache_key = format!("auditor_key:{}", payload.mint_alias);

    // 1. Check Cache
    if let Ok(Some(cached_json)) = state.redis.get(&cache_key).await {
        if let Ok(val) = serde_json::from_str::<Value>(&cached_json) {
            return (StatusCode::OK, Json(json!({"success": true, "data": val, "cached": true})));
        }
    }

    // 2. Start DKG (Cache Miss)
    let cmd = json!({
        "action": "start-auditor-dkg",
        "mint": payload.mint_alias
    });

    if let Err(e) = state.redis.publish("start-auditor-dkg", &cmd).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()})));
    }

    let mut rx = state.redis.subscribe_internal();
    // Wait for auditor-dkg-result
    let result = timeout(Duration::from_secs(30), async {
        loop {
            if let Ok((channel, val)) = rx.recv().await {
                if channel == "auditor-dkg-result" {
                    if val["mint"].as_str() == Some(&payload.mint_alias) {
                        return Some(val);
                    }
                }
            }
        }
    }).await;

    match result {
         Ok(Some(val)) => {
             // 3. Cache Result (Permanent)
             let _ = state.redis.set(&cache_key, &val.to_string()).await;
             
             (StatusCode::OK, Json(json!({"success": true, "data": val})))
         },
         _ => (StatusCode::GATEWAY_TIMEOUT, Json(json!({"error": "Auditor DKG timed out"})))
    }
}

pub async fn generate_proof(
    State(state): State<AppState>,
    Json(req): Json<GenerateProofReq>,
) -> Result<impl IntoResponse, ApiError> {
    // 1. Fetch Ciphertext from Solana RPC
    let ciphertext = match state.solana.fetch_ciphertext(&req.subject_wallet, &req.mint).await {
        Ok(c) => c,
        Err(e) => return Err(ApiError {
            code: "RPC_ERROR".into(),
            message: e.to_string(),
            trace_id: req.request_id,
            details: None,
        }),
    };

    // 2. Decrypt (MPC)
    let decrypt_cmd = json!({
        "action": "auditor-decrypt-start",
        "mint": req.mint,
        "ciphertext": ciphertext
    });

    if let Err(e) = state.redis.publish("auditor-decrypt-start", &decrypt_cmd).await {
         return Err(ApiError{code:"REDIS_ERR".into(),message:e.to_string(),trace_id:req.request_id.clone(),details:None});
    }

    let mut rx = state.redis.subscribe_internal();
    let decrypt_res = timeout(Duration::from_secs(10), async {
        loop {
            if let Ok((channel, val)) = rx.recv().await {
                if channel == "auditor-decrypt-result" {
                    if val["mint"].as_str() == Some(&req.mint) {
                        return Some(val);
                    }
                }
            }
        }
    }).await;

    let point_str = match decrypt_res {
        Ok(Some(v)) => v["value_commitment"].as_str().unwrap_or("").to_string(),
        _ => return Err(ApiError{code:"DECRYPT_TIMEOUT".into(),message:"MPC decryption timed out".into(),trace_id:req.request_id,details:None}),
    };

    // 3. Solve DLP & Predicate
    let point_bytes = match bs58::decode(&point_str).into_vec() {
        Ok(b) => b,
        Err(_) => return Err(ApiError{code:"INVALID_POINT".into(),message:"Failed to decode point".into(),trace_id:req.request_id,details:None})
    };

    let compressed = match point_bytes.len() {
        32 => CompressedRistretto::from_slice(&point_bytes).unwrap(), // Safe due to len check
        _ => return Err(ApiError{code:"INVALID_POINT_LEN".into(),message:"Point must be 32 bytes".into(),trace_id:req.request_id,details:None})
    };

    let point = match compressed.decompress() {
        Some(p) => p,
        None => return Err(ApiError{code:"INVALID_CURVE_POINT".into(),message:"Invalid Ristretto point".into(),trace_id:req.request_id,details:None})
    };
    
    // Solve DLP (Max 32 bits = 4 billion range)
    let amount = match crate::dlp::solve_discrete_log(&point, 32) {
        Some(a) => a,
        None => return Err(ApiError{code:"DLP_FAILED".into(),message:"Amount out of range or unsolvable".into(),trace_id:req.request_id,details:None})
    };

    // Validate Predicate (Simple GT check for MVP)
    let threshold = req.predicate.params.get("amount")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
        
    let valid = amount > threshold; 

    if !valid {
         return Err(ApiError{code:"PREDICATE_FAILED".into(),message:format!("Balance {} not greater than {}", amount, threshold),trace_id:req.request_id,details:None});
    }

    // 4. Sign Attestation
    // Construct SDRF payload
    let sdrf = SdrfPayload {
        version: "3.0".into(),
        request_id: req.request_id.clone(),
        proof_id: Uuid::new_v4().to_string(),
        metadata: SdrfMetadata {
            requester: "gateway".into(),
            purpose: "proof".into(),
            issued_at: 0,
            proof_mode: "attested_mpc".into(),
            consent_proof: "signature_hash".into()
        },
        subject: SdrfSubject {
            r#type: "wallet".into(),
            chain: "solana".into(),
            address: req.subject_wallet.clone()
        },
        predicate: req.predicate,
        result: true,
        signature: "".into() // Pending
    };

    // Serialize to bytes/base64 for signing
    let sdrf_bytes = serde_json::to_vec(&sdrf)
        .map_err(|e| ApiError{code:"SERIALIZATION_ERR".into(),message:e.to_string(),trace_id:req.request_id.clone(),details:None})?;
    let sdrf_b64 = BASE64_STANDARD.encode(sdrf_bytes);

    let session_id = state.committee_session.lock().await.clone();
    let sign_cmd = json!({
        "action": "sign",
        "session": session_id,
        "message": sdrf_b64
    });

    if let Err(_) = state.redis.publish("sign-start", &sign_cmd).await {
         return Err(ApiError{code:"SIGN_ERR".into(),message:"Failed to publish sign request".into(),trace_id:req.request_id.clone(),details:None});
    }

    let sign_res = timeout(Duration::from_secs(10), async {
        loop {
            if let Ok((channel, val)) = rx.recv().await {
                if channel == "sign-result" {
                    // In real impl, verify correlation if possible, or assume serial
                     return Some(val);
                }
            }
        }
    }).await;

    let signature = match sign_res {
        Ok(Some(v)) => v["data"].as_str().unwrap_or("").to_string(),
        _ => return Err(ApiError{code:"SIGN_TIMEOUT".into(),message:"MPC signing timed out".into(),trace_id:req.request_id,details:None}),
    };

    let mut final_sdrf = sdrf;
    final_sdrf.signature = signature;

    Ok(Json(AttestationResponse {
        success: true,
        attestation: Some(final_sdrf),
        error: None
    }))
}
