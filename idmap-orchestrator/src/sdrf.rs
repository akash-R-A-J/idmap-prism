use serde::{Deserialize, Serialize};
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum::http::StatusCode;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttestationResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<SdrfPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub trace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.code.as_str() {
            "DLP_FAILED" | "PREDICATE_FAILED" | "INVALID_POINT" => StatusCode::BAD_REQUEST,
            "RPC_ERROR" | "REDIS_ERR" => StatusCode::SERVICE_UNAVAILABLE,
            "DECRYPT_TIMEOUT" | "SIGN_TIMEOUT" => StatusCode::GATEWAY_TIMEOUT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        
        let body = Json(AttestationResponse {
            success: false,
            attestation: None,
            error: Some(self),
        });

        (status, body).into_response()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SdrfPayload {
    pub version: String,
    pub request_id: String,
    pub proof_id: String,
    pub metadata: SdrfMetadata,
    pub subject: SdrfSubject,
    pub predicate: SdrfPredicate,
    pub result: bool,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SdrfMetadata {
    pub requester: String,
    pub purpose: String,
    pub issued_at: u64,
    pub proof_mode: String,
    pub consent_proof: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SdrfSubject {
    pub r#type: String,
    pub chain: String,
    pub address: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SdrfPredicate {
    pub r#type: String,
    pub registry: String,
    pub params: serde_json::Value,
}
