use tokio::net::TcpListener;
use serde_json::Value as JValue;
use std::fmt;


use pod2::{self,
    middleware::{
        VDSet,
        Params,
        Pod,
        PodId,
        Hash,
        RecursivePod,
        Value,
        containers::Set,
        RawValue,
        KEY_SIGNER,
        CustomPredicateRef, PodType, Predicate, Statement,
        StatementArg, TypedValue, KEY_TYPE, Operation
    },
    backends::plonky2::{
        Result,
        basetypes::{C, D, F},
    },
    frontend::{
        MainPodBuilder,
        MainPod
    },
    backends::plonky2::mainpod,
    timed,
    op
};

// Define the error type for our verification function
#[derive(Debug)]
pub enum VerificationError {
    InvalidProofFormat,
    FileReadError(String),
    JsonParseError(String),
    VerificationFailed,
}

// Implement Display for VerificationError
impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VerificationError::InvalidProofFormat => write!(f, "Invalid proof format"),
            VerificationError::FileReadError(e) => write!(f, "File read error: {}", e),
            VerificationError::JsonParseError(e) => write!(f, "JSON parse error: {}", e),
            VerificationError::VerificationFailed => write!(f, "Verification failed"),
        }
    }
}

// Main verification function
pub async fn verify_pod(pod: &String, pk_list: Value, message: &str) -> Result<bool, VerificationError>{
    let pod_extract:MainPod = serde_json::from_str(&pod).expect("Failed to parse Main Pod");
    let pk_list_pod = pod_extract.get("public_keys").unwrap();
    let message_pod = pod_extract.get("message").unwrap();
    if (message_pod != Value::from(message)) || (pk_list_pod != pk_list) {
        return Ok(false);
    }
    match pod_extract.pod.verify(){
        Ok(()) => Ok(true),
        Err(_) =>  Ok(false)
    }
}
