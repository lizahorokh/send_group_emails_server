use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use rand::thread_rng;
use tokio::net::TcpListener;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::fmt;
use std::str::FromStr;  // Add this import for from_str

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
pub async fn verify_proof(proof_data: &str) -> Result<bool, VerificationError> {
    // Parse the proof data from JSON string
    let proof_json: Value = serde_json::from_str(proof_data)
        .map_err(|e| VerificationError::JsonParseError(e.to_string()))?;

    // Extract proof and public signals
    let proof = proof_json.get("proof")
        .ok_or(VerificationError::InvalidProofFormat)?;
    let public_signals = proof_json.get("publicSignals")
        .ok_or(VerificationError::InvalidProofFormat)?;

    // Load verification key from file
    let mut vk_file = File::open("verification_key.json")
        .map_err(|e| VerificationError::FileReadError(e.to_string() + "1"))?;
    let mut vk_json = String::new();
    vk_file.read_to_string(&mut vk_json)
        .map_err(|e| VerificationError::FileReadError(e.to_string() + "2"))?;
    println!("{vk_json}");
    // Deserialize verification key
    let vk: VerifyingKey<ark_bn254::Bn254> = VerifyingKey::deserialize_uncompressed(
        &mut vk_json.as_bytes()
    ).map_err(|e| VerificationError::FileReadError(e.to_string() + "3"))?;

    // Deserialize proof
    let proof: Proof<ark_bn254::Bn254> = Proof::deserialize_uncompressed(
        &mut serde_json::to_vec(proof).unwrap().as_slice()
    ).map_err(|e| VerificationError::InvalidProofFormat)?;

    // Convert public signals to the appropriate format
    let public_inputs: Vec<ark_bn254::Fr> = public_signals.as_array()
        .ok_or(VerificationError::InvalidProofFormat)?
        .iter()
        .map(|v| {
            let s = v.as_str().unwrap_or_default();
            // Convert string to BigInt first, then to Fr
            let big_int = num_bigint::BigUint::from_str(s)
                .map_err(|_| VerificationError::InvalidProofFormat)?;
            Ok(ark_bn254::Fr::from(big_int))
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Verify the proof using the SNARK trait
    let result = Groth16::<ark_bn254::Bn254>::verify(
        &vk,
        &public_inputs,
        &proof
    ).map_err(|_| VerificationError::VerificationFailed)?;

    Ok(result)
}

// Example usage with error handling
pub async fn verify_proof_with_ui_feedback(proof_data: &str) -> (String, bool) {
    match verify_proof(proof_data).await {
        Ok(true) => ("Verified!".to_string(), true),
        Ok(false) => ("Invalid proof".to_string(), false),
        Err(e) => (format!("Error: {}", e), false),
    }
}

// Example of how to use it in a web context (if using wasm-bindgen)
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub async fn verify_proof_wasm(proof_data: &str) -> Result<JsValue, JsValue> {
    let (message, success) = verify_proof_with_ui_feedback(proof_data).await;
    let result = serde_json::json!({
        "message": message,
        "success": success
    });
    Ok(JsValue::from_serde(&result).unwrap())
}

#[tokio::main]
async fn main() {
    let mut content = std::fs::read_to_string("proof.txt").unwrap();
    
    let res = verify_proof(&content).await;
    println!("{:?}", res);
}
