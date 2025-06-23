use ark_groth16::{Proof, VerifyingKey, Groth16, prepare_verifying_key, PreparedVerifyingKey};
use rand::thread_rng;
use tokio::net::TcpListener;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::fmt;
use std::str::FromStr;  // Add this import for from_str
use std::process::Command;
use tokio::fs::read_to_string;
use std::panic;

use anyhow::Result;

mod util;                     // 👈 declare the sibling module
use util::*;                  // bring E, Fr, g1(), g2(), … into scope

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
pub async fn verify_proof(proof_str: &String, public_str: &String, verification_key_path: &String) -> Result<bool, VerificationError> {
    // ---------- 1. Load the three files asynchronously -------------------
    let (proof_js, vk_js, public_inputs) = {
        let vk_str = read_to_string(verification_key_path)
            .await
            .map_err(|e| VerificationError::FileReadError(e.to_string()))?;

        // Parse JSON ------------------------------------------------------
        let proof_js: ProofJson = serde_json::from_str(&proof_str)
            .map_err(|e| VerificationError::JsonParseError(e.to_string() + "Proof"))?;

        let vk_js: VkJson = serde_json::from_str(&vk_str)
            .map_err(|e| VerificationError::JsonParseError(e.to_string() + "Vk"))?;

        let public_inputs: Vec<Fr> = serde_json::from_str::<Vec<String>>(&public_str)
            .map_err(|e| VerificationError::JsonParseError(e.to_string() + "Public"))?
            .iter()
            .map(|s| fr_from_dec(s))
            .collect();

        (proof_js, vk_js, public_inputs)
    };

    // Quick shape check: #public + 1 must equal #IC points in snarkjs vkey
    if public_inputs.len() + 1 != vk_js.ic.len() {
        return Err(VerificationError::InvalidProofFormat);
    }

    // ---------- 2. Build Ark-works structs -------------------------------
    // a, b, c
    let proof = Proof::<E> {
        a: g1_from_vec(&proof_js.pi_a),
        b: g2_from_vecs(&proof_js.pi_b),
        c: g1_from_vec(&proof_js.pi_c),
    };

    // verifying-key pieces
    let vk = VerifyingKey::<E> {
        alpha_g1:     g1_from_vec(&vk_js.alpha_1),
        beta_g2:      g2_from_vecs(&vk_js.beta_2),
        gamma_g2:     g2_from_vecs(&vk_js.gamma_2),
        delta_g2:     g2_from_vecs(&vk_js.delta_2),
        gamma_abc_g1: vk_js
            .ic
            .iter()
            .map(|vec3| g1_from_vec(vec3))
            .collect(),
    };
    // ---------- 3. Verify ------------------------------------------------
    let pvk: PreparedVerifyingKey<E> = prepare_verifying_key(&vk);
    let verified = panic::catch_unwind( || {Groth16::<E>::verify_proof(&pvk, &proof, &public_inputs)
        .map_err(|_| VerificationError::VerificationFailed)});
    match verified {
    Ok(Ok(result)) => Ok(result),
    Ok(Err(e)) => Err(e),
    Err(_) => Err(VerificationError::InvalidProofFormat),
    }
    //Ok(verified) // true = valid, false = proof failed
}
