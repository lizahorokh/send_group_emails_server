//! Utility functions for fetching GitHub users' RSA public keys and constructing
//! the `publicSignals` array expected by the Circom/zk-SNARK circuit. All
//! helpers are `async` where network or heavy computation is involved and can
//! therefore be called inside an asynchronous runtime (e.g. Tokio).

use reqwest::get;
use num_traits::cast::ToPrimitive;
use num_bigint::BigUint;
use serde_json::Value;
use std::{char::MAX, io};
use anyhow::{anyhow, Result};
use sha2::{Sha256, Sha512, Digest};
use serde::{Serialize, Deserialize};

use base64::decode;
use std::error::Error;

const BLOCK_SIZE :usize = 35;
const MAX_GROUP_SIZE : usize = 300;

/// Represents the data that will be passed to the circuit as `publicSignals`.
///
/// Fields
/// -------
/// * `message_hash` – SHA-512 digest of the message split into five 120-bit
///   limbs.
/// * `keys` – A collection of **exactly** `MAX_GROUP_SIZE` RSA public keys
///   (padded if necessary). Each key is itself split into 35 limbs of
///   120-bit width.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicSignals{

    message_hash: Vec<u128>,
    keys: Vec<Vec<u128>>
    
}

impl PublicSignals{
    pub fn new() -> Self{
        Self{
            message_hash: Vec:: new(),
            keys: Vec::new()
        }
    }
}

/// Converts an arbitrary-sized big-endian integer represented by `array` into a
/// vector of `num_chunks` limbs where each limb is `num_bits` bits wide. The
/// limbs are ordered little-endian (least-significant limb first) because this
/// is the format expected by most Circom gadgets.
///
/// Returns an error if the integer does not fit into the provided number of
/// chunks.
async fn convert_byte_to_chunks(num_bits: u32, num_chunks: u32, array: Vec<u8>) -> anyhow::Result<Vec<u128>>{
    let mut big_int : BigUint = BigUint::from_bytes_be(array[..].try_into().unwrap());
    let mut res : Vec<u128> = Vec::new();
    for i in 0 .. num_chunks {
        let curr : u128 = (big_int.clone() % (1u128 << num_bits.clone())).to_u128().unwrap();
        res.push(curr);
        big_int = big_int >> num_bits.clone();
    }
    // make sure that num_chunks is enough to cover the whole number
    if big_int != BigUint::from(0u32) {
        return Err(anyhow!(
            "Cannot convert number: value does not fit into {} chunks of {} bits",
            num_chunks,
            num_bits
        ));
    }
    Ok(res)
}

/// Parses an SSH-formatted RSA public key (the `ssh-rsa AAAAB3...` string) and
/// extracts the modulus `n` and exponent `e` in raw big-endian byte form.
///
/// The function performs basic validation on the key structure and returns
/// detailed errors when the format is unexpected.
pub async fn extract_rsa_from_ssh(ssh_key: &str) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let parts: Vec<&str> = ssh_key.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err(anyhow!("Invalid SSH key format: should include key type"));
    }

    // Validate key type
    if !parts[0].starts_with("ssh-rsa") {
        return Err(anyhow!("Unsupported key type: {}", parts[0]));
    }
    let key_data = decode(parts[1])?;
    let mut offset = 0;

    // Helper function to read a u32 length-prefixed field
    async fn read_length(data: &[u8], offset: &mut usize) -> anyhow::Result<usize> {
        if *offset + 4 > data.len() {
            return Err(anyhow!("Unexpected end of data when reading length"));
        }
        let len = u32::from_be_bytes(data[*offset..*offset + 4].try_into()?) as usize;
        *offset += 4;
        
        // Validate length is reasonable
        if len > data.len() - *offset {
            return Err(anyhow!("Invalid length {}: exceeds remaining data", len));
        }
        if len == 0 {
            return Err(anyhow!("Invalid length: zero length field"));
        }
        
        Ok(len)
    }

    // Skip key type
    let key_type_len = read_length(&key_data, &mut offset).await?;
    
    // Validate key type string
    if key_type_len > key_data.len() - offset {
        return Err(anyhow!("Key type length exceeds data length"));
    }
    let key_type = String::from_utf8_lossy(&key_data[offset..offset + key_type_len]);
    if key_type != "ssh-rsa" {
        return Err(anyhow!("Invalid key type in data: {}", key_type));
    }
    offset += key_type_len;

    // Read e (exponent)
    let e_len = read_length(&key_data, &mut offset).await?;
    if e_len > key_data.len() - offset {
        return Err(anyhow!("Exponent length exceeds data length"));
    }
    let e = key_data[offset..offset + e_len].to_vec();
    offset += e_len;

    // Read n (modulus)
    let n_len = read_length(&key_data, &mut offset).await?;
    if n_len > key_data.len() - offset {
        return Err(anyhow!("Modulus length exceeds data length"));
    }
    let mut n = key_data[offset..offset + n_len].to_vec();
    
    // Remove leading zero if present (SSH sometimes encodes n with a leading 0)
    if !n.is_empty() && n[0] == 0x00 {
        n = n[1..].to_vec();
    }

    // Validate that we've consumed all data
    if offset + n_len != key_data.len() {
        return Err(anyhow!("Extra data after modulus"));
    }

    Ok((n, e))
}

/// Splits the body returned by GitHub's `https://github.com/<user>.keys` API
/// into individual *RSA* keys (other key types are ignored).
pub async fn parce_keys(all_data: &str) -> anyhow::Result<Vec<String>>{
    let mut key_list: Vec<&str> = all_data.trim().split("ssh-").collect();
    let mut result : Vec<String> = Vec::new();
    for key in key_list{
        if key != ""{
            let mut parts: Vec<&str> = key.trim().split_whitespace().collect();
            if parts.len() < 2 {
                return Err(anyhow!(
                    "Unable to parse GitHub SSH keys: unexpected formatting detected"
                ));
            }
            if parts[0].starts_with("rsa") {
                let mut key = "ssh-rsa ".to_owned() + parts[1] + "\n";
                result.push(key.to_string());
            }
        }
    }
    Ok(result)
}

/// Downloads all RSA public keys of a GitHub user, extracts their moduli and
/// converts them into 120-bit limb representation suitable for the circuit.
pub async fn get_and_process_username(username : String) -> anyhow::Result<Vec<Vec<u128>>> {
    let address = format!("{}{}{}", "https://github.com/", username, ".keys");
    let mut result : Vec<Vec<u128>> = Vec::new();
    match get(&address).await {
        Ok(response) => {
            if response.status().is_success() {
                match response.text().await {
                    Ok(body) => {
                        let mut list_keys = parce_keys(&body).await?;
                        for key in list_keys{
                            let extracted_key = extract_rsa_from_ssh(&key).await?;
                            let mut convert = match convert_byte_to_chunks(120, 35, extracted_key.0).await {
                                Ok(body) => body ,
                                Err(err) => {
                                    return Err(anyhow!(
                                        "Failed to convert key chunks for user '{}': {}",
                                        username,
                                        err
                                    ))
                                },
                            };

                            result.push(convert);
                        }
                        return Ok(result);
                    },
                    Err(err) =>{
                        return Err(anyhow!(
                            "Error while downloading keys for user '{}': {}",
                            username,
                            err
                        ));
                    }
                }
            } else {
                return Err(anyhow!(
                    "GitHub returned a non-success status code for user '{}'",
                    username
                ));
            }

        }
        Err(err) => {
            return Err(anyhow!("HTTP request error: {}", err));
        }
    }
}

/// High-level helper that, given a list of GitHub usernames and a plain-text
/// `message`, constructs a fully-populated `PublicSignals` instance ready for
/// proof generation.
pub async fn create_pb_signals_struct(list_usernames: Vec<String>, message: &str) -> anyhow::Result<PublicSignals>{
    let mut hasher = Sha512::new();
    hasher.update(message.as_bytes());
    let mut message_hash = match convert_byte_to_chunks(120, 5, hasher.finalize().to_vec()).await{
        Ok(body) => body,
        Err(_err) => return Err(anyhow!("Error processing message. Please ensure that message is a string of ASCII characters.")),
    };
    let mut result = PublicSignals::new();
    result.message_hash = message_hash;
    let mut sorted_usernames: Vec<String> = list_usernames.clone();
    sorted_usernames.sort();
    for username in sorted_usernames{
        let keys = get_and_process_username(username.clone()).await?;
        for key in keys{
            result.keys.push(key);
        }
    }
    if result.keys.len() > MAX_GROUP_SIZE {
        return Err(anyhow!(
            "Too many keys in the group: maximum allowed is {}",
            MAX_GROUP_SIZE
        ));
    }  
    while (result.keys.len() < MAX_GROUP_SIZE){
        result.keys.push(result.keys[0].clone());
    }
    return Ok(result);
}

/// Flattens the nested `PublicSignals` structure into a single `Vec<String>` so
/// that it can be passed directly to snarkJS or a Circom verifier.
pub async fn convert_publicSignals(pb_signals: PublicSignals) -> Vec<String>{
    let mut result : Vec<String> = Vec::new();
    for block in pb_signals.message_hash{
        result.push(block.to_string());
    }
    
    for key in pb_signals.keys{
        for block in key{
            result.push(block.to_string());
        }
    } 
    result
}

/// Convenience wrapper that combines `create_pb_signals_struct` and
/// `convert_publicSignals` in one call.
pub async fn create_pb_signals(list_usernames: Vec<String>, message: &str) -> anyhow::Result<Vec<String>>{
    Ok(convert_publicSignals(create_pb_signals_struct(list_usernames, message).await?).await)
}


