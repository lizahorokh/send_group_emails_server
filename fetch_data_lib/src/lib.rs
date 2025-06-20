use reqwest::get;
use num_traits::cast::ToPrimitive;
use num_bigint::BigUint;
use serde_json::Value;
use std::io;
use sha2::{Sha256, Sha512, Digest};
use serde::{Serialize, Deserialize};

use base64::decode;
use std::error::Error;

const BLOCK_SIZE :usize = 35;

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

async fn convert_byte_to_n(n : i32, array: Vec<u8>) -> Vec<u128>{
    //works with 128 > n > 8
    let mut new_array = Vec::new();
    let mut current_val : u128 = 0;
    let mut current_index : i32 = 0;
    let mut left : i32 = 0;
    let size = array.len();
    for i in 0 .. size{
        current_index = i as i32 * 8;
        if current_index / n == (current_index + 7) / n{
            if current_index % n == 0{
                if i != 0 {
                    new_array.push(current_val);
                    current_val = 0;
                }
            }
            current_val = current_val + (array[i as usize] as u128) << (current_index % n);
        }
        else{
            left = (n - current_index % n) % n;
            current_val = current_val + (array[i as usize] as u128 % ( 1 << left)) << (current_index % n);
            new_array.push(current_val);
            current_val = array[i as usize] as u128 / ( 1 << left);
        }
    }
    if current_val != 0{
        new_array.push(current_val);
    }
    new_array
}

async fn convert_byte_to_chunks_alternative(num_bits: u32, num_chunks: u32, array: Vec<u8>) -> Vec<u128>{
    let mut big_int : BigUint = BigUint::from_bytes_be(array[..].try_into().unwrap());
    let mut res : Vec<u128> = Vec::new();
    for i in 0 .. num_chunks {
        let curr : u128 = (big_int.clone() % (1u128 << num_bits.clone())).to_u128().unwrap();
        res.push(curr);
        big_int = big_int >> num_bits.clone();
    }
    // make sure that num_chunks is enough to cover the whole number
    assert!(big_int == BigUint::from(0u32));
    res
}

async fn pad_number_to_k(k: usize, array: &mut Vec<u128>){

    if array.len() < k {
        for _ in array.len() .. k {
            array.push(0);
        }
    }
}

pub async fn extract_rsa_from_ssh(ssh_key: &str) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let parts: Vec<&str> = ssh_key.trim().split_whitespace().collect();
    if parts.len() < 2 {
        return Err("Invalid SSH key format: should include key type".into());
    }

    // Validate key type
    if !parts[0].starts_with("ssh-rsa") {
        return Err(format!("Unsupported key type: {}", parts[0]).into());
    }
    let key_data = decode(parts[1])?;
    let mut offset = 0;

    // Helper function to read a u32 length-prefixed field
    async fn read_length(data: &[u8], offset: &mut usize) -> Result<usize, Box<dyn Error>> {
        if *offset + 4 > data.len() {
            return Err("Unexpected end of data when reading length".into());
        }
        let len = u32::from_be_bytes(data[*offset..*offset + 4].try_into()?) as usize;
        *offset += 4;
        
        // Validate length is reasonable
        if len > data.len() - *offset {
            return Err(format!("Invalid length {}: exceeds remaining data", len).into());
        }
        if len == 0 {
            return Err("Invalid length: zero length field".into());
        }
        
        Ok(len)
    }

    // Skip key type
    let key_type_len = read_length(&key_data, &mut offset).await?;
    
    // Validate key type string
    if key_type_len > key_data.len() - offset {
        return Err("Key type length exceeds data length".into());
    }
    let key_type = String::from_utf8_lossy(&key_data[offset..offset + key_type_len]);
    if key_type != "ssh-rsa" {
        return Err(format!("Invalid key type in data: {}", key_type).into());
    }
    offset += key_type_len;

    // Read e (exponent)
    let e_len = read_length(&key_data, &mut offset).await?;
    if e_len > key_data.len() - offset {
        return Err("Exponent length exceeds data length".into());
    }
    let e = key_data[offset..offset + e_len].to_vec();
    offset += e_len;

    // Read n (modulus)
    let n_len = read_length(&key_data, &mut offset).await?;
    if n_len > key_data.len() - offset {
        return Err("Modulus length exceeds data length".into());
    }
    let mut n = key_data[offset..offset + n_len].to_vec();
    
    // Remove leading zero if present (SSH sometimes encodes n with a leading 0)
    if !n.is_empty() && n[0] == 0x00 {
        n = n[1..].to_vec();
    }

    // Validate that we've consumed all data
    if offset + n_len != key_data.len() {
        return Err("Extra data after modulus".into());
    }

    Ok((n, e))
}

pub async fn parce_keys(all_data: &str) -> Vec<String>{
    let mut key_list: Vec<&str> = all_data.trim().split("ssh-").collect();
    let mut result : Vec<String> = Vec::new();
    for key in key_list{
        if key != ""{
            let mut parts: Vec<&str> = key.trim().split_whitespace().collect();
            if parts[0].starts_with("rsa") {
                let mut key = "ssh-rsa ".to_owned() + parts[1] + "\n";
                result.push(key.to_string());
            }
        }
    }
    result
}

pub async fn get_and_process_username(username : String) -> Result<Vec<Vec<u128>>, Box<dyn Error>> {
    let address = format!("{}{}{}", "https://github.com/", username, ".keys");
    let mut result : Vec<Vec<u128>> = Vec::new();
    println!("{}", address);
    match get(&address).await {
        Ok(response) => {
            if response.status().is_success() {
                match response.text().await {
                    Ok(body) => {
                        let mut list_keys = parce_keys(&body).await;
                        for key in list_keys{
                            let extracted_key = extract_rsa_from_ssh(&key).await.unwrap();
                            let mut convert = convert_byte_to_chunks_alternative(120, 35, extracted_key.0).await;
                            //pad_number_to_k(35 as usize, &mut convert).await;
                            result.push(convert);
                        }
                        return Ok(result);
                    },
                    Err(_err) =>{
                        return Err("Error reading response".into());
                    }
                }
            } else {
                return Err("Request failed".into());
            }

        }
        Err(_err) => {
            return Err("Request error".into());
        }
    }
}

pub async fn create_pb_signals_struct(list_usernames: Vec<String>, message: &str) -> PublicSignals{
    let mut hasher = Sha512::new();
    hasher.update(message.as_bytes());
    let mut message_hash = convert_byte_to_chunks_alternative(120, 5, hasher.finalize().to_vec()).await;
    //pad_number_to_k(5, &mut message_hash).await;
    let mut result = PublicSignals::new();
    result.message_hash = message_hash;
    for username in list_usernames{
        let keys = get_and_process_username(username.clone()).await.unwrap();
        println!("username {username:?} is processed");
        for key in keys{
            result.keys.push(key);
        }
    }
    return result;
}

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

pub async fn create_pb_signals(list_usernames: Vec<String>, message: &str) -> Vec<String>{
    convert_publicSignals(create_pb_signals_struct(list_usernames, message).await).await
}


