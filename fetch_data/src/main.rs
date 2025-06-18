use reqwest::blocking::get;
use serde_json::Value;
use std::io;
//use byteorder::{BigEndian, ByteOrder};
//use regex::Regex;

/*fn clean_base64(data: &str) -> String {
    // Remove all whitespace
    let re = Regex::new(r"\s+").unwrap();
    let mut cleaned = re.replace_all(data, "").to_string();

    // If "Signature:" is present, take everything after it
    if let Some(pos) = cleaned.find("Signature:") {
        cleaned = cleaned[pos + "Signature:".len()..].to_string();
    }

    // Pad with '=' to make the length a multiple of 4
    let padding = (4 - cleaned.len() % 4) % 4;
    cleaned.push_str(&"=".repeat(padding));

    cleaned
}

fn read_u32(blob: &[u8], offset: usize) -> (u32, usize) {
    let value = BigEndian::read_u32(&blob[offset..offset + 4]);
    (value, offset + 4)
}

fn read_string(blob: &[u8], offset: usize) -> (&[u8], usize) {
    let (length, new_offset) = read_u32(blob, offset);
    let end = new_offset + length as usize;
    (&blob[new_offset..end], end)
}

fn peel_mpint(blob: &[u8]) -> &[u8] {
    if blob.len() > 4 {
        let len = BigEndian::read_u32(&blob[0..4]) as usize;
        if len == blob.len() - 4 {
            return &blob[4..];
        }
    }
    blob
}

fn parse_ssh_signature(b64_blob: &str) -> Option<(&[u8], &[u8])> {
    let cleaned = clean_base64(b64_blob);
    let blob = general_purpose::STANDARD.decode(cleaned).ok()?;

    if &blob[0..6] != b"SSHSIG" {
        eprintln!("Bad magic: {:?}", &blob[0..6]);
        return None;
    }

    let mut off = 6;
    let (_, new_off) = read_uint32(&blob, off); // skip version
    off = new_off;

    let (pub_blob, new_off) = read_string(&blob, off);
    off = new_off;
    let (_, new_off) = read_string(&blob, off);
    off = new_off;
    let (_, new_off) = read_string(&blob, off);
    off = new_off;
    let (_, new_off) = read_string(&blob, off);
    off = new_off;

    let (sig_blob, _) = read_string(&blob, off);
    let (_, sig_off2) = read_string(sig_blob, 0);
    let (sig_mpint, _) = read_string(sig_blob, sig_off2);

    Some((pub_blob, peel_mpint(sig_mpint)))
}

fn parse_rsa_public_key(pk::String) -> ()*/

use base64::decode;
use std::error::Error;

fn convert_byte_to_n(n : i32, array: Vec<u8>) -> Vec<u128>{
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
            current_val = current_val * 256 + array[i as usize] as u128;
        }
        else{
            left = (n - current_index % n) % n;
            current_val = current_val * (1 << left) + array[i as usize] as u128 / ( 1 << (8 - left));
            new_array.push(current_val);
            current_val = array[i as usize] as u128 % ( 1 << (8 - left));
        }
    }
    if current_val != 0{
        new_array.push(current_val);
    }
    new_array
}

fn extract_rsa_from_ssh(ssh_key: &str) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
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
    fn read_length(data: &[u8], offset: &mut usize) -> Result<usize, Box<dyn Error>> {
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
    let key_type_len = read_length(&key_data, &mut offset)?;
    
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
    let e_len = read_length(&key_data, &mut offset)?;
    if e_len > key_data.len() - offset {
        return Err("Exponent length exceeds data length".into());
    }
    let e = key_data[offset..offset + e_len].to_vec();
    offset += e_len;

    // Read n (modulus)
    let n_len = read_length(&key_data, &mut offset)?;
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


fn main(){
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let address = format!("{}{}{}", "https://github.com/", input.trim(), ".keys");
    println!("{}", address);
    match get(&address) {
        Ok(response) => {
            if response.status().is_success() {
                match response.text() {
                    Ok(body) => {
                        let extracted_key = extract_rsa_from_ssh(&body).unwrap();
                        println!("Response:\n{}\nExtracted N: {:?}\nExtracted E: {:?}\n", &body[7..],  convert_byte_to_n(120, extracted_key.0), convert_byte_to_n(120, extracted_key.1));
                    },
                        Err(err) => eprintln!("Error reading response: {}", err),
                }
            } else {
                eprintln!("Request failed with status: {}", response.status());
            }
        }
        Err(err) => eprintln!("Request error: {}", err),
    }
}
