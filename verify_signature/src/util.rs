//! util.rs  (only the parts that change are shown)
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ec::pairing::Pairing;
use num_bigint::BigUint;
use serde::Deserialize;
use ark_ff::{BigInteger256, PrimeField};

pub type E  = Bn254;
pub type Fr = <E as Pairing>::ScalarField;

/* ---------- updated JSON mirrors ------------------------------------- */

#[derive(Deserialize)]
pub struct ProofJson {
    /// SnarkJS gives 3 field elements (x,y,z).  We ignore z.
    pub pi_a: Vec<String>,               // len = 3
    /// 3 × Fq2 projective coords.  We need only the first two arrays.
    pub pi_b: Vec<[String; 2]>,          // len = 3
    pub pi_c: Vec<String>,               // len = 3
}

#[derive(Deserialize)]
pub struct VkJson {
    #[serde(rename = "nPublic")]
    pub n_public: usize,

    #[serde(rename = "vk_alpha_1")]
    pub alpha_1: Vec<String>,           // len = 3

    #[serde(rename = "vk_beta_2")]
    pub beta_2:  Vec<[String; 2]>,      // len = 3

    #[serde(rename = "vk_gamma_2")]
    pub gamma_2: Vec<[String; 2]>,      // len = 3

    #[serde(rename = "vk_delta_2")]
    pub delta_2: Vec<[String; 2]>,      // len = 3

    #[serde(rename = "IC")]
    pub ic:      Vec<Vec<String>>,      // each len = 3
}

// -- 3. parsing helpers ---------------------------------------------------

pub fn g1_from_vec(v: &[String]) -> G1Affine {
    G1Affine::new(fq(&v[0]), fq(&v[1]))
}

pub fn g2_from_vecs(v: &[[String; 2]]) -> G2Affine {
    let x = Fq2::new(fq(&v[0][0]), fq(&v[0][1]));
    let y = Fq2::new(fq(&v[1][0]), fq(&v[1][1]));
    G2Affine::new(x, y)
}

fn fq(s: &str) -> Fq {
    // 1. decimal string → BigUint
    let bn = BigUint::parse_bytes(s.as_bytes(), 10)
        .expect("not a base-10 string");

    // 2. BigUint → ark_ff::BigInteger256 (fails only if > 256 bits)
    let bi = BigInteger256::try_from(bn)
        .expect("integer does not fit into 256 bits");

    // 3. BigInteger256 → field element
    Fq::from_bigint(bi).expect("not in field modulus")
}

fn fq_from_dec(s: &str) -> Fq {
    let bn = BigUint::parse_bytes(s.as_bytes(), 10).expect("decimal string");
    let mut bytes = bn.to_bytes_be();
    if bytes.len() < 32 {             // pad to 32 bytes
        let mut pad = vec![0u8; 32 - bytes.len()];
        pad.extend(bytes);
        bytes = pad;
    }
    Fq::from_be_bytes_mod_order(&bytes)
}

pub fn fr_from_dec(s: &str) -> Fr {
    use ark_ff::BigInteger;
    let bn = BigUint::parse_bytes(s.as_bytes(), 10).unwrap();
    let mut bytes = bn.to_bytes_be();
    if bytes.len() < 32 {
        let mut pad = vec![0u8; 32 - bytes.len()];
        pad.extend(bytes);
        bytes = pad;
    }
    Fr::from_be_bytes_mod_order(&bytes)
}

pub fn g1(coords: &[String; 2]) -> G1Affine {
    G1Affine::new(fq_from_dec(&coords[0]), fq_from_dec(&coords[1]))
}

pub fn g2(coords: &[[String; 2]; 2]) -> G2Affine {
    let x = Fq2::new(fq_from_dec(&coords[0][0]), fq_from_dec(&coords[0][1]));
    let y = Fq2::new(fq_from_dec(&coords[1][0]), fq_from_dec(&coords[1][1]));
    G2Affine::new(x, y)
}
