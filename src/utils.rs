use crate::types::{Hash256Digest, MerkleArray, MerkleInput};
use hex;
use std::fs::File;
use std::io::Read;

fn strip_0x_prefix(s: &str) -> &str {
    if &s[..2] == "0x" {
        &s[2..]
    } else {
        s
    }
}

fn deserialize_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(strip_0x_prefix(s))
}

// Returns the leaf, the siblings, and the expected root
pub fn extract_proof_components(proof: &str) -> (Hash256Digest, MerkleArray, Hash256Digest) {
    let extended_proof = deserialize_hex(proof).unwrap();
    let proof_len = extended_proof.len();
    if proof_len < 32 {
        panic!("Proof is too short");
    }

    let expected_root: Hash256Digest = extended_proof[proof_len - 32..].try_into().unwrap();
    let leaf: Hash256Digest = extended_proof[..32].try_into().unwrap();
    let siblings: Vec<u8> = if proof_len > 64 {
        extended_proof[32..proof_len - 32].to_vec()
    } else {
        vec![]
    };
    let siblings = MerkleArray::new(&siblings).unwrap();

    (leaf, siblings, expected_root)
}

fn load_inputs_file(inputs_file: &str) -> serde_json::Value {
    let mut file = File::open(inputs_file).unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();

    serde_json::from_str(&data).unwrap()
}

pub fn get_input_cases(inputs_file: &str, name: &str) -> Vec<serde_json::Value> {
    let fixtures = load_inputs_file(inputs_file);
    let vals: &Vec<serde_json::Value> = fixtures.get(name).unwrap().as_array().unwrap();
    vals.to_vec()
}

pub fn parse_input(test_case: &serde_json::Value) -> MerkleInput {
    let proof = test_case.get("proof").unwrap().as_str().unwrap();
    let index = test_case.get("index").unwrap().as_u64().unwrap();

    let (leaf, siblings, expected_root) = extract_proof_components(proof);

    MerkleInput {
        txid: leaf,
        index: index as u32,
        siblings,
        root: expected_root,
    }
}
