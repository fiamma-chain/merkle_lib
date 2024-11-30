use serde::{Deserialize, Serialize};
/// The public values encoded as a struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicValuesStruct {
    pub n: u32,
    pub a: u32,
    pub b: u32,
}

#[derive(Debug)]
pub enum MerkleError {
    EmptyLeaves,
    InvalidIndex,
    BadMerkleProof,
}

pub type Hash256Digest = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleArray(Vec<u8>);

impl MerkleArray {
    /// Return a new merkle array from a slice
    pub fn new(data: &[u8]) -> Result<Self, MerkleError> {
        if data.len() % 32 == 0 {
            Ok(Self(data.to_vec()))
        } else {
            Err(MerkleError::BadMerkleProof)
        }
    }

    /// The length of the underlying vector
    pub fn len(&self) -> usize {
        self.0.len() / 32
    }

    /// Whether the underlying vector is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return the underlying bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Index into the merkle array
    pub fn index(&self, index: usize) -> Hash256Digest {
        let mut digest = Hash256Digest::default();
        digest
            .as_mut()
            .copy_from_slice(&self.0[index * 32..(index + 1) * 32]);
        digest
    }

    /// To hex string
    pub fn str(&self) -> String {
        hex::encode(&self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleInput {
    pub txid: Hash256Digest,
    pub index: u32,
    pub siblings: MerkleArray,
    pub root: Hash256Digest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerklePublicValues {
    pub txid: Hash256Digest,
    pub index: u32,
    pub siblings: MerkleArray,
    pub root: Hash256Digest,
    pub verified: bool,
}
