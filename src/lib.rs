pub mod input;
pub mod types;
pub mod utils;

use sha2::{Digest, Sha256};
pub use types::*;

/// Implements bitcoin's hash256 (double sha2).
/// Returns the digest.
///
/// # Arguments
///
/// * `preimage` - The pre-image
fn bitcoin_hash256(preimages: &[&[u8]]) -> Hash256Digest {
    let mut sha = Sha256::new();
    for preimage in preimages.iter() {
        sha.update(preimage);
    }
    let digest = sha.finalize();

    let mut second_sha = Sha256::new();
    second_sha.update(digest);
    let buf: [u8; 32] = second_sha.finalize().into();
    buf
}

/// Concatenates and hashes two inputs for merkle proving.
pub(crate) fn hash256_merkle_step(a: &[u8], b: &[u8]) -> Hash256Digest {
    bitcoin_hash256(&[a, b])
}

/// Verifies a Bitcoin-style merkle tree.
/// Leaves are 0-indexed.
/// Note that `index` is not a reliable indicator of location within a block.
pub fn merkle_root(leaf: &Hash256Digest, index: u32, siblings: &MerkleArray) -> Hash256Digest {
    let mut idx = index;
    let proof_len = siblings.len();

    if proof_len == 0 {
        return *leaf;
    }

    let mut current = *leaf;
    for i in 0..proof_len {
        let next = siblings.index(i);

        if idx % 2 == 1 {
            current = hash256_merkle_step(next.as_ref(), current.as_ref());
        } else {
            current = hash256_merkle_step(current.as_ref(), next.as_ref());
        }
        idx >>= 1;
    }

    current
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::*;

    #[test]
    fn test_merkle_proof() {
        let input_cases = get_input_cases("./test_vectors.json", "verifyHash256Merkle");
        for input_case in input_cases {
            let input = parse_input(&input_case);
            let root = merkle_root(&input.txid, input.index, &input.siblings);
            assert_eq!(root, input.root);
        }
    }

    #[test]
    fn test_merkle_proof_with_host() {
        let siblings = [
            19, 166, 215, 50, 115, 7, 158, 212, 133, 61, 236, 108, 94, 216, 234, 107, 225, 101, 91,
            148, 15, 222, 251, 10, 245, 166, 183, 239, 238, 147, 9, 86, 164, 23, 27, 224, 236, 49,
            19, 39, 156, 105, 52, 114, 168, 12, 27, 54, 107, 155, 15, 186, 167, 167, 167, 73, 180,
            228, 119, 145, 142, 83, 206, 240,
        ];

        let siblings = MerkleArray::new(&siblings).unwrap();
        let input = MerkleInput {
            txid: [
                121, 81, 106, 253, 54, 111, 216, 153, 14, 133, 137, 83, 23, 228, 101, 83, 245, 226,
                30, 196, 25, 206, 206, 73, 34, 106, 253, 81, 159, 111, 207, 133,
            ],
            index: 1,
            siblings,
            root: [
                107, 158, 174, 156, 7, 43, 25, 114, 13, 87, 145, 103, 55, 167, 39, 79, 210, 208,
                128, 64, 54, 158, 120, 166, 66, 221, 211, 254, 75, 184, 35, 122,
            ],
        };

        let root = merkle_root(&input.txid, input.index, &input.siblings);
        println!("root: {:?}", root);
        assert_eq!(root, input.root);
    }

    #[test]
    fn test_hash() {
        let left = "479dab8ccf7d2603386dddf9625d9c20c6d49cf9d7302ef0ade1e446625cb7ec";
        let right = "c3b2a2741892a2a30a1579fd66fabe157ea1eb7bebd006ad9061adf2a1a8cde2";

        let mut left = hex::decode(left).unwrap();
        let mut right = hex::decode(right).unwrap();
        left.reverse();
        right.reverse();

        let hash = hash256_merkle_step(&left, &right);
        println!("hash: {}", hex::encode(hash));
    }

    #[test]
    fn test_merkle_input() {
        // Get block transactions by [getblock.io](https://getblock.io/docs/btc/json-rpc/btc_getblock/) RPCs.
        // bitcoin mainnet 116928
        let txs = [
            "77a65018ade2ac9ec37e66ba35a9aaffe72f17b0750ed8c6ac746a6d19565454",
            "c518b7d7a61c800f5e5b182f72edcc8103910fb1254191e509fa6b9aee641a7c",
            "e9b2080d73bdfed05342a4f2702ce7d5190f83af2f3853a7093ccbf88494780e",
            "3046341af38ed5918e5ef4883dced8f3d1b4b19d08d02c0172b54530dd316e82",
            "c1bfd5d56eb8a999127f61987d155988583ef2e55090dd64ad669498510188cf",
            "6547e46183fa5f4c1e456faad1929b928254dbf484669ae6e58a132bd443f685",
            "7011a0b02226a565678c938ef574de0869d79aabc78510585207efefce4644b6",
            "dfefe12432ede593c3c8c6c6d42b044ce01d2e91aef4a073fe455b4d6ca68597",
            "0fda745581662314a6edf25ed7a3731c63684860e984682567a7ff7e8c82d1cc",
            "1836289e21127920c5cdb0ad9bf05896690d577c4a4835853fc9d50036bf79e9",
        ];

        let txs: Vec<[u8; 32]> = txs
            .iter()
            .map(|tx| {
                let mut raw: [u8; 32] = hex::decode(tx).unwrap().try_into().unwrap();
                raw.reverse();
                raw
            })
            .collect();

        let mut leaves = vec![];
        for tx in txs {
            leaves.extend_from_slice(&tx);
        }

        let index = 0;
        let leaves = MerkleArray::new(&leaves).unwrap();
        let merkle_input = input::create_merkle_input(&leaves, index).unwrap();
        let tx_id_leaf = leaves.index(index);
        let root = merkle_root(&tx_id_leaf, index as u32, &merkle_input.siblings);
        // root.reverse();
        // println!("root: {}", hex::encode(root));

        println!(
            "proof: {}{}{}",
            hex::encode(tx_id_leaf),
            merkle_input.siblings.str(),
            hex::encode(root)
        );
    }
}
