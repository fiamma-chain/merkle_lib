use crate::{
    merkle_root,
    types::{MerkleArray, MerkleError, MerkleInput},
};

pub fn create_merkle_input(leaves: &MerkleArray, index: usize) -> Result<MerkleInput, MerkleError> {
    let siblings = get_merkle_proof(leaves, index)?;
    let leaf = leaves.index(index);
    let root = merkle_root(&leaf, index as u32, &siblings);
    Ok(MerkleInput {
        txid: leaf,
        index: index as u32,
        siblings,
        root,
    })
}

pub fn get_merkle_proof(leaves: &MerkleArray, index: usize) -> Result<MerkleArray, MerkleError> {
    let tx_len = leaves.len();
    if tx_len == 0 {
        return Err(MerkleError::EmptyLeaves);
    }
    if tx_len == 1 {
        return Ok(MerkleArray::new(&[]).unwrap());
    }
    if index >= tx_len {
        return Err(MerkleError::InvalidIndex);
    }
    let mut layers = Vec::new();
    let mut proof = Vec::new();
    let layer = (0..leaves.len())
        .map(|i| leaves.index(i))
        .collect::<Vec<_>>();

    layers.push(layer);
    let mut current_layer_index = 0;
    let mut proof_index_in_layer = index;
    loop {
        let mut current_layer = layers[current_layer_index].iter();
        let current_layer_len = current_layer.len();
        if current_layer_len <= 1 {
            break;
        }
        let new_layer_len = current_layer_len / 2 + current_layer_len % 2;
        let mut new_layer = Vec::with_capacity(new_layer_len);
        while let Some(hash1) = current_layer.next() {
            let hash2 = current_layer.next().unwrap_or(hash1);
            new_layer.push(crate::hash256_merkle_step(hash1, hash2));
        }
        layers.push(new_layer);
        let current_layer = layers[current_layer_index].clone();
        if proof_index_in_layer % 2 == 0 {
            proof.push(current_layer[proof_index_in_layer + 1].clone());
        } else {
            proof.push(current_layer[proof_index_in_layer - 1].clone());
        }
        proof_index_in_layer >>= 1;
        current_layer_index += 1;
    }
    MerkleArray::new(&proof.into_flattened())
}

#[test]
fn test_create_merkle_input() {
    let left = [
        33, 218, 42, 232, 204, 119, 59, 2, 11, 72, 115, 245, 151, 54, 148, 22, 207, 150, 26, 24,
        150, 194, 65, 6, 176, 25, 132, 89, 254, 194, 223, 119,
    ];
    let right = [
        51, 157, 154, 55, 30, 43, 90, 38, 20, 125, 223, 216, 114, 40, 185, 0, 255, 117, 118, 42,
        24, 164, 15, 39, 120, 190, 219, 205, 231, 233, 176, 163,
    ];
    let root = [
        191, 68, 115, 229, 55, 148, 190, 174, 52, 230, 79, 204, 196, 113, 218, 206, 106, 229, 68,
        24, 8, 22, 248, 149, 145, 137, 78, 15, 65, 122, 145, 76,
    ];

    let mut leaves = Vec::new();
    leaves.extend_from_slice(&left);
    leaves.extend_from_slice(&right);

    let merkle_array = MerkleArray::new(&leaves).unwrap();
    let merkle_input = create_merkle_input(&merkle_array, 0).unwrap();
    assert_eq!(merkle_input.root, root);
}
