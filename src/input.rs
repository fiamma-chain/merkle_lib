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
            if proof_index_in_layer + 1 < current_layer.len() {
                proof.push(current_layer[proof_index_in_layer + 1].clone());
            } else {
                proof.push(current_layer[proof_index_in_layer].clone());
            }
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

#[test]
fn test_odd_txs() {
    let txs = [
        "f89c65bdcd695e4acc621256085f20d7c093097e04a1ce34b606a5829cbaf2c6",
        "1818bef9c6aeed09de0ed999b5f2868b3555084437e1c63f29d5f37b69bb214f",
        "d43a40a2db5bad2bd176c27911ed86d97bff734425953b19c8cf77910b21020d",
    ];
    let root = "34d5a57822efa653019edfee29b9586a0d0d807572275b45f39a7e9c25614bf9";

    test_txs(&txs, &root);
}

#[test]
fn test_even_txs() {
    let txs = [
        "590e6abd3f7bc242544216061a60a9131e95b1ccea2ec58186d04ce525f1f7d5",
        "cee36e9c7272a5c464609e398dd1d525ea181c55779ebb9a3c90ce905152f074",
        "ebe2985f6fa1c1ad96adab05879d1e13f7b50ffc873c960a9c8d600fd91565b4",
        "4baa10198dd7c351ac7f97602b6b8c5521613b284a580c2acdd17c9513b01d36",
    ];
    let root = "c83640427315a008b7ca9670201eab7363211566a7536a8ed446b36af222b338";

    test_txs(&txs, &root);
}

#[allow(dead_code)]
fn test_txs(txs: &[&str], expected_root: &str) {
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
    let merkle_input = create_merkle_input(&leaves, index).unwrap();
    let tx_id_leaf = leaves.index(index);
    let mut root = merkle_root(&tx_id_leaf, index as u32, &merkle_input.siblings);
    root.reverse();
    let root = hex::encode(root);

    assert_eq!(root.as_str(), expected_root);
}
