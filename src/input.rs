use crate::types::{MerkleArray, MerkleInput};

pub fn create_merkle_input(leaves: &MerkleArray, index: usize) -> MerkleInput {
    let mut siblings = Vec::new();
    let mut current_level = (0..leaves.len())
        .map(|i| leaves.index(i))
        .collect::<Vec<_>>();
    let mut current_index = index;

    while current_level.len() > 1 {
        let mut next_level = Vec::new();
        let mut i = 0;

        while i < current_level.len() {
            if i + 1 < current_level.len() {
                if i / 2 == current_index / 2 {
                    if current_index % 2 == 0 {
                        siblings.push(current_level[i + 1]);
                    } else {
                        siblings.push(current_level[i]);
                    }
                }

                let combined = crate::hash256_merkle_step(&current_level[i], &current_level[i + 1]);
                next_level.push(combined);
            } else {
                next_level.push(current_level[i]);
            }
            i += 2;
        }

        current_level = next_level;
        current_index /= 2;
    }

    let root = current_level[0];

    let siblings_bytes: Vec<u8> = siblings
        .iter()
        .flat_map(|hash| hash.iter())
        .cloned()
        .collect();

    MerkleInput {
        txid: leaves.index(index),
        index: index as u32,
        siblings: MerkleArray::new(&siblings_bytes).unwrap(),
        root,
    }
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
    let merkle_input = create_merkle_input(&merkle_array, 0);
    assert_eq!(merkle_input.root, root);
}
