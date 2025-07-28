// Square attack encryption
use rand::prelude::*;

use crate::aes as aes;

pub fn encrypt_with_rounds(plaintext: &str, key: [u8; 16], rounds: u32) -> [u8; 16] {
    assert!(0 < rounds && rounds <= 11);
    let mut state = aes::transform(plaintext);
    let round_keys = aes::key_expansion(key);
    // Round 1
    state = aes::add_round_key(state, round_keys[0]);
    // Round 2 to 10
    for round in 1..((rounds-1) as usize) {
        state = aes::sub_bytes(state);
        state = aes::shift_rows(state);
        state = aes::mix_columns(state);
        state = aes::add_round_key(state, round_keys[round]);
    }
    // Round 11
    state = aes::sub_bytes(state);
    state = aes::shift_rows(state);
    state = aes::add_round_key(state, round_keys[10]);
    return state;
}

// Produces a Λ-set encrypyed with 3-round AES
pub fn setup(key: [u8; 16]) -> [[u8; 16]; 256] {
    let mut rng = rand::rng();
    let pad = rng.random::<u8>();
    let mut delta_set: [[u8; 16]; 256] = [[pad; 16]; 256];
    for i in 0..256 {
        delta_set[i][0] = i as u8;
        encrypt_with_rounds(&aes::inv_transform(delta_set[i]), key, 3);
    }
    return delta_set;
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use super::*;

    fn get_delta_set() -> [[u8; 16]; 256] {
        let key: [u8; 16] = [
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xaa,
        ];
        return setup(key);
    }

    #[test]
    fn test_delta_set_first_byte() {
        let delta_set = get_delta_set();
        let mut byte = delta_set[0][0];
        for i in 1..256 {
            byte ^= delta_set[i][0];
        }
        assert_eq!(byte, 0x00);
    }

    #[test]
    fn test_delta_set_other_bytes() {
        let delta_set = get_delta_set();
        for pos in 1..16 {
            let mut byte = delta_set[0][pos];
            for i in 1..256 {
                byte ^= delta_set[i][pos];
            }
            assert_eq!(byte, 0x00);
        }
    }
}
