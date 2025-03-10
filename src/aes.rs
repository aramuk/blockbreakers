// AES-128 encryption

// ------
// Round Key Expansion
// ------
const SBOX_EN: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn rot_word(word: u32) -> u32 {
    let mut rotated_bytes: [u8; 4] = word.to_be_bytes();
    let temp = rotated_bytes[0];
    rotated_bytes[0] = rotated_bytes[1];
    rotated_bytes[1] = rotated_bytes[2];
    rotated_bytes[2] = rotated_bytes[3];
    rotated_bytes[3] = temp;
    u32::from_be_bytes(rotated_bytes)
}

fn sub_word(word: u32) -> u32 {
    let bytes = word.to_be_bytes();
    let mut subbed_bytes: [u8; 4] = [0; 4];
    for i in 0..4 {
        subbed_bytes[i] = SBOX_EN[bytes[i] as usize];
    }
    u32::from_be_bytes(subbed_bytes)
}

fn rcon(i: i32) -> [u8; 4] {
    let mut rc: u32 = 1;
    for _ in 2..(i + 1) {
        if rc >= 0x80 {
            rc = (2 * rc) ^ 0x11b;
        } else {
            rc = 2 * rc;
        }
    }
    return [rc as u8, 0, 0, 0];
}

pub fn key_expansion(rk0: [u8; 16]) -> [[u8; 16]; 11] {
    let mut round_keys: [[u8; 16]; 11] = [[0x00; 16]; 11];
    round_keys[0] = rk0;
    for round in 1..11 {
        let prev0 = u32::from_be_bytes(round_keys[round - 1][0..4].try_into().unwrap());
        let prev1 = u32::from_be_bytes(round_keys[round - 1][4..8].try_into().unwrap());
        let prev2 = u32::from_be_bytes(round_keys[round - 1][8..12].try_into().unwrap());
        let prev3 = u32::from_be_bytes(round_keys[round - 1][12..16].try_into().unwrap());

        let new0 = sub_word(rot_word(prev3)) ^ prev0 ^ u32::from_be_bytes(rcon(round as i32));
        let new1 = new0 ^ prev1;
        let new2 = new1 ^ prev2;
        let new3 = new2 ^ prev3;

        round_keys[round][0..4].copy_from_slice(&new0.to_be_bytes());
        round_keys[round][4..8].copy_from_slice(&new1.to_be_bytes());
        round_keys[round][8..12].copy_from_slice(&new2.to_be_bytes());
        round_keys[round][12..16].copy_from_slice(&new3.to_be_bytes());
    }
    return round_keys;
}

// ------
// Utility functions
// ------
pub fn transform(plaintext: &str) -> [u8; 16] {
    let mut state: [u8; 16] = [0; 16];
    for (i, c) in plaintext[..state.len()].as_bytes().iter().enumerate() {
        state[i] = *c;
    }
    return state;
}

pub fn inv_transform(state: [u8; 16]) -> String {
    let mut plaintext = String::new();
    for c in state.iter() {
        plaintext.push(char::from(*c));
    }
    return plaintext;
}

pub fn print_state(state: [u8; 16]) {
    for i in 0..4 {
        for j in 0..4 {
            print!("{:#04x} ", state[j * 4 + i]);
        }
        println!();
    }
}

// ------
// Encryption
// ------
pub fn sub_bytes(state: [u8; 16]) -> [u8; 16] {
    let mut subbed_state: [u8; 16] = [0; 16];
    for i in 0..16 {
        subbed_state[i] = SBOX_EN[state[i] as usize];
    }
    return subbed_state;
}

pub fn shift_rows(state: [u8; 16]) -> [u8; 16] {
    let mut shifted_state: [u8; 16] = [0; 16];
    for i in 0..4 {
        shifted_state[i] = state[(i + 4 * i) % 16];
        shifted_state[i + 4] = state[(i + 4 + 4 * i) % 16];
        shifted_state[i + 8] = state[(i + 8 + 4 * i) % 16];
        shifted_state[i + 12] = state[(i + 12 + 4 * i) % 16];
    }
    return shifted_state;
}

// https://en.wikipedia.org/wiki/Rijndael_MixColumns#Implementation_example
fn dbl(a: u8) -> u8 {
    return (a << 1) ^ (0x1b * (a >> 7));
}

fn mul2(a: u8) -> u8 {
    return dbl(a);
}

fn mul3(a: u8) -> u8 {
    return dbl(a) ^ a;
}

pub fn mix_columns(state: [u8; 16]) -> [u8; 16] {
    let mut mixed_state: [u8; 16] = [0; 16];
    for i in 0..4 {
        let a0 = state[4 * i];
        let a1 = state[4 * i + 1];
        let a2 = state[4 * i + 2];
        let a3 = state[4 * i + 3];

        mixed_state[4 * i] = mul2(a0) ^ mul3(a1) ^ a2 ^ a3;
        mixed_state[4 * i + 1] = a0 ^ mul2(a1) ^ mul3(a2) ^ a3;
        mixed_state[4 * i + 2] = a0 ^ a1 ^ mul2(a2) ^ mul3(a3);
        mixed_state[4 * i + 3] = mul3(a0) ^ a1 ^ a2 ^ mul2(a3);
    }
    return mixed_state;
}

pub fn add_round_key(state: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    let mut added_state: [u8; 16] = [0; 16];
    for i in 0..16 {
        added_state[i] = state[i] ^ key[i];
    }
    return added_state;
}

// AES-128 encryption
pub fn encrypt(plaintext: &str, key: [u8; 16]) -> [u8; 16] {
    let mut state = transform(plaintext);
    let round_keys = key_expansion(key);
    // Round 1
    state = add_round_key(state, round_keys[0]);
    // Round 2 to 10
    for round in 1..10 {
        state = sub_bytes(state);
        state = shift_rows(state);
        state = mix_columns(state);
        state = add_round_key(state, round_keys[round]);
    }
    // Round 11
    state = sub_bytes(state);
    state = shift_rows(state);
    state = add_round_key(state, round_keys[10]);
    return state;
}

// ------
// AES-128 decryption
// ------
const INV_SBOX_EN: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

pub fn inv_sub_bytes(state: [u8; 16]) -> [u8; 16] {
    let mut inv_subbed_state: [u8; 16] = [0; 16];
    for i in 0..16 {
        inv_subbed_state[i] = INV_SBOX_EN[state[i] as usize];
    }
    return inv_subbed_state;
}

pub fn inv_shift_rows(state: [u8; 16]) -> [u8; 16] {
    let mut inv_shifted_state: [u8; 16] = [0; 16];
    for i in 0..4 {
        inv_shifted_state[i] = state[(i + 12 * i) % 16];
        inv_shifted_state[i + 4] = state[(i + 4 + 12 * i) % 16];
        inv_shifted_state[i + 8] = state[(i + 8 + 12 * i) % 16];
        inv_shifted_state[i + 12] = state[(i + 12 + 12 * i) % 16];
    }
    return inv_shifted_state;
}

fn mul9(a: u8) -> u8 {
    return dbl(dbl(dbl(a))) ^ a;
}

fn mul11(a: u8) -> u8 {
    let a2 = dbl(a);
    let a8 = dbl(dbl(a2));
    return a8 ^ a2 ^ a;
}

fn mul13(a: u8) -> u8 {
    let a4 = dbl(dbl(a));
    let a8 = dbl(a4);
    return a8 ^ a4 ^ a;
}

fn mul14(a: u8) -> u8 {
    let a2 = dbl(a);
    let a4 = dbl(a2);
    let a8 = dbl(a4);
    return a8 ^ a4 ^ a2;
}

pub fn inv_mix_columns(state: [u8; 16]) -> [u8; 16] {
    let mut inv_mixed_state: [u8; 16] = [0; 16];
    for i in 0..4 {
        let a0 = state[4 * i];
        let a1 = state[4 * i + 1];
        let a2 = state[4 * i + 2];
        let a3 = state[4 * i + 3];

        inv_mixed_state[4 * i] = mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3);
        inv_mixed_state[4 * i + 1] = mul9(a0) ^ mul14(a1) ^ mul11(a2) ^ mul13(a3);
        inv_mixed_state[4 * i + 2] = mul13(a0) ^ mul9(a1) ^ mul14(a2) ^ mul11(a3);
        inv_mixed_state[4 * i + 3] = mul11(a0) ^ mul13(a1) ^ mul9(a2) ^ mul14(a3);
    }
    return inv_mixed_state;
}

pub fn inv_add_round_key(state: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    // Inverse of XOR is itself.
    return add_round_key(state, key);
}


pub fn decrypt(ciphertext: [u8; 16], key: [u8; 16]) -> String {
    let mut state = ciphertext;
    let round_keys = key_expansion(key);
    // Round 10
    state = inv_add_round_key(state, round_keys[10]);
    state = inv_shift_rows(state);
    state = inv_sub_bytes(state);
    // Round 9 to 1
    for round in (1..10).rev() {
        state = inv_add_round_key(state, round_keys[round]);
        state = inv_mix_columns(state);
        state = inv_shift_rows(state);
        state = inv_sub_bytes(state);
    }
    // Round 0
    state = inv_add_round_key(state, round_keys[0]);
    return inv_transform(state);
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rot_word() {
        let case1: u32 = 0x00010203u32;
        assert_eq!(rot_word(case1), 0x01020300u32);
    }

    #[test]
    fn test_sub_word() {
        let case1: u32 = 0x0001c29e;
        assert_eq!(sub_word(case1), 0x637c250b);
    }

    #[test]
    fn test_rcon() {
        let cases = [
            (1, [0x1, 0, 0, 0]),
            (4, [0x08, 0, 0, 0]),
            (8, [0x80, 0, 0, 0]),
            (16, [0x2f, 0, 0, 0]),
            (32, [0x72, 0, 0, 0]),
            (64, [0xab, 0, 0, 0]),
            (255, [0x8d, 0, 0, 0]),
        ];
        for (i, expected) in cases {
            assert_eq!(rcon(i), expected);
        }
    }

    #[test]
    fn test_key_expansion() {
        let case1 = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        assert_eq!(key_expansion(case1), [
            [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
            [0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05],
            [0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f],
            [0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b],
            [0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00],
            [0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc],
            [0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd],
            [0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f],
            [0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f],
            [0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e],
            [0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6],
        ]);
    }

    #[test]
    fn test_transform() {
        let case1 = "this is one text";
        let state = transform(case1);
        print_state(state);
        assert_eq!(state, [
            0x74, 0x68, 0x69, 0x73,
            0x20, 0x69, 0x73, 0x20,
            0x6f, 0x6e, 0x65, 0x20,
            0x74, 0x65, 0x78, 0x74
        ]);
    }

    #[test]
    fn test_sub_bytes() {
        let state = [
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f
        ];
        let subbed_state = sub_bytes(state);
        print_state(subbed_state);
        assert_eq!(
            subbed_state,
            [
                0x63, 0x7c, 0x77, 0x7b,
                0xf2, 0x6b, 0x6f, 0xc5,
                0x30, 0x01, 0x67, 0x2b,
                0xfe, 0xd7, 0xab, 0x76
            ]
        );
    }

    #[test]
    fn test_shift_rows() {
        let state = [
            0x63, 0x7c, 0x77, 0x7b,
            0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b,
            0xfe, 0xd7, 0xab, 0x76,
        ];
        let shifted_state = shift_rows(state);
        print_state(shifted_state);
        assert_eq!(shifted_state, [
            0x63, 0x6b, 0x67, 0x76,
            0xf2, 0x01, 0xab, 0x7b,
            0x30, 0xd7, 0x77, 0xc5,
            0xfe, 0x7c, 0x6f, 0x2b
        ]);
    }

    #[test]
    fn test_mix_columns() {
        let state = [
            0x63, 0x6b, 0x67, 0x76,
            0xf2, 0x01, 0xab, 0x7b,
            0x30, 0xd7, 0x77, 0xc5,
            0xfe, 0x7c, 0x6f, 0x2b
        ];
        let mixed_state = mix_columns(state);
        print_state(mixed_state);
        assert_eq!(mixed_state, [
            0x6a, 0x6a, 0x5c, 0x45,
            0x2c, 0x6d, 0x33, 0x51,
            0xb0, 0xd9, 0x5d, 0x61,
            0x27, 0x9c, 0x21, 0x5c
        ]);
    }

    #[test]
    fn test_add_round_key() {
        let state = [
            0x6a, 0x6a, 0x5c, 0x45,
            0x2c, 0x6d, 0x33, 0x51,
            0xb0, 0xd9, 0x5d, 0x61,
            0x27, 0x9c, 0x21, 0x5c
        ];
        let key = [
            0xd6, 0xaa, 0x74, 0xfd,
            0xd2, 0xaf, 0x72, 0xfa,
            0xda, 0xa6, 0x78, 0xf1,
            0xd6, 0xab, 0x76, 0xfe
        ];
        let added_state = add_round_key(state, key);
        print_state(added_state);
        assert_eq!(added_state, [
            0xbc, 0xc0, 0x28, 0xb8,
            0xfe, 0xc2, 0x41, 0xab,
            0x6a, 0x7f, 0x25, 0x90,
            0xf1, 0x37, 0x57, 0xa2
        ]);
    }

    #[test]
    fn test_encrypt() {
        let plaintext = "theblockbreakers";
        let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let ciphertext = encrypt(plaintext, key);

        print_state(ciphertext);
        assert_eq!(ciphertext, [
            0xc6, 0x9f, 0x25, 0xd0,
            0x02, 0x5a, 0x9e, 0xf3,
            0x23, 0x93, 0xf6, 0x3e,
            0x2f, 0x05, 0xb7, 0x47
        ]);
    }

    #[test]
    fn test_decrypt() {
        let ciphertext = [0xc6, 0x9f, 0x25, 0xd0, 0x02, 0x5a, 0x9e, 0xf3, 0x23, 0x93, 0xf6, 0x3e, 0x2f, 0x05, 0xb7, 0x47];
        let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];

        let plaintext = decrypt(ciphertext, key);

        assert_eq!(plaintext.as_str(), "theblockbreakers");
    }

    #[test]
    fn test_inv_sbox_en() {
        for i in 0..256 {
            assert_eq!(i as u8, INV_SBOX_EN[SBOX_EN[i] as usize]);
        }
    }

    #[test]
    fn test_inv_sub_bytes() {
        let state =             [
            0x63, 0x7c, 0x77, 0x7b,
            0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b,
            0xfe, 0xd7, 0xab, 0x76
        ];
        let inv_subbed_state = inv_sub_bytes(state);
        print_state(inv_subbed_state);
        assert_eq!(inv_subbed_state, [
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f
        ]);
    }

    #[test]
    fn test_inv_shift_rows() {
        let state =[
            0x63, 0x6b, 0x67, 0x76,
            0xf2, 0x01, 0xab, 0x7b,
            0x30, 0xd7, 0x77, 0xc5,
            0xfe, 0x7c, 0x6f, 0x2b
        ];
        let inv_shifted_state = inv_shift_rows(state);
        print_state(inv_shifted_state);
        assert_eq!(inv_shifted_state,  [
            0x63, 0x7c, 0x77, 0x7b,
            0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b,
            0xfe, 0xd7, 0xab, 0x76,
        ]);
    }

    #[test]
    fn test_inv_mix_columns() {
        let state = [
            0x6a, 0x6a, 0x5c, 0x45,
            0x2c, 0x6d, 0x33, 0x51,
            0xb0, 0xd9, 0x5d, 0x61,
            0x27, 0x9c, 0x21, 0x5c
        ];
        let inv_mixed_state = inv_mix_columns(state);
        print_state(inv_mixed_state);
        assert_eq!(inv_mixed_state, [
            0x63, 0x6b, 0x67, 0x76,
            0xf2, 0x01, 0xab, 0x7b,
            0x30, 0xd7, 0x77, 0xc5,
            0xfe, 0x7c, 0x6f, 0x2b
        ]);
    }

    #[test]
    fn test_inv_add_round_key() {
        let state = [
            0xbc, 0xc0, 0x28, 0xb8,
            0xfe, 0xc2, 0x41, 0xab,
            0x6a, 0x7f, 0x25, 0x90,
            0xf1, 0x37, 0x57, 0xa2
        ];
        let key = [
            0xd6, 0xaa, 0x74, 0xfd,
            0xd2, 0xaf, 0x72, 0xfa,
            0xda, 0xa6, 0x78, 0xf1,
            0xd6, 0xab, 0x76, 0xfe
        ];
        let inv_added_state = inv_add_round_key(state, key);
        print_state(inv_added_state);
        assert_eq!(inv_added_state, [
            0x6a, 0x6a, 0x5c, 0x45,
            0x2c, 0x6d, 0x33, 0x51,
            0xb0, 0xd9, 0x5d, 0x61,
            0x27, 0x9c, 0x21, 0x5c
        ]);
    }

    #[test]
    fn test_mul(){
        assert_eq!(mul2(0x01), 0x02);
        assert_eq!(mul3(0x01), 0x03);
        assert_eq!(mul9(0x01), 0x09);
        assert_eq!(mul11(0x01), 0x0b);
        assert_eq!(mul13(0x01), 0x0d);
        assert_eq!(mul14(0x01), 0x0e);
    }
}

