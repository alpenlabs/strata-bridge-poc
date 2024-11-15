use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::{AdditiveGroup, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use sha2::{Digest, Sha256};

pub const MASK: u8 = 0b11 << 6;

pub const COMPRESSED_POSTIVE: u8 = 0b10 << 6;
pub const COMPRESSED_NEGATIVE: u8 = 0b11 << 6;
pub const COMPRESSED_INFINITY: u8 = 0b01 << 6;

// pub const GROTH16_VK_BYTES: &[u8] = include_bytes!("../artifacts/sp1v3_groth16_vk.bin");

#[derive(Debug, PartialEq)]
pub enum CompressionFlag {
    Positive = COMPRESSED_POSTIVE as isize,
    Negative = COMPRESSED_NEGATIVE as isize,
    Infinity = COMPRESSED_INFINITY as isize,
}

impl From<u8> for CompressionFlag {
    fn from(val: u8) -> Self {
        match val {
            COMPRESSED_POSTIVE => CompressionFlag::Positive,
            COMPRESSED_NEGATIVE => CompressionFlag::Negative,
            COMPRESSED_INFINITY => CompressionFlag::Infinity,
            _ => panic!("Invalid compressed point flag"),
        }
    }
}

impl From<CompressionFlag> for u8 {
    fn from(value: CompressionFlag) -> Self {
        value as u8
    }
}

pub fn is_zeroed(first_byte: u8, buf: &[u8]) -> bool {
    if first_byte != 0 {
        return false;
    }
    for &b in buf {
        if b != 0 {
            return false;
        }
    }
    true
}

pub fn hash_bn254_be_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut hash: [u8; 32] = hasher.finalize().into();
    hash[0] &= 0b00011111; // mask 3 most significant bits
    hash
}

pub fn deserialize_with_flags(buf: &[u8; 32]) -> (Fq, CompressionFlag) {
    let m_data = buf[0] & MASK;
    if m_data == <CompressionFlag as Into<u8>>::into(CompressionFlag::Infinity) {
        if !is_zeroed(buf[0] & !MASK, &buf[1..32]) {
            panic!("invalid point")
        }
        (Fq::ZERO, CompressionFlag::Infinity)
    } else {
        let mut x_bytes: [u8; 32] = [0u8; 32];
        x_bytes.copy_from_slice(buf);
        x_bytes[0] &= !MASK;
        let x = Fq::from_be_bytes_mod_order(&x_bytes);
        (x, m_data.into())
    }
}

pub fn g1_point_from_compressed_x_bytes(buf: &[u8; 32]) -> G1Affine {
    let (x, m_data) = deserialize_with_flags(buf);
    let (y, neg_y) = G1Affine::get_ys_from_x_unchecked(x).unwrap();
    let mut final_y = y;
    if y > neg_y {
        if m_data == CompressionFlag::Positive {
            final_y = -y;
        }
    } else if m_data == CompressionFlag::Negative {
        final_y = -y;
    }
    G1Affine::new(x, final_y)
}

pub fn g1_point_from_compressed_x_unchecked_bytes(buf: &[u8; 32]) -> G1Affine {
    let (x, m_data) = deserialize_with_flags(buf);
    let (y, neg_y) = G1Affine::get_ys_from_x_unchecked(x).unwrap();

    let mut final_y = y;
    if y > neg_y {
        if m_data == CompressionFlag::Positive {
            final_y = -y;
        }
    } else if m_data == CompressionFlag::Negative {
        final_y = -y;
    }
    G1Affine::new_unchecked(x, final_y)
}

pub fn g1_point_from_uncompressed_bytes(buf: &[u8; 64]) -> G1Affine {
    let (x_bytes, y_bytes) = buf.split_at(32);
    let x = Fq::from_be_bytes_mod_order(x_bytes);
    let y = Fq::from_be_bytes_mod_order(y_bytes);
    G1Affine::new(x, y)
}

pub fn g2_point_from_compressed_x_bytes(buf: &[u8; 64]) -> G2Affine {
    let (x1, flag) = deserialize_with_flags(&buf[..32].try_into().unwrap());
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64]);
    let x = Fq2::new(x0, x1);

    if flag == CompressionFlag::Infinity {
        return G2Affine::identity();
    }

    let (y, neg_y) = G2Affine::get_ys_from_x_unchecked(x).unwrap();

    match flag {
        CompressionFlag::Positive => G2Affine::new(x, y),
        CompressionFlag::Negative => G2Affine::new(x, neg_y),
        _ => panic!("invalid point"),
    }
}

pub fn g2_point_from_compressed_x_bytes_unchecked(buf: &[u8; 64]) -> G2Affine {
    let (x1, flag) = deserialize_with_flags(&buf[..32].try_into().unwrap());
    let x0 = Fq::from_be_bytes_mod_order(&buf[32..64]);
    let x = Fq2::new(x0, x1);

    if flag == CompressionFlag::Infinity {
        return G2Affine::identity();
    }

    let (y, neg_y) = G2Affine::get_ys_from_x_unchecked(x).unwrap();

    match flag {
        CompressionFlag::Positive => G2Affine::new_unchecked(x, y),
        CompressionFlag::Negative => G2Affine::new_unchecked(x, neg_y),
        _ => panic!("invalid point"),
    }
}

pub fn g2_point_from_uncompressed_bytes(buf: &[u8; 128]) -> G2Affine {
    let (x_bytes, y_bytes) = buf.split_at(64);
    let (x1_bytes, x0_bytes) = x_bytes.split_at(32);
    let (y1_bytes, y0_bytes) = y_bytes.split_at(32);

    let x1 = Fq::from_be_bytes_mod_order(x1_bytes);
    let x0 = Fq::from_be_bytes_mod_order(x0_bytes);
    let y1 = Fq::from_be_bytes_mod_order(y1_bytes);
    let y0 = Fq::from_be_bytes_mod_order(y0_bytes);

    let x = Fq2::new(x0, x1);
    let y = Fq2::new(y0, y1);

    G2Affine::new(x, y)
}

pub fn load_groth16_proof_from_bytes(buffer: &[u8]) -> Proof<Bn254> {
    let a = g1_point_from_uncompressed_bytes(buffer[..64].try_into().unwrap());
    let b = g2_point_from_uncompressed_bytes(buffer[64..192].try_into().unwrap());
    let c = g1_point_from_uncompressed_bytes(buffer[192..256].try_into().unwrap());
    Proof::<_> { a, b, c }
}

pub fn load_groth16_verifying_key_from_bytes(buffer: &[u8]) -> VerifyingKey<Bn254> {
    let alpha_g1 = g1_point_from_compressed_x_unchecked_bytes(&buffer[..32].try_into().unwrap());
    let _beta_g1 = g1_point_from_compressed_x_unchecked_bytes(&buffer[32..64].try_into().unwrap());
    let beta_g2 = g2_point_from_compressed_x_bytes_unchecked(&buffer[64..128].try_into().unwrap());
    let gamma_g2 =
        g2_point_from_compressed_x_bytes_unchecked(&buffer[128..192].try_into().unwrap());
    let _delta_g1 =
        g1_point_from_compressed_x_unchecked_bytes(&buffer[192..224].try_into().unwrap());
    let delta_g2 =
        g2_point_from_compressed_x_bytes_unchecked(&buffer[224..288].try_into().unwrap());

    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut gamma_abc_g1 = Vec::new();
    let mut offset = 292;
    for _ in 0..num_k {
        let point = g1_point_from_compressed_x_unchecked_bytes(
            &buffer[offset..offset + 32].try_into().unwrap(),
        );
        gamma_abc_g1.push(point);
        offset += 32;
    }
    VerifyingKey::<_> {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        gamma_abc_g1,
    }
}

#[cfg(test)]
mod tests {
    use ark_bn254::{Bn254, Fr};
    use ark_ff::PrimeField;
    use ark_groth16::{prepare_verifying_key, Groth16};

    use super::*;

    const PROOF_BYTES: [u8; 256] = [
        3, 19, 181, 171, 106, 36, 254, 91, 176, 187, 23, 155, 242, 49, 77, 18, 29, 61, 133, 124,
        173, 153, 46, 211, 86, 5, 150, 151, 220, 122, 45, 149, 27, 255, 221, 181, 253, 53, 170,
        120, 140, 182, 233, 163, 0, 254, 244, 56, 60, 172, 169, 1, 73, 102, 4, 194, 124, 178, 79,
        214, 3, 132, 72, 225, 15, 184, 72, 216, 152, 16, 211, 198, 116, 226, 163, 80, 58, 15, 115,
        198, 161, 41, 222, 197, 138, 32, 197, 2, 176, 242, 33, 253, 86, 55, 162, 37, 1, 146, 31,
        61, 150, 61, 163, 188, 13, 200, 103, 178, 233, 242, 182, 185, 170, 228, 73, 186, 112, 228,
        46, 212, 153, 136, 255, 174, 213, 218, 44, 183, 19, 96, 129, 89, 14, 204, 7, 110, 69, 213,
        130, 175, 61, 230, 32, 45, 160, 147, 11, 203, 115, 249, 220, 168, 41, 1, 54, 3, 136, 124,
        229, 209, 14, 129, 39, 137, 91, 37, 64, 122, 221, 168, 63, 237, 61, 39, 210, 12, 127, 199,
        198, 174, 167, 248, 43, 248, 37, 250, 6, 15, 165, 108, 139, 223, 30, 178, 183, 158, 238,
        43, 172, 134, 237, 174, 80, 111, 220, 77, 193, 20, 66, 80, 139, 217, 42, 186, 62, 204, 20,
        6, 106, 227, 105, 144, 168, 18, 12, 23, 198, 77, 246, 57, 79, 171, 234, 6, 202, 144, 181,
        116, 229, 165, 196, 214, 184, 74, 81, 191, 144, 60, 239, 1, 67, 58, 7, 54, 51, 203,
    ];

    // 0x00288dca96fa670c0292be7bd684999e0e8a6b000abf9730a6fa1b039731b59b
    const VKEY_HASH: [u8; 32] = [
        0, 40, 141, 202, 150, 250, 103, 12, 2, 146, 190, 123, 214, 132, 153, 158, 14, 138, 107, 0,
        10, 191, 151, 48, 166, 250, 27, 3, 151, 49, 181, 155,
    ];

    const PUBLIC_INPUT_BYTES: [u8; 84] = [
        32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn test_sp1_groth16_verify() {
        let vk = load_groth16_verifying_key_from_bytes(sp1_verifier::GROTH16_VK_BYTES.as_ref());
        let pvk = prepare_verifying_key(&vk);

        let proof = load_groth16_proof_from_bytes(&PROOF_BYTES);

        let public_inputs = vec![
            Fr::from_be_bytes_mod_order(&VKEY_HASH),
            Fr::from_be_bytes_mod_order(&hash_bn254_be_bytes(&PUBLIC_INPUT_BYTES)),
        ];

        let res = Groth16::<Bn254>::verify_proof(&pvk, &proof, &public_inputs);
        assert_eq!(res, Ok(true));
    }
}
