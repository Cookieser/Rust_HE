//! BOLT: Privacy-Preserving, Accurate and Efficient Inference for Transformers
//! 
//! Ciphertext * ciphertext matrix multiplication. The ciphertext LHS is diagonal packed, RHS is column-major packed.
//! Ref: BOLT 4.1.3

use crate::{BatchEncoder, Ciphertext, Evaluator, GaloisKeys, RelinKeys};
use super::{ceil_div, ceil_two_power, Cipher1d, Plain1d, Cipher2d, Plain2d};

/// `m` cannot exceed `poly_degree / 2`.
struct MatmulBoltCcDcSmall {
    poly_degree: usize,
    m: usize,
    n: usize,
    gap: usize,
    gap_slot_count: usize
}

fn set_or_add(a: &mut Option<Ciphertext>, b: &Ciphertext, evaluator: &Evaluator) {
    if let Some(a) = a {
        evaluator.add_inplace(a, b);
    } else {
        *a = Some(b.clone());
    }
}

/// Matmul Helper for `[a] * [b] = [c]`, where `a: m × m, b: m × n, c: m × n`. 
/// `m` must not exceed `poly_degree/2`
/// 
/// **The row-count of a and column-count of b must be the same.**
/// - g = ceil_two_power(m)
/// - s = poly_degree / g
/// - Input ciphertext count = ceil(m/s)
/// - Weight ciphertext count = c = ceil(n/s)
/// - Output ciphertext count = c = ceil(n/s)
/// - HE cipher-cipher mult count = (2m - 1) * c
/// - HE cipher-plain mult count = (2m - 1) * c
/// - HE relin count = c
/// - HE rotations count = (2m - 1) * c * log(s)
impl MatmulBoltCcDcSmall {

    pub fn new(m: usize, n: usize, poly_degree: usize) -> Self {
        assert!(m <= poly_degree / 2);
        let gap = ceil_two_power(m);
        let gap_slot_count = ceil_div(poly_degree, gap);
        Self { poly_degree, m, n, gap, gap_slot_count }
    }

    pub fn encode_inputs(&self, encoder: &BatchEncoder, 
        a: &[u64], a_height: usize, a_width: usize, a_start_y: usize, a_start_x: usize
    ) -> Plain1d {
        let count = ceil_div(self.m, self.gap_slot_count);
        let mut ret = Vec::with_capacity(count);
        for i in 0..count {
            let mut vec = vec![0; self.poly_degree];
            let lower = i * self.gap_slot_count;
            for j in 0..self.gap_slot_count {
                for k in 0..self.gap {
                    let from_y = a_start_y + k;
                    let from_x = a_start_x + (lower + k + j) % self.m;
                    if from_y < a_height && from_x < a_width {
                        vec[j * self.gap + k] = a[from_y * a_width + from_x];
                    }
                }
            }
            ret.push(encoder.encode_new(&vec));
        }
        Plain1d::new(ret)
    }

    pub fn encode_weights(&self, encoder: &BatchEncoder, 
        b: &[u64], b_height: usize, b_width: usize, b_start_y: usize, b_start_x: usize
    ) -> Plain1d {
        let count = ceil_div(self.n, self.gap_slot_count);
        let mut ret = Vec::with_capacity(count);
        for i in 0..count {
            let mut taken = vec![0; self.poly_degree];
            let lower = i * self.gap_slot_count;
            let upper = self.n.min(lower + self.gap_slot_count);
            for column in lower..upper {
                let offset = (column - lower) * self.gap;
                for k in 0..self.m {
                    let from_y = b_start_y + k;
                    let from_x = b_start_x + column;
                    if from_y < b_height && from_x < b_width {
                        taken[offset + k] = b[from_y * b_width + from_x];
                    }
                }
            }
            ret.push(encoder.encode_new(&taken));
        }
        Plain1d::new(ret)
    }

    fn spread_inputs(
        &self,
        encoder: &BatchEncoder, evaluator: &Evaluator, 
        a: &Ciphertext, galois_keys: &GaloisKeys, 
        low: usize, high: usize
    ) -> Ciphertext {
        assert_eq!(low / self.gap, (high - 1) / self.gap);
        let mut mask = vec![0; self.poly_degree];
        for i in low..high {
            mask[i] = 1;
        }
        let mask = encoder.encode_new(&mask);
        let mut masked = evaluator.multiply_plain_new(a, &mask);
        let mut start_id = low / self.gap;
        let mut rotate_count = self.gap;
        let mut temp = Ciphertext::new();
        while rotate_count != self.poly_degree {
            if rotate_count < self.poly_degree / 2 {
                if start_id % 2 == 0 {
                    evaluator.rotate_rows(&masked, (self.poly_degree / 2 - rotate_count) as isize, galois_keys, &mut temp);
                } else {
                    evaluator.rotate_rows(&masked, rotate_count as isize, galois_keys, &mut temp);
                }
            } else {
                evaluator.rotate_columns(&masked, galois_keys, &mut temp)
            }
            evaluator.add_inplace(&mut masked, &temp);
            start_id /= 2;
            rotate_count *= 2;
        }
        masked
    }

    pub fn multiply(&self, 
        encoder: &BatchEncoder,
        evaluator: &Evaluator,
        // decryptor: &crate::Decryptor,
        galois_keys: &GaloisKeys,
        relin_keys: &RelinKeys,
        encrypted_a: &Cipher1d,
        encrypted_b: &Cipher1d,
    ) -> Cipher1d {
        assert_eq!(encrypted_a.len(), ceil_div(self.m, self.gap_slot_count));
        let out_poly_count = ceil_div(self.n, self.gap_slot_count);
        assert_eq!(encrypted_b.len(), out_poly_count);
        let mut out = vec![None; out_poly_count];
        let mut temp = Ciphertext::new();
        let mut b_rotated = encrypted_b.clone();
        for shift in 0..self.m {
            let in_poly_id = shift / self.gap_slot_count;
            let in_poly_slot_id = shift % self.gap_slot_count;
            if shift != 0 {
                for out_id in 0..out_poly_count {
                    evaluator.rotate_rows_inplace(&mut b_rotated[out_id], 1, galois_keys);
                }
            }
            for out_id in 0..out_poly_count {
                if true { // shift left
                    let mask_low = in_poly_slot_id * self.gap;
                    let mask_high = mask_low + (self.m - shift);
                    let masked_a = self.spread_inputs(encoder, evaluator, &encrypted_a[in_poly_id], galois_keys, mask_low, mask_high);
                    evaluator.multiply(&b_rotated[out_id], &masked_a, &mut temp);
                    set_or_add(&mut out[out_id], &temp, evaluator);
                }
            }
        }
        b_rotated = encrypted_b.clone();
        for shift in (0..self.m).rev() {
            let in_poly_id = shift / self.gap_slot_count;
            let in_poly_slot_id = shift % self.gap_slot_count;
            if shift != 0 {
                for out_id in 0..out_poly_count {
                    evaluator.rotate_rows_inplace(&mut b_rotated[out_id], -1, galois_keys);
                }
            }
            for out_id in 0..out_poly_count {
                if shift != 0 { // shift right
                    let mask_low = in_poly_slot_id * self.gap + (self.m - shift);
                    let mask_high = mask_low + shift;
                    let masked_a = self.spread_inputs(encoder, evaluator, &encrypted_a[in_poly_id], galois_keys, mask_low, mask_high);
                    evaluator.multiply(&b_rotated[out_id], &masked_a, &mut temp);
                    set_or_add(&mut out[out_id], &temp, evaluator);
                }
            }
        }

        out.into_iter().map(|c| {
            let mut c = c.unwrap();
            evaluator.relinearize_inplace(&mut c, relin_keys);
            c
        }).collect()
    }

    pub fn decode_outputs(&self, encoder: &BatchEncoder, encoded_outputs: &Plain1d) -> Vec<u64> {
        assert_eq!(encoded_outputs.len(), ceil_div(self.n, self.gap_slot_count));
        let outputs = encoded_outputs.iter().map(|p| encoder.decode_new(p)).collect::<Vec<_>>();
        let mut ret = vec![0; self.m * self.n];
        for col in 0..self.n {
            let out_poly_id = col / self.gap_slot_count;
            let out_poly_slot_id = col % self.gap_slot_count;
            for i in 0..self.m {
                ret[i * self.n + col] = outputs[out_poly_id][out_poly_slot_id * self.gap + i];
            }
        }
        ret
    }

    pub fn encode_outputs(&self, encoder: &BatchEncoder, outputs: &[u64]) -> Plain1d {
        let count = ceil_div(self.n, self.gap_slot_count);
        let mut ret = vec![vec![0; self.poly_degree]; count];
        for col in 0..self.n {
            let out_poly_id = col / self.gap_slot_count;
            let out_poly_slot_id = col % self.gap_slot_count;
            for i in 0..self.m {
                ret[out_poly_id][out_poly_slot_id * self.gap + i] = outputs[i * self.n + col];
            }
        }
        Plain1d::new(ret.into_iter().map(|v| encoder.encode_new(&v)).collect())
    }

}

pub struct MatmulBoltCcDc {
    pub m: usize,
    pub r: usize,
    pub n: usize,
    regular: MatmulBoltCcDcSmall,
}



/// General case for `MatmulBoltCpSmall`, which can handle `m > poly_degree / 2`.
/// 
/// This implementation partitions large matrices into smaller blocks.
/// First determine M = min(max(m, r), poly_degree/2). 
/// Then the overhead is ceil(m/M) * ceil(r/M) * ceil(n/M) times of the small case.
impl MatmulBoltCcDc {
    
    pub fn new(m: usize, r: usize, n: usize, poly_degree: usize) -> Self {
        let max_mr = m.max(r);
        let regular = MatmulBoltCcDcSmall::new(max_mr.min(poly_degree / 2), n, poly_degree);
        Self { m, r, n, regular }
    }

    pub fn encode_inputs(&self, encoder: &BatchEncoder, a: &[u64]) -> Plain2d {
        assert_eq!(a.len(), self.m * self.r);
        let hcount = ceil_div(self.m, self.regular.m);
        let wcount = ceil_div(self.r, self.regular.m);
        let mut ret = Vec::with_capacity(hcount * wcount);
        for i in 0..hcount {
            for j in 0..wcount {
                let a_start_y = i * self.regular.m;
                let a_start_x = j * self.regular.m;
                ret.push(self.regular.encode_inputs(encoder, a, self.m, self.r, a_start_y, a_start_x));
            }
        }
        Plain2d::new_1ds(ret)
    }

    pub fn encode_weights(&self, encoder: &BatchEncoder, b: &[u64]) -> Plain2d {
        assert_eq!(b.len(), self.r * self.n);
        let hcount = ceil_div(self.r, self.regular.m);
        let mut ret = Vec::with_capacity(hcount);
        for i in 0..hcount {
            let b_start_y = i * self.regular.m;
            let b_start_x = 0;
            ret.push(self.regular.encode_weights(encoder, b, self.r, self.n, b_start_y, b_start_x));
        }
        Plain2d::new_1ds(ret)
    }

    pub fn multiply(&self, 
        encoder: &BatchEncoder,
        evaluator: &Evaluator,
        // decryptor: &crate::Decryptor,
        galois_keys: &GaloisKeys,
        relin_keys: &RelinKeys,
        encrypted_a: &Cipher2d,
        encrypted_b: &Cipher2d,
    ) -> Cipher2d {
        assert_eq!(encrypted_a.len(), ceil_div(self.m, self.regular.m) * ceil_div(self.r, self.regular.m));
        assert_eq!(encrypted_b.len(), ceil_div(self.r, self.regular.m));
        let b_count = encrypted_b.len();
        let out_count = ceil_div(self.m, self.regular.m);
        let mut out = Vec::with_capacity(out_count);
        for i in 0..out_count {
            let mut item: Option<Cipher1d> = None;
            for j in 0..b_count {
                let a_id = i * b_count + j;
                let a = &encrypted_a[a_id];
                let b = &encrypted_b[j];
                let c = self.regular.multiply(encoder, evaluator, galois_keys, relin_keys, a, b);
                if let Some(item) = &mut item {
                    item.add_inplace(evaluator, &c);
                } else {
                    item = Some(c);
                }
            }
            out.push(item.unwrap());
        }
        Cipher2d::new_1ds(out)
    }

    pub fn decode_outputs(&self, encoder: &BatchEncoder, encoded_outputs: &Plain2d) -> Vec<u64> {
        assert_eq!(encoded_outputs.len(), ceil_div(self.m, self.regular.m));
        let outputs = encoded_outputs.iter().map(|p| self.regular.decode_outputs(encoder, p)).collect::<Vec<_>>();
        let mut ret = vec![0; self.m * self.n];
        for i in 0..self.m {
            let out_id = i / self.regular.m;
            for j in 0..self.n {
                let ret_id = i * self.n + j;
                ret[ret_id] = outputs[out_id][(i % self.regular.m) * self.n + j];
            }
        }
        ret
    }

    pub fn encode_outputs(&self, encoder: &BatchEncoder, outputs: &[u64]) -> Plain2d {
        let hcount = ceil_div(self.m, self.regular.m);
        let mut ret = vec![vec![0; self.regular.m * self.n]; hcount];
        for i in 0..self.m {
            let out_id = i / self.regular.m;
            for j in 0..self.n {
                ret[out_id][(i % self.regular.m) * self.n + j] = outputs[i * self.n + j];
            }
        }
        Plain2d::new_1ds(ret.into_iter().map(|v| self.regular.encode_outputs(encoder, &v)).collect())
    }


}


#[cfg(test)]
mod tests {

    use rand::Rng;
    use crate::{ExpandSeed, Modulus, PlainModulus, SerializableWithHeContext};
    use crate::{EncryptionParameters, CoeffModulus, HeContext, BatchEncoder, KeyGenerator, Encryptor, Decryptor};
    use super::*;

    pub fn random_u64_array(len: usize, modulus: &Modulus) -> Vec<u64> {
        let mut rng = rand::thread_rng();
        (0..len).map(|_| modulus.reduce(rng.gen())).collect()
    }

    fn test_bfv_matmul(poly_degree: usize, plain_modulus: u64, q_bits: Vec<usize>, m: usize, r: usize, n: usize) {
        let params = EncryptionParameters::new(crate::SchemeType::BFV)
            .set_poly_modulus_degree(poly_degree)
            .set_plain_modulus_u64(plain_modulus)
            .set_coeff_modulus(&CoeffModulus::create(poly_degree, q_bits));
        let context = HeContext::new(params.clone(), true, crate::SecurityLevel::None);
        let encoder = BatchEncoder::new(context.clone());
        let keygen = KeyGenerator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false)).set_secret_key(keygen.secret_key().clone());
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let evaluator = Evaluator::new(context.clone());
        let galois_keys = keygen.create_galois_keys(false);
        let relin_keys = keygen.create_relin_keys(false);

        // generate data
        let plain_modulus = params.plain_modulus();
        let inputs = random_u64_array(m * r, plain_modulus);
        // let inputs = (0..batch_size*input_dims).map(|i| i as u64).collect::<Vec<_>>();
        let weights = random_u64_array(r * n, plain_modulus);
        // let weights = (0..output_dims*input_dims).map(|i| i as u64).collect::<Vec<_>>();
        // calc
        let helper = MatmulBoltCcDc::new(m, r, n, params.poly_modulus_degree());
        // println!("helper created");
        let inputs_encoded = helper.encode_inputs(&encoder, &inputs);
        // println!("inputs encoded");
        let inputs_encrypted = inputs_encoded.encrypt_symmetric(&encryptor).expand_seed(&context);
        // println!("inputs encrypted");
        let mut inputs_serialized = vec![]; inputs_encrypted.serialize(&context, &mut inputs_serialized).unwrap();
        // println!("inputs serialized");
        assert_eq!(inputs_serialized.len(), inputs_encrypted.serialized_size(&context));
        let inputs_encrypted = Cipher2d::deserialize(&context, &mut inputs_serialized.as_slice()).unwrap();
        // println!("inputs deserialized");

        let weights_encoded = helper.encode_weights(&encoder, &weights);
        let weights_encrypted = weights_encoded.encrypt_symmetric(&encryptor).expand_seed(&context);

        let mut outputs_encrypted = helper.multiply(
            &encoder, &evaluator, 
            // &decryptor, 
            &galois_keys, &relin_keys,
            &inputs_encrypted, &weights_encrypted
        );
        // println!("multiplied");
        let mut outputs_serialized = vec![];
        outputs_encrypted.serialize(&context, &mut outputs_serialized).unwrap();
        // println!("output serialized");
        assert_eq!(outputs_serialized.len(), outputs_encrypted.serialized_size(&context));
        outputs_encrypted = Cipher2d::deserialize(&context, &mut outputs_serialized.as_slice()).unwrap();
        // println!("output deserialized");
        let outputs_decrypted = outputs_encrypted.decrypt(&decryptor);
        let outputs = helper.decode_outputs(&encoder, &outputs_decrypted);
        // println!("output decoded");
        // plain calc
        let mut outputs_plain = vec![0; m * n]; 
        for i in 0..m {
            for j in 0..n {
                for k in 0..r {
                    outputs_plain[i * n + j] += plain_modulus.reduce_u128(inputs[i * r + k] as u128 * weights[k * n + j] as u128);
                    outputs_plain[i * n + j] = plain_modulus.reduce(outputs_plain[i * n + j]);
                }
                // outputs_plain[i * output_dims + j] = plain_modulus.reduce(outputs_plain[i * output_dims + j] + output_bias[i * output_dims + j]);
            }
        }
        // check correct
        assert_eq!(outputs_plain, outputs);

        // check encode_outputs and decode_outputs are consistent
        let outputs_encoded = helper.encode_outputs(&encoder, &outputs);
        let outputs_decoded = helper.decode_outputs(&encoder, &outputs_encoded);
        assert_eq!(outputs_decoded, outputs);
    }

    #[test]
    fn bfv_matmul() {
        test_bfv_matmul(32, PlainModulus::batching(32, 20).value(), vec![60, 60, 60], 4, 5, 6);
        test_bfv_matmul(32, PlainModulus::batching(32, 20).value(), vec![60, 60, 60], 20, 5, 6);    
        test_bfv_matmul(256, PlainModulus::batching(256, 20).value(), vec![60, 60, 49], 17, 30, 23);
    }

}