//! BOLT: Privacy-Preserving, Accurate and Efficient Inference for Transformers
//! 
//! Ciphertext * ciphertext matrix multiplication. The ciphertext LHS is column-major packe, RHS is row-major packed.
//! Ref: BOLT 4.1.3

use crate::{BatchEncoder, Ciphertext, Evaluator, GaloisKeys, RelinKeys};
use super::{ceil_div, ceil_two_power, Cipher1d, Plain1d, Cipher2d, Plain2d};

/// Matmul Helper for `[a] * [b] = [c]`, where `a: m × r, b: r × m, c: m × m`. 
/// `m` must not exceed `poly_degree/2`
/// 
/// **The row-count of a and column-count of b must be the same.**
/// - g = ceil_two_power(m)
/// - s = poly_degree / g
/// - Input ciphertext count = c = ceil(r/s)
/// - Weight ciphertext count = c = ceil(r/s)
/// - Output ciphertext count = ceil(m/s)
/// - HE cipher-cipher mult count = (2m - 1) * c
/// - HE cipher-plain mult count = 2m - 1
/// - HE relin count = 2m - 1
/// - HE rotations count = (2m - 2) * c + 2m * log(s)
struct MatmulBoltCcCrSmall {
    poly_degree: usize,
    m: usize, 
    r: usize,
    gap: usize,
    gap_slot_count: usize,
}

fn set_or_add(a: &mut Option<Ciphertext>, b: &Ciphertext, evaluator: &Evaluator) {
    if let Some(a) = a {
        evaluator.add_inplace(a, b);
    } else {
        *a = Some(b.clone());
    }
}

impl MatmulBoltCcCrSmall {

    /// Construct the helper
    pub fn new(m: usize, r: usize, poly_degree: usize) -> Self {
        assert!(m <= poly_degree/2, "m must not exceed poly_degree/2");
        let gap = ceil_two_power(m);
        let gap_slot_count = ceil_div(poly_degree, gap);
        MatmulBoltCcCrSmall {
            poly_degree, m, r, gap, gap_slot_count
        }
    }

    /// The elements in `a` will be organized as column-major in the plaintext slots.
    /// `len(a)` should be a multiple of `r`. If `a` does not have `m` rows, treat it as having m rows with 0s padded
    pub fn encode_inputs(&self, encoder: &BatchEncoder, a: &[u64]) -> Plain1d {
        assert!(a.len() % self.r == 0);
        let input_count = ceil_div(self.r, self.gap_slot_count);
        let mut ret = Vec::with_capacity(input_count);
        for i in 0..input_count {
            let mut taken = vec![0; self.poly_degree];
            let column_lower = i * self.gap_slot_count;
            let column_upper = self.r.min(column_lower + self.gap_slot_count);
            for column in column_lower..column_upper {
                let inner_column = column % self.gap_slot_count;
                let offset = inner_column * self.gap;
                for j in 0..self.m {
                    let id = j * self.r + column;
                    if id < a.len() {
                        taken[offset + j] = a[id];
                    }
                }
            }
            ret.push(encoder.encode_new(&taken));
        }
        Plain1d::new(ret)
    }

    /// The elements in `b` will be organized as column-major in the plaintext slots.
    /// Regard `b` as a `r × c` matrix, where `c` is `total_columns`. Encode the columns from `column_start` to `column_end`.
    /// If the selected columns of `b` does not have `m` columns, treat it as having m columns with 0s padded
    pub fn encode_weights(&self, encoder: &BatchEncoder, b: &[u64], total_columns: usize, column_start: usize, column_end: usize) -> Plain1d {
        assert!(b.len() % self.r == 0);
        let weight_count = ceil_div(self.r, self.gap_slot_count);
        let mut ret = Vec::with_capacity(weight_count);
        for i in 0..weight_count {
            let mut taken = vec![0; self.poly_degree];
            let row_lower = i * self.gap_slot_count;
            let row_upper = self.r.min(row_lower + self.gap_slot_count);
            for row in row_lower..row_upper {
                let inner_row = row % self.gap_slot_count;
                let offset = inner_row * self.gap;
                for j in 0..self.m.min(column_end - column_start) {
                    let id = row * total_columns + j + column_start;
                    if id < b.len() {
                        taken[offset + j] = b[id];
                    }
                }
            }
            ret.push(encoder.encode_new(&taken));
        }
        Plain1d::new(ret)
    }

    fn sum_inplace(&self, evaluator: &Evaluator, galois_keys: &GaloisKeys, a: &mut Ciphertext) {
        let mut rotate_count = self.gap;
        let mut temp = Ciphertext::new();
        while rotate_count != self.poly_degree {
            if rotate_count < self.poly_degree / 2 {
                evaluator.rotate_rows(a, rotate_count as isize, galois_keys, &mut temp);
            } else {
                evaluator.rotate_columns(a, galois_keys, &mut temp);
            }
            evaluator.add_inplace(a, &temp);
            rotate_count *= 2;
        }
    }

    fn mask_out_inplace(&self, encoder: &BatchEncoder, evaluator: &Evaluator, a: &mut Ciphertext, mask_lower: usize, mask_upper: usize) {
        let mut mask = vec![0; self.poly_degree];
        for i in mask_lower..mask_upper {
            mask[i] = 1;
        }
        let mask = encoder.encode_new(&mask);
        evaluator.multiply_plain_inplace(a, &mask);
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
        assert_eq!(encrypted_a.len(), encrypted_b.len());
        let poly_count = encrypted_a.len();
        let out_poly_count = ceil_div(self.m, self.gap_slot_count);
        let mut out = vec![None; out_poly_count];
        let mut temp = Ciphertext::new();
        let mut b_rotated = encrypted_b.clone();
        for shift in 0..self.m {
            if shift != 0 {
                for i in 0..poly_count {
                    evaluator.rotate_rows_inplace(&mut b_rotated[i], 1, galois_keys);
                }
            }
            let out_poly_id = shift / self.gap_slot_count;
            let out_poly_slot_id = shift % self.gap_slot_count;
            if true {
                let mut partial_sum = None;
                for i in 0..poly_count {
                    evaluator.multiply(&b_rotated[i], &encrypted_a[i], &mut temp);
                    set_or_add(&mut partial_sum, &temp, evaluator);
                }
                evaluator.relinearize_inplace(partial_sum.as_mut().unwrap(), relin_keys);
                self.sum_inplace(evaluator, galois_keys, partial_sum.as_mut().unwrap());
                self.mask_out_inplace(encoder, evaluator, partial_sum.as_mut().unwrap(), 
                    out_poly_slot_id * self.gap, out_poly_slot_id * self.gap + self.m - shift);
                set_or_add(&mut out[out_poly_id], partial_sum.as_ref().unwrap(), evaluator);
            }
        }
        b_rotated = encrypted_b.clone();
        for shift in (1..self.m).rev() {
            for i in 0..poly_count {
                evaluator.rotate_rows_inplace(&mut b_rotated[i], -1, galois_keys);
            }
            let out_poly_id = shift / self.gap_slot_count;
            let out_poly_slot_id = shift % self.gap_slot_count;
            let mut partial_sum = None;
            for i in 0..poly_count {
                evaluator.multiply(&b_rotated[i], &encrypted_a[i], &mut temp);
                set_or_add(&mut partial_sum, &temp, evaluator);
            }
            evaluator.relinearize_inplace(partial_sum.as_mut().unwrap(), relin_keys);
            self.sum_inplace(evaluator, galois_keys, partial_sum.as_mut().unwrap());
            self.mask_out_inplace(encoder, evaluator, partial_sum.as_mut().unwrap(), 
                out_poly_slot_id * self.gap + self.m - shift, out_poly_slot_id * self.gap + self.m);
            set_or_add(&mut out[out_poly_id], partial_sum.as_ref().unwrap(), evaluator);
        }
        Cipher1d::new(out.into_iter().map(|x| {
            x.unwrap()
        }).collect())
    }

    pub fn decode_outputs(&self, encoder: &BatchEncoder, encoded_outputs: &Plain1d) -> Vec<u64> {
        let decoded = encoded_outputs.iter().map(|x| encoder.decode_new(x)).collect::<Vec<_>>();
        let mut ret = vec![0; self.m * self.m];
        for shift in 0..self.m {
            let out_poly_id = shift / self.gap_slot_count;
            let out_poly_slot_id = shift % self.gap_slot_count;
            for i in 0..self.m {
                ret[i * self.m + (i + shift) % self.m] = decoded[out_poly_id][out_poly_slot_id * self.gap + i];
            }
        }
        ret
    }

    pub fn encode_outputs(&self, encoder: &BatchEncoder, outputs: &[u64]) -> Plain1d {
        assert_eq!(outputs.len(), self.m * self.m);
        let mut ret = vec![vec![0; self.poly_degree]; ceil_div(self.m, self.gap_slot_count)];
        for shift in 0..self.m {
            let out_poly_id = shift / self.gap_slot_count;
            let out_poly_slot_id = shift % self.gap_slot_count;
            for i in 0..self.m {
                ret[out_poly_id][out_poly_slot_id * self.gap + i] = outputs[i * self.m + (i + shift) % self.m];
            }
        }
        Plain1d::new(ret.iter().map(|x| encoder.encode_new(x)).collect())
    }

}


/// General case for `MatmulBoltCpSmall`, which can handle `m > poly_degree / 2`.
/// 
/// This implementation partitions large matrices into smaller blocks.
/// First determine M = min(max(m, n), poly_degree/2). The LHS is split vertically into ceil(m/M) blocks
/// and the RHS is split horizontally into ceil(n/M) blocks.
/// Then each block Ai and Bj are multiplicated with `MatmulBoltCpSmall` and the results are concatenated.
/// Naturally, the overhead is ceil(m/M) * ceil(n/M) times of the small case.
pub struct MatmulBoltCcCr {
    pub m: usize,
    pub r: usize,
    pub n: usize,
    regular: MatmulBoltCcCrSmall,
}

impl MatmulBoltCcCr {
    
    pub fn new(m: usize, r: usize, n: usize, poly_degree: usize) -> Self {
        let max_mn = m.max(n);
        let regular = MatmulBoltCcCrSmall::new(max_mn.min(poly_degree / 2), r, poly_degree);
        Self { m, r, n, regular }
    }

    pub fn encode_inputs(&self, encoder: &BatchEncoder, inputs: &[u64]) -> Plain2d {
        assert!(inputs.len() == self.m * self.r);
        let count = ceil_div(self.m, self.regular.m);
        let mut ret = Vec::with_capacity(count);
        for i in 0..count {
            let lower = i * self.regular.m;
            let upper = (lower + self.regular.m).min(self.m);
            let inputs_part = &inputs[lower * self.r..upper * self.r];
            ret.push(self.regular.encode_inputs(encoder, inputs_part));
        }
        Plain2d::new_1ds(ret)
    }

    pub fn encode_weights(&self, encoder: &BatchEncoder, weights: &[u64]) -> Plain2d {
        assert!(weights.len() == self.r * self.n);
        let count = ceil_div(self.n, self.regular.m);
        let mut ret = Vec::with_capacity(count);
        for i in 0..count {
            let lower = i * self.regular.m;
            let upper = (lower + self.regular.m).min(self.n);
            ret.push(self.regular.encode_weights(encoder, weights, self.n, lower, upper));
        }
        Plain2d::new_1ds(ret)
    }

    pub fn multiply(&self, 
        encoder: &BatchEncoder,
        evaluator: &Evaluator,
        galois_keys: &GaloisKeys,
        relin_keys: &RelinKeys,
        encrypted_inputs: &Cipher2d,
        encrypted_weights: &Cipher2d,
    ) -> Cipher2d {
        let icount = encrypted_inputs.len();
        assert_eq!(icount, ceil_div(self.m, self.regular.m));
        let wcount = encrypted_weights.len();
        assert_eq!(wcount, ceil_div(self.n, self.regular.m));
        let mut out = Vec::with_capacity(icount * wcount);
        for i in 0..icount {
            for j in 0..wcount {
                let out_part = self.regular.multiply(
                    encoder, evaluator, galois_keys, relin_keys, 
                    &encrypted_inputs[i], &encrypted_weights[j]
                );
                out.push(out_part);
            }
        }
        Cipher2d::new_1ds(out)
    }

    pub fn decode_outputs(&self, encoder: &BatchEncoder, encoded_outputs: &Plain2d) -> Vec<u64> {
        let mut outputs = vec![0; self.m * self.n];
        let icount = ceil_div(self.m, self.regular.m);
        let wcount = ceil_div(self.n, self.regular.m);
        assert_eq!(encoded_outputs.len(), icount * wcount);
        for id in 0..encoded_outputs.len() {
            let i = id / wcount;
            let j = id % wcount;
            let outputs_part = self.regular.decode_outputs(encoder, &encoded_outputs[id]);
            // outputs_part is a submatrix of the outputs matrix
            let start_i = i * self.regular.m;
            let start_j = j * self.regular.m;
            let end_i = ((i + 1) * self.regular.m).min(self.m);
            let end_j = ((j + 1) * self.regular.m).min(self.n);
            for ii in start_i..end_i {
                for jj in start_j..end_j {
                    outputs[ii * self.n + jj] = outputs_part[(ii - start_i) * self.regular.m + (jj - start_j)];
                }
            }
        }
        outputs
    }

    pub fn encode_outputs(&self, encoder: &BatchEncoder, outputs: &[u64]) -> Plain2d {
        let mut ret = Vec::with_capacity(ceil_div(self.m, self.regular.m) * ceil_div(self.n, self.regular.m));
        let icount = ceil_div(self.m, self.regular.m);
        let wcount = ceil_div(self.n, self.regular.m);
        for i in 0..icount {
            for j in 0..wcount {
                let mut vec = vec![0; self.regular.m * self.regular.m];
                let start_i = i * self.regular.m;
                let start_j = j * self.regular.m;
                let end_i = ((i + 1) * self.regular.m).min(self.m);
                let end_j = ((j + 1) * self.regular.m).min(self.n);
                for ii in start_i..end_i {
                    for jj in start_j..end_j {
                        vec[(ii - start_i) * self.regular.m + (jj - start_j)] = outputs[ii * self.n + jj];
                    }
                }
                ret.push(self.regular.encode_outputs(encoder, &vec));
            }
        }
        Plain2d::new_1ds(ret)
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
        let helper = MatmulBoltCcCr::new(m, r, n, params.poly_modulus_degree());
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
        test_bfv_matmul(256, PlainModulus::batching(256, 20).value(), vec![60, 60, 49], 17, 80, 23); 
        // test_bfv_matmul(8192, PlainModulus::batching(8192, 20).value(), vec![60, 60, 49], 128, 64, 128);
    }

}