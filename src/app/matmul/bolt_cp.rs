//! BOLT: Privacy-Preserving, Accurate and Efficient Inference for Transformers
//! 
//! Ciphertext * plaintext matrix multiplication. The ciphertext LHS is column-major packed.
//! Ref: BOLT 4.1.1 and 4.1.2
//! This only supports BFV/BGV. No CKKS.

use crate::{BatchEncoder, Evaluator, GaloisKeys};

use super::{ceil_div, ceil_two_power, Cipher1d, Plain1d, Cipher2d, Plain2d};

/// Matmul helper for processing `[a] * b = [c]`` scenario, a: `m × r`, b: `r × n`, c: `m × n`, but m cannot exceed `poly_degree / 2` here.
/// 
/// Ref: BOLT 4.1.1.
/// - g = ceil_two_power(m)
/// - s = poly_degree / g
/// - Input ciphertext count = ceil(r/s)
/// - Output ciphertext count = ceil(n/s)
/// - HE cipher-plain multiplication count = input_count * output_count * s
/// - HE rotation count = min{for p is a factor of s}(input_count * (p - 1) + output_count * (s/p - 1))
struct MatmulBoltCpSmall {
    poly_degree: usize,
    m: usize,
    r: usize,
    n: usize,
    column_gap: usize,
    column_slot_count: usize,
    input_rotate_count: usize,
    output_rotate_count: usize,
}

impl MatmulBoltCpSmall {

    /// Constructs the helper
    fn new(m: usize, r: usize, n: usize, poly_degree: usize) -> Self {
        assert!(m <= poly_degree / 2);
        let column_gap = ceil_two_power(m);
        let column_slot_count = poly_degree / column_gap;

        let input_count = ceil_div(r, column_slot_count);
        let output_count = ceil_div(n, column_slot_count);
        let mut input_rotate_count = 1;
        let mut best_input_rotate_count = 1;
        let mut best = usize::MAX;
        while input_rotate_count < column_slot_count {
            let count = (input_rotate_count - 1) * input_count + (column_slot_count / input_rotate_count - 1) * output_count;
            if count < best {
                best = count;
                best_input_rotate_count = input_rotate_count;
            }
            input_rotate_count *= 2;
        }
        let input_rotate_count = best_input_rotate_count;
        let output_rotate_count = column_slot_count / input_rotate_count;

        Self { poly_degree, m, r, n, column_gap, column_slot_count, input_rotate_count, output_rotate_count }
    }

    /// Encode the input a.
    /// 
    /// The elements in `a` are organized as column-major in the plaintext slots.
    /// `len(a)` should be a multiple of `r`. If `a` does not have `m` rows, treat it as having m rows with 0s padded
    fn encode_inputs(&self, encoder: &BatchEncoder, a: &[u64]) -> Plain1d {
        assert!(a.len() % self.r == 0);
        let input_count = ceil_div(self.r, self.column_slot_count);
        let mut ret = vec![];
        for i in 0..input_count {
            let mut taken = vec![0; self.poly_degree];
            let column_lower = i * self.column_slot_count;
            let column_upper = self.r.min(column_lower + self.column_slot_count);
            for column in column_lower..column_upper {
                let inner_column = column % self.column_slot_count;
                let offset = inner_column * self.column_gap;
                for j in 0..self.m {
                    let id = j * self.r + column;
                    if id < a.len() {
                        taken[offset + j] = a[id];
                    }
                }
            }
            ret.push(taken);
        }
        let encoded = ret.into_iter().map(|v| encoder.encode_new(&v)).collect();
        Plain1d::new(encoded)
    }

    fn encode_weights(&self, encoder: &BatchEncoder, b: &[u64]) -> Plain2d {
        let input_count = ceil_div(self.r, self.column_slot_count);
        let output_count = ceil_div(self.n, self.column_slot_count);
        let column_slot_half = self.column_slot_count / 2;

        let mut ret = Vec::with_capacity(self.input_rotate_count * self.output_rotate_count);

        for input_rotate in 0..self.input_rotate_count {
            for output_rotate in 0..self.output_rotate_count {
                let mut ret_current = Vec::with_capacity(output_count * input_count); 
                let rotation_slots = output_rotate * self.input_rotate_count + input_rotate;
                for i in 0..output_count {
                    for j in 0..input_count {
                        // encode b
                        let mut b_encoded = vec![0; self.poly_degree];
                        for k in 0..self.column_slot_count {
                            let a_shift_index = (rotation_slots + k) % column_slot_half + (rotation_slots / column_slot_half + k / column_slot_half) % 2 * column_slot_half;
                            let b_row_index = j * self.column_slot_count + a_shift_index;
                            let b_column_index = i * self.column_slot_count + k;
                            // here the k is already rotated by "rotation_slots", but the inputs are only rotated by "input_rotate"
                            // therefore we need to rotate back "correction = output_rotate * input_rotate_count" slots
                            // so we directly calculate a corrected_k as the rotated-back index
                            let correction = output_rotate * self.input_rotate_count % self.column_slot_count;
                            let corrected_k = ((k + correction) % column_slot_half) + ((k / column_slot_half) + (correction / column_slot_half)) % 2 * column_slot_half;
                            if b_row_index < self.r && b_column_index < self.n {
                                let taken = b[b_row_index * self.n + b_column_index];
                                for t in 0..self.column_gap {
                                    b_encoded[corrected_k * self.column_gap + t] = taken;
                                }
                            }
                        }
                        let b_encoded = encoder.encode_new(&b_encoded);
                        ret_current.push(b_encoded);
                    }
                }
                ret.push(Plain1d::new(ret_current));
            }
        }
        Plain2d::new_1ds(ret)
    }

    fn multiply(&self, 
        evaluator: &Evaluator,
        // decryptor: &crate::Decryptor,
        galois_keys: &GaloisKeys,
        encrypted_a: &Cipher1d,
        encoded_b: &Plain2d,
    ) -> Cipher1d {
        let input_count = ceil_div(self.r, self.column_slot_count);
        assert_eq!(encrypted_a.len(), input_count);
        let output_count = ceil_div(self.n, self.column_slot_count);

        let mut outputs = vec![vec![None; output_count]; self.output_rotate_count];
        let mut encrypted_a_cloned = encrypted_a.clone();
        
        for input_rotate in 0..self.input_rotate_count {

            // rotate
            for j in 0..input_count {
                if input_rotate != 0 && input_rotate != self.column_slot_count / 2 {
                    evaluator.rotate_rows_inplace(&mut encrypted_a_cloned[j], self.column_gap as isize, galois_keys);
                } else if input_rotate == self.column_slot_count / 2 {
                    encrypted_a_cloned[j] = encrypted_a[j].clone();
                    evaluator.rotate_columns_inplace(&mut encrypted_a_cloned[j], galois_keys);
                }
            }

            for output_rotate in 0..self.output_rotate_count {

                // multiply and sum
                for i in 0..output_count {
                    if i * self.column_slot_count >= self.n {continue;}
                    for j in 0..input_count {
                        if j * self.column_slot_count >= self.r {continue;}

                        // println!("rot={}, i={}, j={}, ir={}, or={}", rotation_slots, i, j, input_rotate, output_rotate);
                        // let a = decryptor.decrypt_new(&encrypted_a[j]); println!("a = {:?}", encoder.decode_new(&a));
                        // println!("b = {:?}", b_encoded);

                        let b_encoded = &encoded_b
                            [input_rotate * self.output_rotate_count + output_rotate]
                            [i * input_count + j];
                        let product = evaluator.multiply_plain_new(&encrypted_a_cloned[j], b_encoded);
                        if outputs[output_rotate][i].is_none() {
                            outputs[output_rotate][i] = Some(product);
                        } else {
                            evaluator.add_inplace(outputs[output_rotate][i].as_mut().unwrap(), &product);
                        }
                    }
                }

            }

        }

        // rotate the left slots and sum them up
        let mut half_sum = vec![None; output_count];
        let mut outputs_summed = vec![None; output_count];
        for (i, outputs_partial) in outputs.into_iter().enumerate().rev() {
            // first rotate all sums left by self.column_gap * self.input_rotate_count
            for sum in outputs_summed.iter_mut() {
                if sum.is_some() && self.input_rotate_count * self.column_gap < self.poly_degree / 2 {
                    evaluator.rotate_rows_inplace(sum.as_mut().unwrap(), (self.input_rotate_count * self.column_gap) as isize, galois_keys);
                }
            }
            // add the partial sums
            for (_j, (sum, partial)) in outputs_summed.iter_mut().zip(outputs_partial.into_iter()).enumerate() {
                if partial.is_some() {
                    if sum.is_none() {
                        *sum = partial;
                    } else if let Some(partial) = partial {
                        evaluator.add_inplace(sum.as_mut().unwrap(), &partial);
                        // println!("i={}, j={}", i, j);
                        // let sum = decryptor.decrypt_new(sum.as_ref().unwrap());
                        // println!("sum = {:?}", encoder.decode_new(&sum));
                    }
                }
            }
            if i == self.output_rotate_count / 2 {
                for (j, sum) in outputs_summed.iter_mut().enumerate() {
                    if sum.is_some() {
                        evaluator.rotate_columns_inplace(sum.as_mut().unwrap(), galois_keys);
                        half_sum[j] = sum.take();
                    }
                }
            }
        }

        // add half_sum to outputs_summed
        for (sum, half) in outputs_summed.iter_mut().zip(half_sum.into_iter()) {
            if let Some(half) = half {
                if sum.is_none() {
                    *sum = Some(half);
                } else {
                    evaluator.add_inplace(sum.as_mut().unwrap(), &half);
                }
            }
        }

        let outputs = outputs_summed.into_iter().map(|o| o.unwrap()).collect();
        Cipher1d::new(outputs)
    }

    /// Decode the outputs.
    fn decode_outputs(&self, encoder: &BatchEncoder, encoded_c: &Plain1d) -> Vec<u64> {
        let mut c = vec![0; self.m * self.n];
        let output_count = ceil_div(self.n, self.column_slot_count);
        assert_eq!(encoded_c.len(), output_count);
        let decoded_c = encoded_c.iter().map(|p| encoder.decode_new(p)).collect::<Vec<_>>();
        for j in 0..self.n {
            let output_index = j / self.column_slot_count;
            let inner_column = j % self.column_slot_count;
            let offset = inner_column * self.column_gap;
            for i in 0..self.m {
                c[i * self.n + j] = decoded_c[output_index][offset + i];
            }
        }
        c
    }

    fn encode_outputs(&self, encoder: &BatchEncoder, c: &[u64]) -> Plain1d {
        assert!(c.len() % self.n == 0);
        let output_count = ceil_div(self.n, self.column_slot_count);
        let mut ret = Vec::with_capacity(output_count);
        for i in 0..output_count {
            let mut taken = vec![0; self.poly_degree];
            let column_lower = i * self.column_slot_count;
            let column_upper = self.n.min(column_lower + self.column_slot_count);
            for column in column_lower..column_upper {
                let inner_column = column % self.column_slot_count;
                let offset = inner_column * self.column_gap;
                for j in 0..self.m {
                    let id = j * self.n + column;
                    if id < c.len() {
                        taken[offset + j] = c[id];
                    }
                }
            }
            ret.push(encoder.encode_new(&taken));
        }
        Plain1d::new(ret)
    }

}

/// General case for `MatmulBoltCpSmall`, which can handle `m > poly_degree / 2`.
/// 
/// If `m <= poly_degree / 2`, this will be the same as `MatmulBoltCpSmall`.
/// If `m > poly_degree / 2`, all overheads will be `ceil(m / (poly_degree / 2))` times larger.
pub struct MatmulBoltCp {
    pub m: usize,
    pub r: usize,
    pub n: usize,
    regular: MatmulBoltCpSmall,
}

impl MatmulBoltCp {
    
    pub fn new(m: usize, r: usize, n: usize, poly_degree: usize) -> Self {
        let regular = MatmulBoltCpSmall::new(m.min(poly_degree / 2), r, n, poly_degree);
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
        self.regular.encode_weights(encoder, weights)
    }

    pub fn multiply(&self, 
        evaluator: &Evaluator,
        galois_keys: &GaloisKeys,
        encrypted_inputs: &Cipher2d,
        encoded_weights: &Plain2d,
    ) -> Cipher2d {
        let count = ceil_div(self.m, self.regular.m);
        assert_eq!(encrypted_inputs.len(), count);
        let mut ret = Vec::with_capacity(count);
        for i in 0..count {
            let inputs_part = &encrypted_inputs[i];
            let outputs_part = self.regular.multiply(evaluator, galois_keys, inputs_part, encoded_weights);
            ret.push(outputs_part);
        }
        Cipher2d::new_1ds(ret)
    }

    pub fn decode_outputs(&self, encoder: &BatchEncoder, encoded_outputs: &Plain2d) -> Vec<u64> {
        let mut outputs = vec![0; self.m * self.n];
        for i in 0..encoded_outputs.len() {
            let outputs_part = &encoded_outputs[i];
            let lower = i * self.regular.m;
            let upper = (lower + self.regular.m).min(self.m);
            let outputs_part = self.regular.decode_outputs(encoder, outputs_part);
            let copy_length = (upper - lower) * self.n;
            let copy_start = lower * self.n;
            outputs[copy_start..copy_start + copy_length].copy_from_slice(&outputs_part[..copy_length]);
        }
        outputs
    }

    pub fn encode_outputs(&self, encoder: &BatchEncoder, outputs: &[u64]) -> Plain2d {
        assert!(outputs.len() == self.m * self.n);
        let count = ceil_div(self.m, self.regular.m);
        let mut ret = Vec::with_capacity(count);
        for i in 0..count {
            let lower = i * self.regular.m;
            let upper = (lower + self.regular.m).min(self.m);
            let outputs_part = &outputs[lower * self.n..upper * self.n];
            ret.push(self.regular.encode_outputs(encoder, outputs_part));
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

    fn test_bfv_matmul(poly_degree: usize, plain_modulus: u64, q_bits: Vec<usize>, batch_size: usize, input_dims: usize, output_dims: usize) {
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

        // generate data
        let plain_modulus = params.plain_modulus();
        let inputs = random_u64_array(batch_size * input_dims, plain_modulus);
        // let inputs = (0..batch_size*input_dims).map(|i| i as u64).collect::<Vec<_>>();
        let weights = random_u64_array(output_dims * input_dims, plain_modulus);
        // let weights = (0..output_dims*input_dims).map(|i| i as u64).collect::<Vec<_>>();
        // calc
        let helper = MatmulBoltCp::new(batch_size, input_dims, output_dims, params.poly_modulus_degree());
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

        let mut outputs_encrypted = helper.multiply(
            &evaluator, 
            // &decryptor, 
            &galois_keys, &inputs_encrypted, &weights_encoded
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
        let mut outputs_plain = vec![0; batch_size * output_dims]; 
        for i in 0..batch_size {
            for j in 0..output_dims {
                for k in 0..input_dims {
                    outputs_plain[i * output_dims + j] += plain_modulus.reduce_u128(inputs[i * input_dims + k] as u128 * weights[k * output_dims + j] as u128);
                    outputs_plain[i * output_dims + j] = plain_modulus.reduce(outputs_plain[i * output_dims + j]);
                }
                // outputs_plain[i * output_dims + j] = plain_modulus.reduce(outputs_plain[i * output_dims + j] + output_bias[i * output_dims + j]);
            }
        }
        // check correct
        assert_eq!(outputs_plain, outputs);

        // check encode outputs and decode outputs are consistent
        let outputs_encoded = helper.encode_outputs(&encoder, &outputs);
        let outputs_decoded = helper.decode_outputs(&encoder, &outputs_encoded);
        assert_eq!(outputs_decoded, outputs);
    }

    #[test]
    fn bfv_matmul() {
        test_bfv_matmul(32, PlainModulus::batching(32, 20).value(), vec![60, 60], 4, 5, 6);
        test_bfv_matmul(32, PlainModulus::batching(32, 20).value(), vec![60, 60], 20, 5, 6);    
        test_bfv_matmul(256, PlainModulus::batching(256, 20).value(), vec![60, 60, 49], 17, 80, 96);
    }

}