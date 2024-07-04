//! Implement HE-based matrix multiplication. Supports both BFV(BGV) and CKKS.
//! 
//! Calculate y = xW, where we call y as 'outputs', x as 'inputs', w as 'weights'.
//! x has shape `[batch_size, input_dims]`, 
//! w has shape `[input_dims, output_dims]`, 
//! y has shape `[batch_size, output_dims]`.
//! These semantics match those of fully connected layer in deep learning.
//! The users should provide the matrices as a 1d-slice of `u64` or `f64`, row-major.
//! Check the test functions for examples.

use super::{Cipher2d, Plain2d};
use crate::{BatchEncoder, CKKSEncoder, Decryptor, Evaluator, Plaintext, Ciphertext, GaloisKeys, ParmsID};

/// Defines how the helper is used.
/// 
/// This tells the helper how to optimize the encoding method.
/// The usage is not obligatory. For example, you could use `CipherPlain` but still call `matmul_reverse`, 
/// but that will cost more communication/computation than `PlainCipher`.
#[derive(Clone, Copy, Debug)]
pub enum MatmulHelperObjective {
    /// `[y] = [x] * w`
    CipherPlain,
    /// `[y] = x * [w]`
    PlainCipher,
    /// `[y] = [x1] * w0 + x0 * [w1]`
    CpAddPc, 
}

/// Provide utilities for matrix multiplication.
#[derive(Clone, Debug)]
pub struct MatmulHelper {
    pub batch_size: usize, pub input_dims: usize, pub output_dims: usize,
    batch_block: usize, input_block: usize, output_block: usize,
    poly_degree: usize,
    #[allow(dead_code)]
    objective: MatmulHelperObjective,
    pack_lwe: bool,
}

fn ceil_div(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

impl MatmulHelper {

    /// Pack LWE enabled?
    pub fn pack_lwe(&self) -> bool {self.pack_lwe}

    /// Create helper instance, given shape info of the matrices.
    pub fn new(batch_size: usize, input_dims: usize, output_dims: usize, poly_degree: usize, objective: MatmulHelperObjective, pack_lwe: bool) -> Self {
        assert!(batch_size > 0);
        assert!(input_dims > 0);
        assert!(output_dims > 0);
        assert!(poly_degree > 0);
        let mut b_best = 0; let mut i_best = 0; let mut o_best = 0;
        let mut c_best = usize::MAX;
        if !pack_lwe {
            for b in (1..=batch_size).rev() {
                let bc = ceil_div(batch_size, b);
                if b > poly_degree {continue;}
                if bc * 2 > c_best {continue;}
                for i in 1..poly_degree / b {
                    if i > input_dims {break;}
                    let mut o = poly_degree / b / i;
                    if o > output_dims {o = output_dims;}
                    if o < 1 {continue;}
                    let ic = ceil_div(input_dims, i);
                    let oc = ceil_div(output_dims, o);
                    let c = match objective {
                        MatmulHelperObjective::CipherPlain => bc * (ic + oc),
                        MatmulHelperObjective::PlainCipher => (bc + ic) + oc,
                        MatmulHelperObjective::CpAddPc => bc * ic + ic * oc + bc * oc,
                    };
                    if c >= c_best {continue;}
                    b_best = b; i_best = i; o_best = o; c_best = c;
                }
            }
        } else {
            let mut i = 2usize.pow(((poly_degree as f64).powf(0.33) as usize).ilog2());
            if i > input_dims {
                i = 2usize.pow((input_dims as f64).log2().ceil() as u32);
            }
            for b in (1..=batch_size).rev() {
                let bc = ceil_div(batch_size, b);
                if b > poly_degree {continue;}
                let mut o = poly_degree / b / i;
                if o > output_dims {o = output_dims;}
                if o < 1 {continue;}
                let ic = ceil_div(input_dims, i);
                let oc = ceil_div(output_dims, o);
                let c = match objective {
                    MatmulHelperObjective::CipherPlain => bc * ic + ceil_div(bc * oc, i) * 2,
                    MatmulHelperObjective::PlainCipher => ic * oc + ceil_div(bc * oc, i) * 2,
                    MatmulHelperObjective::CpAddPc => bc * ic + ic * oc + ceil_div(bc * oc, i) * 2,
                };
                if c >= c_best {continue;}
                b_best = b; i_best = i; o_best = o; c_best = c;
            }
        }
        // println!("b => {}, i => {}, o => {}", b_best, i_best, o_best);
        Self {
            batch_size, input_dims, output_dims,
            batch_block: b_best, input_block: i_best, output_block: o_best,
            poly_degree, objective, pack_lwe,
        }
    }

    fn encode_weight_small_bfv(
        &self, encoder: &BatchEncoder, weights: &[u64],
        li: usize, ui: usize, lj: usize, uj: usize
    ) -> Plaintext {
        let slots = self.poly_degree;
        let mut vec = vec![0; self.input_block * self.output_block];
        for j in lj..uj {
            for i in li..ui {
                let r = (j - lj) * self.input_block + self.input_block - (i - li) - 1;
                assert!(r < slots && r < vec.len());
                vec[r] = weights[i * self.output_dims + j];
            }
        }
        encoder.encode_polynomial_new(&vec)
    }

    fn encode_weight_small_ckks(
        &self, encoder: &CKKSEncoder, weights: &[f64],
        li: usize, ui: usize, lj: usize, uj: usize, parms_id: Option<ParmsID>, scale: f64
    ) -> Plaintext {
        let slots = self.poly_degree;
        let mut vec = vec![0.0; self.input_block * self.output_block];
        for j in lj..uj {
            for i in li..ui {
                let r = (j - lj) * self.input_block + self.input_block - (i - li) - 1;
                assert!(r < slots && r < vec.len());
                vec[r] = weights[i * self.output_dims + j];
            }
        }
        encoder.encode_f64_polynomial_new(&vec, parms_id, scale)
    }

    /// Encode weights.
    pub fn encode_weights_bfv(&self, encoder: &BatchEncoder, weights: &[u64]) -> Plain2d {
        assert_eq!(weights.len(), self.input_dims * self.output_dims);
        let height = self.input_dims; let width = self.output_dims;
        let h = self.input_block; let w = self.output_block;
        let mut encoded_weights = Vec::with_capacity(ceil_div(height, h));
        let mut li = 0; 
        while li < height {
            let ui = height.min(li + h);
            let mut encoded_row = Vec::with_capacity(ceil_div(width, w));
            let mut lj = 0;
            while lj < width {
                let uj = width.min(lj + w);
                encoded_row.push(self.encode_weight_small_bfv(encoder, weights, li, ui, lj, uj));
                lj += w;
            }
            encoded_weights.push(encoded_row);
            li += h;
        }
        Plain2d::new(encoded_weights)
    }

    /// Encode weights.
    pub fn encode_weights_ckks(&self, encoder: &CKKSEncoder, weights: &[f64], parms_id: Option<ParmsID>, scale: f64) -> Plain2d {
        assert_eq!(weights.len(), self.input_dims * self.output_dims);
        let height = self.input_dims; let width = self.output_dims;
        let h = self.input_block; let w = self.output_block;
        let mut encoded_weights = Vec::with_capacity(ceil_div(height, h));
        let mut li = 0; 
        while li < height {
            let ui = height.min(li + h);
            let mut encoded_row = Vec::with_capacity(ceil_div(width, w));
            let mut lj = 0;
            while lj < width {
                let uj = width.min(lj + w);
                encoded_row.push(self.encode_weight_small_ckks(encoder, weights, li, ui, lj, uj, parms_id, scale));
                lj += w;
            }
            encoded_weights.push(encoded_row);
            li += h;
        }
        Plain2d::new(encoded_weights)
    }

    /// Encode inputs. They might be further encrypted with [Encryptor::encrypt].
    pub fn encode_inputs_bfv(&self, encoder: &BatchEncoder, inputs: &[u64]) -> Plain2d {
        assert_eq!(inputs.len(), self.batch_size * self.input_dims);
        let vecsize = self.input_block;
        let mut ret = Vec::with_capacity(self.batch_size);
        let mut li = 0; while li < self.batch_size {
            let ui = self.batch_size.min(li + self.batch_block);
            let mut encoded_row = Vec::with_capacity(ceil_div(self.input_dims, vecsize));
            let mut lj = 0; while lj < self.input_dims {
                let uj = self.input_dims.min(lj + vecsize);
                let mut vec = vec![0; self.poly_degree];
                for i in li..ui {
                    for j in lj..uj {
                        vec[(i - li) * self.input_block * self.output_block + (j - lj)] = inputs[i * self.input_dims + j];
                    }
                }
                encoded_row.push(encoder.encode_polynomial_new(&vec));
                lj += vecsize;
            }
            ret.push(encoded_row);
            li += self.batch_block;
        }
        Plain2d::new(ret)
    }

    /// Encode inputs. They might be further encrypted with [Encryptor::encrypt].
    pub fn encode_inputs_ckks(&self, encoder: &CKKSEncoder, inputs: &[f64], parms_id: Option<ParmsID>, scale: f64) -> Plain2d {
        assert_eq!(inputs.len(), self.batch_size * self.input_dims);
        let vecsize = self.input_block;
        let mut ret = Vec::with_capacity(self.batch_size);
        let mut li = 0; while li < self.batch_size {
            let ui = self.batch_size.min(li + self.batch_block);
            let mut encoded_row = Vec::with_capacity(ceil_div(self.input_dims, vecsize));
            let mut lj = 0; while lj < self.input_dims {
                let uj = self.input_dims.min(lj + vecsize);
                let mut vec = vec![0.0; self.poly_degree];
                for i in li..ui {
                    for j in lj..uj {
                        vec[(i - li) * self.input_block * self.output_block + (j - lj)] = inputs[i * self.input_dims + j];
                    }
                }
                encoded_row.push(encoder.encode_f64_polynomial_new(&vec, parms_id, scale));
                lj += vecsize;
            }
            ret.push(encoded_row);
            li += self.batch_block;
        }
        Plain2d::new(ret)
    }

    /// Returns the indices of the input terms in the encoded input plaintext/ciphertext.
    /// You cannot serialize the ciphertext with these indices only because this would lead other slots te be non-zero,
    /// making the multiplication result wrong. This function is thus marked deprecated.
    #[deprecated]
    pub fn input_terms(&self) -> Vec<usize> {
        let mut required = vec![];
        let vecsize = self.input_block;
        for i in 0..self.batch_block {
            for j in 0..vecsize {
                required.push(i * self.input_block * self.output_block + j);
            }
        }
        required
    }

    /// Encodes output. Useful for re-sharing matmul output. 
    /// Call with a random tensor `s`, and add it to the matmul result as `y0 = matmul_result + s` [Cipher2d::add_plain_inplace].
    /// The other share is `y1 = -s`. Then 'y0' and 'y1' form a valid re-sharing of the matmul result.
    pub fn encode_outputs_bfv(&self, encoder: &BatchEncoder, outputs: &[u64]) -> Plain2d {
        assert_eq!(outputs.len(), self.batch_size * self.output_dims);
        let vecsize = self.output_block;
        if !self.pack_lwe {
            let mut ret = Vec::with_capacity(ceil_div(self.batch_size, self.batch_block));
            let mut li = 0; while li < self.batch_size {
                let ui = self.batch_size.min(li + self.batch_block);
                let mut encoded_row = Vec::with_capacity(ceil_div(self.output_dims, vecsize));
                let mut lj = 0; while lj < self.output_dims {
                    let uj = self.output_dims.min(lj + vecsize);
                    let mut vec = vec![0; self.poly_degree];
                    for i in li..ui {
                        for j in lj..uj {
                            vec[(i - li) * self.input_block * self.output_block + (j - lj) * self.input_block + self.input_block - 1] = outputs[i * self.output_dims + j];
                        }
                    }
                    encoded_row.push(encoder.encode_polynomial_new(&vec));
                    lj += vecsize;
                }
                ret.push(encoded_row);
                li += self.batch_block;
            }
            Plain2d::new(ret)
        } else {
            let batch_block_count = ceil_div(self.batch_size, self.batch_block);
            let output_block_count = ceil_div(self.output_dims, self.output_block);
            let mut ret = vec![vec![0; self.poly_degree]; ceil_div(batch_block_count * output_block_count, self.input_block)];
            let mut li = 0; let mut di = 0; while li < self.batch_size {
                let ui = self.batch_size.min(li + self.batch_block);
                let mut lj = 0; let mut dj = 0; while lj < self.output_dims {
                    let uj = self.output_dims.min(lj + vecsize);
                    let cipher_id = di * ceil_div(self.output_dims, self.output_block) + dj;
                    let packed_id = cipher_id / self.input_block;
                    let packed_offset = cipher_id % self.input_block;
                    for i in li..ui {
                        for j in lj..uj {
                            ret[packed_id][(i - li) * self.input_block * self.output_block + (j - lj) * self.input_block + packed_offset] 
                                = outputs[i * self.output_dims + j];
                        }
                    }
                    dj += 1;
                    lj += vecsize; 
                }
                di += 1;
                li += self.batch_block;
            }
            let encoded = ret.into_iter().map(|x| encoder.encode_polynomial_new(&x)).collect::<Vec<_>>();
            Plain2d::new(vec![encoded])
        }
    }

    /// CKKS counterpart of [MatmulHelper::encode_outputs_bfv].
    pub fn encode_outputs_ckks(&self, encoder: &CKKSEncoder, outputs: &[f64], parms_id: Option<ParmsID>, scale: f64) -> Plain2d {
        assert_eq!(outputs.len(), self.batch_size * self.output_dims);
        let vecsize = self.output_block;
            if !self.pack_lwe {
            let mut ret = Vec::with_capacity(ceil_div(self.batch_size, self.batch_block));
            let mut li = 0; while li < self.batch_size {
                let ui = self.batch_size.min(li + self.batch_block);
                let mut encoded_row = Vec::with_capacity(ceil_div(self.output_dims, vecsize));
                let mut lj = 0; while lj < self.output_dims {
                    let uj = self.output_dims.min(lj + vecsize);
                    let mut vec = vec![0.0f64; self.poly_degree];
                    for i in li..ui {
                        for j in lj..uj {
                            vec[(i - li) * self.input_block * self.output_block + (j - lj) * self.input_block + self.input_block - 1] = outputs[i * self.output_dims + j];
                        }
                    }
                    encoded_row.push(encoder.encode_f64_polynomial_new(&vec, parms_id, scale));
                    lj += vecsize;
                }
                ret.push(encoded_row);
                li += self.batch_block;
            }
            Plain2d::new(ret)
        } else {
            let batch_block_count = ceil_div(self.batch_size, self.batch_block);
            let output_block_count = ceil_div(self.output_dims, self.output_block);
            let mut ret = vec![vec![0.0f64; self.poly_degree]; ceil_div(batch_block_count * output_block_count, self.input_block)];
            let mut li = 0; let mut di = 0; while li < self.batch_size {
                let ui = self.batch_size.min(li + self.batch_block);
                let mut lj = 0; let mut dj = 0; while lj < self.output_dims {
                    let uj = self.output_dims.min(lj + vecsize);
                    let cipher_id = di * ceil_div(self.output_dims, self.output_block) + dj;
                    let packed_id = cipher_id / self.input_block;
                    let packed_offset = cipher_id % self.input_block;
                    for i in li..ui {
                        for j in lj..uj {
                            ret[packed_id][(i - li) * self.input_block * self.output_block + (j - lj) * self.input_block + packed_offset] 
                                = outputs[i * self.output_dims + j];
                        }
                    }
                    dj += 1;
                    lj += vecsize; 
                }
                di += 1;
                li += self.batch_block;
            }
            let encoded = ret.into_iter().map(|x| encoder.encode_f64_polynomial_new(&x, parms_id, scale)).collect::<Vec<_>>();
            Plain2d::new(vec![encoded])
        }
    }

    /// Returns the indices of the output terms in the encoded input plaintext/ciphertext.
    /// Useful with [Cipher2d::serialize_terms].
    pub fn output_terms(&self) -> Vec<usize> {
        let mut required = vec![];
        let vecsize = self.output_block;
        for i in 0..self.batch_block {
            for j in 0..vecsize {
                required.push(i * self.input_block * self.output_block + j * self.input_block + self.input_block - 1);
            }
        }
        required
    }

    /// Decrypt the outputs. Wrapper of [Decryptor::decrypt_new].
    pub fn decrypt_outputs_bfv(&self, encoder: &BatchEncoder, decryptor: &Decryptor, outputs: &Cipher2d) -> Vec<u64> {
        let mut dec = vec![0; self.batch_size * self.output_dims];
        let vecsize = self.output_block;
        let mut pt = Plaintext::new();
        if !self.pack_lwe {
            let mut buffer = vec![0; self.poly_degree];
            let mut li = 0; let mut di = 0; while li < self.batch_size {
                let ui = self.batch_size.min(li + self.batch_block);
                let mut lj = 0; let mut dj = 0; while lj < self.output_dims {
                    let uj = self.output_dims.min(lj + vecsize);
                    decryptor.decrypt(&outputs.data[di][dj], &mut pt);
                    encoder.decode_polynomial(&pt, &mut buffer);
                    for i in li..ui {
                        for j in lj..uj {
                            dec[i * self.output_dims + j] = buffer[(i - li) * self.input_block * self.output_block + (j - lj) * self.input_block + self.input_block - 1];
                        }
                    }
                    dj += 1;
                    lj += vecsize; 
                }
                di += 1;
                li += self.batch_block;
            }
        } else {
            let buffers = outputs.data[0].iter().map(|x| {
                decryptor.decrypt(x, &mut pt);
                encoder.decode_polynomial_new(&pt)
            }).collect::<Vec<_>>();
            let mut li = 0; let mut di = 0; while li < self.batch_size {
                let ui = self.batch_size.min(li + self.batch_block);
                let mut lj = 0; let mut dj = 0; while lj < self.output_dims {
                    let uj = self.output_dims.min(lj + vecsize);
                    let cipher_id = di * ceil_div(self.output_dims, self.output_block) + dj;
                    let packed_id = cipher_id / self.input_block;
                    let packed_offset = cipher_id % self.input_block;
                    for i in li..ui {
                        for j in lj..uj {
                            dec[i * self.output_dims + j] = buffers[packed_id][(i - li) * self.input_block * self.output_block + (j - lj) * self.input_block + packed_offset];
                        }
                    }
                    dj += 1;
                    lj += vecsize; 
                }
                di += 1;
                li += self.batch_block;
            }
        }
        dec
    }

    /// Decrypt the outputs. Wrapper of [Decryptor::decrypt_new].
    pub fn decrypt_outputs_ckks(&self, encoder: &CKKSEncoder, decryptor: &Decryptor, outputs: &Cipher2d) -> Vec<f64> {
        let mut dec = vec![0.0f64; self.batch_size * self.output_dims];
        let vecsize = self.output_block;
        let mut pt = Plaintext::new();
        if !self.pack_lwe {
            let mut buffer = vec![0.0f64; self.poly_degree];
            let mut li = 0; let mut di = 0; while li < self.batch_size {
                let ui = self.batch_size.min(li + self.batch_block);
                let mut lj = 0; let mut dj = 0; while lj < self.output_dims {
                    let uj = self.output_dims.min(lj + vecsize);
                    decryptor.decrypt(&outputs.data[di][dj], &mut pt);
                    encoder.decode_polynomial(&pt, &mut buffer);
                    for i in li..ui {
                        for j in lj..uj {
                            dec[i * self.output_dims + j] = buffer[(i - li) * self.input_block * self.output_block + (j - lj) * self.input_block + self.input_block - 1];
                        }
                    }
                    dj += 1;
                    lj += vecsize; 
                }
                di += 1;
                li += self.batch_block;
            }
        } else {
            let buffers = outputs.data[0].iter().map(|x| {
                decryptor.decrypt(x, &mut pt);
                encoder.decode_polynomial_new(&pt)
            }).collect::<Vec<_>>();
            let mut li = 0; let mut di = 0; while li < self.batch_size {
                let ui = self.batch_size.min(li + self.batch_block);
                let mut lj = 0; let mut dj = 0; while lj < self.output_dims {
                    let uj = self.output_dims.min(lj + vecsize);
                    let cipher_id = di * ceil_div(self.output_dims, self.output_block) + dj;
                    let packed_id = cipher_id / self.input_block;
                    let packed_offset = cipher_id % self.input_block;
                    for i in li..ui {
                        for j in lj..uj {
                            dec[i * self.output_dims + j] = buffers[packed_id][(i - li) * self.input_block * self.output_block + (j - lj) * self.input_block + packed_offset];
                        }
                    }
                    dj += 1;
                    lj += vecsize; 
                }
                di += 1;
                li += self.batch_block;
            }
        }
        dec
    }

    /// Compress the output of matmul with Pack LWEs
    pub fn pack_outputs(&self, evaluator: &Evaluator, auto_key: &GaloisKeys, cipher: &Cipher2d) -> Cipher2d {
        assert!(self.pack_lwe);
        if cipher.data.is_empty() || cipher.data[0].is_empty() {return Cipher2d::new(vec![vec![]]);}
        let pack_slots = self.input_block;
        let total_count = cipher.data.len() * cipher.data[0].len();
        let mut output = Vec::with_capacity(ceil_div(total_count, pack_slots));
        let mut current = None;
        let mut current_slot = 0;
        let context_data = evaluator.get_context_data(cipher.data[0][0].parms_id());
        let poly_degree = context_data.parms().poly_modulus_degree();
        let modulus = context_data.parms().coeff_modulus();
        let field_trace_logn = (poly_degree / pack_slots).ilog2() as usize;

        let mut buffer = cipher.data[0][0].clone();
        buffer.set_is_ntt_form(false);
        let mut shifted = buffer.clone();
        shifted.set_is_ntt_form(false);
        for i in 0..cipher.data.len() {
            for j in 0..cipher.data[0].len() {
                let shift = pack_slots - 1;
                let mut ciphertext = cipher.data[i][j].clone();
                if context_data.is_ckks() {
                    evaluator.transform_from_ntt_inplace(&mut ciphertext);
                }
                if shift != 0 {
                    crate::polymod::negacyclic_shift_ps(
                        ciphertext.data(), 
                        poly_degree * 2 - shift, 
                        ciphertext.size(), poly_degree, modulus, 
                        buffer.data_mut()
                    );
                } else {
                    buffer.data_mut().copy_from_slice(ciphertext.data());
                }
                evaluator.divide_by_poly_modulus_degree_inplace(&mut buffer, Some((poly_degree / pack_slots) as u64));
                if context_data.is_ckks() {
                    evaluator.transform_to_ntt_inplace(&mut buffer);
                }
                evaluator.field_trace_inplace(&mut buffer, auto_key, field_trace_logn);
                if context_data.is_ckks() {
                    evaluator.transform_from_ntt_inplace(&mut buffer);
                }
                let shift = current_slot;
                if shift != 0 {
                    crate::polymod::negacyclic_shift_ps(
                        buffer.data(), 
                        shift,
                        ciphertext.size(), poly_degree, modulus, 
                        shifted.data_mut()
                    );
                } else {
                    shifted.data_mut().copy_from_slice(buffer.data());
                }
                if current.is_none() {
                    current = Some(shifted);
                    shifted = buffer.clone();
                    shifted.set_is_ntt_form(false);
                } else {
                    evaluator.add_inplace(current.as_mut().unwrap(), &shifted);
                }
                current_slot += 1;
                if current_slot == pack_slots {
                    current_slot = 0;
                    output.push(current.take().unwrap());
                }
            }
        }
        if current.is_some() {
            output.push(current.unwrap());
        }
        if context_data.is_ckks() {
            for each in output.iter_mut() {
                evaluator.transform_to_ntt_inplace(each);
            }
        }

        
        Cipher2d::new(vec![output])
    }

    /// Multiply two 2d matrices `[y]=[x]*W`.
    pub fn matmul(&self, evaluator: &Evaluator, x: &Cipher2d, w: &Plain2d) -> Cipher2d {
        let mut ret = Vec::with_capacity(ceil_div(self.batch_size, self.batch_block));
        assert_eq!(x.data.len(), ceil_div(self.batch_size, self.batch_block), "Input batchsize incorrect.");
        assert_eq!(w.data.len(), ceil_div(self.input_dims, self.input_block), "Weight input dim incorrect.");
        let output_vec_count = ceil_div(self.output_dims, self.output_block);
        for b in 0..ceil_div(self.batch_size, self.batch_block) {
            let mut out_vecs = vec![Ciphertext::new(); output_vec_count];
            for i in 0..w.data.len() {
                for j in 0..w.data[i].len() {
                    let prod = evaluator.multiply_plain_new(&x.data[b][i], &w.data[i][j]);
                    if i == 0 {
                        out_vecs[j] = prod;
                    } else {
                        evaluator.add_inplace(&mut out_vecs[j], &prod);
                    }
                }
            }
            ret.push(out_vecs);
        }
        Cipher2d::new(ret)
    }

    /// Multiply two 2d matrices `[y]=x*[W]`.
    pub fn matmul_reverse(&self, evaluator: &Evaluator, x: &Plain2d, w: &Cipher2d) -> Cipher2d {
        let mut ret = Vec::with_capacity(ceil_div(self.batch_size, self.batch_block));
        assert_eq!(x.data.len(), ceil_div(self.batch_size, self.batch_block), "Input batchsize incorrect.");
        assert_eq!(w.data.len(), ceil_div(self.input_dims, self.input_block), "Weight input dim incorrect.");
        let output_vec_count = ceil_div(self.output_dims, self.output_block);
        for b in 0..ceil_div(self.batch_size, self.batch_block) {
            let mut out_vecs = vec![Ciphertext::new(); output_vec_count];
            for i in 0..w.data.len() {
                for j in 0..w.data[i].len() {
                    let prod = evaluator.multiply_plain_new(&w.data[i][j], &x.data[b][i]);
                    if i == 0 {
                        out_vecs[j] = prod;
                    } else {
                        evaluator.add_inplace(&mut out_vecs[j], &prod);
                    }
                }
            }
            ret.push(out_vecs);
        }
        Cipher2d::new(ret)
    }

}

#[cfg(test)]
pub(crate) mod tests {

    use rand::Rng;
    use crate::{BatchEncoder, CoeffModulus, Decryptor, EncryptionParameters, Encryptor, Evaluator, ExpandSeed, HeContext, KeyGenerator, Modulus, SerializableWithHeContext};
    use super::*;

    pub fn random_u64_array(len: usize, modulus: &Modulus) -> Vec<u64> {
        let mut rng = rand::thread_rng();
        (0..len).map(|_| modulus.reduce(rng.gen())).collect()
    }

    pub fn random_f64_array(len: usize, bound: f64) -> Vec<f64> {
        let mut rng = rand::thread_rng();
        (0..len).map(|_| rng.gen::<f64>() * 2.0 * bound - bound).collect()
    }

    fn test_bfv_matmul(poly_degree: usize, plain_modulus: u64, q_bits: Vec<usize>, batch_size: usize, input_dims: usize, output_dims: usize, pack_lwe: bool) {
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
        let auto_key = &keygen.create_automorphism_keys(false);

        // let print_dec = |x: &Cipher2d| {
        //     for (i, each) in x.data.iter().enumerate() {
        //         for (j, each) in each.iter().enumerate() {
        //             let dec = decryptor.decrypt_new(each);
        //             let dec = encoder.decode_polynomial_new(&dec);
        //             println!("i={}, j={}, dec={:?}", i, j, dec);
        //         }
        //     }
        // };

        // generate data
        let plain_modulus = params.plain_modulus();
        let inputs = random_u64_array(batch_size * input_dims, plain_modulus);
        let weights = random_u64_array(output_dims * input_dims, plain_modulus);
        let output_bias = random_u64_array(batch_size * output_dims, plain_modulus);
        // calc
        let helper = MatmulHelper::new(batch_size, input_dims, output_dims, params.poly_modulus_degree(), MatmulHelperObjective::CipherPlain, pack_lwe);
        let inputs_encoded = helper.encode_inputs_bfv(&encoder, &inputs);
        let weights_encoded = helper.encode_weights_bfv(&encoder, &weights);
        let inputs_encrypted = inputs_encoded.encrypt_symmetric(&encryptor).expand_seed(&context);
        let mut inputs_serialized = vec![]; inputs_encrypted.serialize(&context, &mut inputs_serialized).unwrap();
        assert_eq!(inputs_serialized.len(), inputs_encrypted.serialized_size(&context));
        let inputs_encrypted = Cipher2d::deserialize(&context, &mut inputs_serialized.as_slice()).unwrap();
        let mut outputs_encrypted = helper.matmul(&evaluator, &inputs_encrypted, &weights_encoded);  
        if pack_lwe {
            outputs_encrypted = helper.pack_outputs(&evaluator, auto_key, &outputs_encrypted)
        }
        let output_bias_encoded = helper.encode_outputs_bfv(&encoder, &output_bias);
        outputs_encrypted.add_plain_inplace(&evaluator, &output_bias_encoded);
        if !pack_lwe {
            let outputs_terms = helper.output_terms();
            let mut outputs_serialized = vec![];
            outputs_encrypted.serialize_terms(&context, &outputs_terms, &mut outputs_serialized).unwrap();
            assert_eq!(outputs_serialized.len(), outputs_encrypted.serialized_terms_size(&context, outputs_terms.len()));
            outputs_encrypted = Cipher2d::deserialize_terms(&context, &outputs_terms, &mut outputs_serialized.as_slice()).unwrap();
        } else {
            let mut outputs_serialized = vec![];
            outputs_encrypted.serialize(&context, &mut outputs_serialized).unwrap();
            assert_eq!(outputs_serialized.len(), outputs_encrypted.serialized_size(&context));
            outputs_encrypted = Cipher2d::deserialize(&context, &mut outputs_serialized.as_slice()).unwrap();
        }
        let outputs = helper.decrypt_outputs_bfv(&encoder, &decryptor, &outputs_encrypted);
        // plain calc
        let mut outputs_plain = vec![0; batch_size * output_dims]; 
        for i in 0..batch_size {
            for j in 0..output_dims {
                for k in 0..input_dims {
                    outputs_plain[i * output_dims + j] += plain_modulus.reduce_u128(inputs[i * input_dims + k] as u128 * weights[k * output_dims + j] as u128);
                    outputs_plain[i * output_dims + j] = plain_modulus.reduce(outputs_plain[i * output_dims + j]);
                }
                outputs_plain[i * output_dims + j] = plain_modulus.reduce(outputs_plain[i * output_dims + j] + output_bias[i * output_dims + j]);
            }
        }
        // check correct
        assert_eq!(outputs_plain, outputs);
    }


    fn test_ckks_matmul(poly_degree: usize, scale: f64, q_bits: Vec<usize>, batch_size: usize, input_dims: usize, output_dims: usize, pack_lwe: bool) {
        let params = EncryptionParameters::new(crate::SchemeType::CKKS)
            .set_poly_modulus_degree(poly_degree)
            .set_coeff_modulus(&CoeffModulus::create(poly_degree, q_bits));
        let context = HeContext::new(params.clone(), true, crate::SecurityLevel::None);
        let encoder = CKKSEncoder::new(context.clone());
        let keygen = KeyGenerator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false)).set_secret_key(keygen.secret_key().clone());
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let evaluator = Evaluator::new(context.clone());
        let auto_key = keygen.create_automorphism_keys(false);

        // let print_dec = |x: &Cipher2d| {
        //     for (i, each) in x.data.iter().enumerate() {
        //         for (j, each) in each.iter().enumerate() {
        //             let dec = decryptor.decrypt_new(each);
        //             let dec = encoder.decode_polynomial_new(&dec);
        //             print!("i={}, j={}, dec=[", i, j);
        //             for each in dec {print!("{:.0}, ", each);}
        //             println!("]");
        //         }
        //     }
        // };

        // generate data
        let bound = 10.0;
        let inputs = random_f64_array(batch_size * input_dims, bound);
        let weights = random_f64_array(output_dims * input_dims, bound);
        let output_bias = random_f64_array(batch_size * output_dims, bound);
        // calc
        let helper = MatmulHelper::new(batch_size, input_dims, output_dims, params.poly_modulus_degree(), MatmulHelperObjective::CipherPlain, pack_lwe);
        let inputs_encoded = helper.encode_inputs_ckks(&encoder, &inputs, None, scale);
        let weights_encoded = helper.encode_weights_ckks(&encoder, &weights, None, scale);
        let inputs_encrypted = inputs_encoded.encrypt_symmetric(&encryptor).expand_seed(&context);
        let mut inputs_serialized = vec![]; inputs_encrypted.serialize(&context, &mut inputs_serialized).unwrap();
        assert_eq!(inputs_serialized.len(), inputs_encrypted.serialized_size(&context));
        let inputs_encrypted = Cipher2d::deserialize(&context, &mut inputs_serialized.as_slice()).unwrap();
        let mut outputs_encrypted = helper.matmul(&evaluator, &inputs_encrypted, &weights_encoded);
        if pack_lwe {
            outputs_encrypted = helper.pack_outputs(&evaluator, &auto_key, &outputs_encrypted)
        }
        let output_bias_encoded = helper.encode_outputs_ckks(&encoder, &output_bias, None, scale * scale / params.coeff_modulus()[params.coeff_modulus().len() - 2].value() as f64);
        outputs_encrypted.rescale_to_next_inplace(&evaluator);
        outputs_encrypted.add_plain_inplace(&evaluator, &output_bias_encoded);
        if !pack_lwe {
            let outputs_terms = helper.output_terms();
            let mut outputs_serialized = vec![];
            outputs_encrypted.serialize_terms(&context, &outputs_terms, &mut outputs_serialized).unwrap();
            assert_eq!(outputs_serialized.len(), outputs_encrypted.serialized_terms_size(&context, outputs_terms.len()));
            outputs_encrypted = Cipher2d::deserialize_terms(&context, &outputs_terms, &mut outputs_serialized.as_slice()).unwrap();
        } else {
            let mut outputs_serialized = vec![];
            outputs_encrypted.serialize(&context, &mut outputs_serialized).unwrap();
            assert_eq!(outputs_serialized.len(), outputs_encrypted.serialized_size(&context));
            outputs_encrypted = Cipher2d::deserialize(&context, &mut outputs_serialized.as_slice()).unwrap();
        }
        let outputs = helper.decrypt_outputs_ckks(&encoder, &decryptor, &outputs_encrypted);
        // plain calc
        let mut outputs_plain = vec![0.0; batch_size * output_dims]; 
        for i in 0..batch_size {
            for j in 0..output_dims {
                for k in 0..input_dims {
                    outputs_plain[i * output_dims + j] += inputs[i * input_dims + k] * weights[k * output_dims + j];
                }
                outputs_plain[i * output_dims + j] += output_bias[i * output_dims + j];
            }
        }
        // check correct
        for i in 0..outputs_plain.len() {
            assert!((outputs_plain[i] - outputs[i]).abs() < 1e-1);
        }
    }

    #[test]
    fn bfv_matmul() {
        test_bfv_matmul(4096, 1<<20, vec![60, 49], 4, 5, 6, false);  
        test_bfv_matmul(4096, 1<<20, vec![60, 49], 17, 80, 96, false);
        test_bfv_matmul(4096, 1<<20, vec![60, 49], 4, 5, 6, true);  
        test_bfv_matmul(4096, 1<<20, vec![60, 49], 17, 80, 100, true);
    }

    #[test]
    fn ckks_matmul() {
        test_ckks_matmul(8192, 2.0f64.powf(40.0), vec![60, 40, 40, 60], 4, 5, 6, false);
        test_ckks_matmul(8192, 2.0f64.powf(40.0), vec![60, 40, 40, 60], 17, 80, 96, false);
        test_ckks_matmul(8192, 2.0f64.powf(40.0), vec![60, 40, 40, 60], 4, 5, 6, true);
        test_ckks_matmul(8192, 2.0f64.powf(40.0), vec![60, 40, 40, 60], 17, 80, 100, true);
    }

}