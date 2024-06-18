//! Implement HE-based 2d-convoluion. Supports both BFV(BGV) and CKKS.
//! 
//! Calculate y = Conv2d(x, w), where we call y as 'outputs', x as 'inputs', w as 'weights'.
//! x has shape `[batch_size, input_channels, image_height, image_width]`, 
//! w has shape `[output_channels, input_channels, kernel_height, kernel_width]`, 
//! y has shape `[batch_size, output_channels, output_height, output_width]`,
//! where `output_height = image_height - kernel_height + 1`,
//! `output_width = image_width - kernel_width + 1`.
//! These semantics match those of fully connected layer in deep learning.
//! The users should provide the matrices as a 1d-array.
//! Check the test functions for examples.

pub use super::matmul::{Plain2d, Cipher2d, MatmulHelperObjective as Conv2dHelperObjective};

use crate::{
    BatchEncoder, CKKSEncoder,
    Ciphertext,
    Decryptor, Evaluator, 
    ParmsID,
};

/// Provide utilities for 2d convolution.
pub struct Conv2dHelper {

    batch_size: usize,
    input_channels: usize,
    output_channels: usize,
    image_height: usize, image_width: usize,
    kernel_height: usize, kernel_width: usize,
    slot_count: usize,

    batch_block: usize,
    input_channel_block: usize,
    output_channel_block: usize,
    image_height_block: usize, image_width_block: usize,

    #[allow(dead_code)]
    objective: Conv2dHelperObjective,

}

fn ceil_div(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

impl Conv2dHelper {

    /// Create helper instance, given shape info of the tensors.
    pub fn new(
        batch_size: usize,
        input_channels: usize,
        output_channels: usize,
        image_height: usize, image_width: usize,
        kernel_height: usize, kernel_width: usize,
        poly_degree: usize,
        objective: Conv2dHelperObjective,
    ) -> Self {

        let mut best = usize::MAX;
        let mut best_b = 0;
        let mut best_h = 0;
        let mut best_w = 0;
        let mut best_ci = 0;
        let mut best_co = 0;
        let slot_count = poly_degree;

        for b in (1..=batch_size).rev() {
            let upper = slot_count / b;
            // println!("b: {}, slot_count: {}, image_height: {}, upper: {}", b, slot_count, image_height, upper);
            for h in (kernel_height..=image_height.min(upper)).rev() {
                let upper = upper / h;
                // println!("b: {}, h: {}", b, h);
                for w in (kernel_width..=image_width.min(upper)).rev() {
                    let upper = upper / w;
                    // println!("b: {}, h: {}, w: {}", b, h, w);
                    for co in (1..=output_channels.min(upper)).rev() {
                        let ci = input_channels.min(upper / co);
                        // println!("b: {}, h: {}, w: {}, ci: {}, co: {}", b, h, w, ci, co);
                        if ci == 0 {continue;}
                        let cut_b = ceil_div(batch_size, b);
                        let cut_h = ceil_div(image_height - kernel_height + 1, h - kernel_height + 1);
                        let cut_w = ceil_div(image_width - kernel_width + 1, w - kernel_width + 1);
                        let cut_ci = ceil_div(input_channels, ci);
                        let cut_co = ceil_div(output_channels, co);
                        let cost_input = cut_b * cut_h * cut_w * cut_ci;
                        let cost_output = cut_b * cut_h * cut_w * cut_co;
                        let cost_weight = cut_ci * cut_co;
                        let cost = match objective {
                            Conv2dHelperObjective::CipherPlain => cost_input + cost_output,
                            Conv2dHelperObjective::PlainCipher => cost_weight + cost_output,
                            Conv2dHelperObjective::CpAddPc => cost_input + cost_output + cost_weight,
                        };
                        if cost < best {
                            best = cost;
                            best_b = b;
                            best_h = h;
                            best_w = w;
                            best_ci = ci;
                            best_co = co;
                        }
                    }
                }
            }
        }

        // println!("Blocking:");
        // println!("  batch: {} => {}", batch_size, best_b);
        // println!("  input channel: {} => {}", input_channels, best_ci);
        // println!("  output channel: {} => {}", output_channels, best_co);
        // println!("  image height: {} => {}", image_height, best_h);
        // println!("  image width: {} => {}", image_width, best_w);

        Self {
            batch_size,
            input_channels,
            output_channels,
            image_height, image_width,
            kernel_height, kernel_width,
            batch_block: best_b,
            input_channel_block: best_ci,
            output_channel_block: best_co,
            image_height_block: best_h,
            image_width_block: best_w,
            objective,
            slot_count: poly_degree
        }

    }

    /// Encode weights.
    pub fn encode_weights_bfv(&self, encoder: &BatchEncoder, inputs: &[u64]) -> Plain2d {
        assert_eq!(inputs.len(), self.kernel_height * self.kernel_width * self.input_channels * self.output_channels);
        let block_size = self.image_height_block * self.image_width_block;
        let mut ret = Vec::with_capacity(ceil_div(self.output_channels, self.output_channel_block));
        let mut loc = 0; while loc < self.output_channels {
            let uoc = self.output_channels.min(loc + self.output_channel_block);
            let mut current_channel = Vec::with_capacity(ceil_div(self.input_channels, self.input_channel_block));
            let mut lic = 0; while lic < self.input_channels {
                let uic = self.input_channels.min(lic + self.input_channel_block);
                let mut spread = vec![0; self.input_channel_block * self.output_channel_block * self.image_width_block * self.image_height];
                for oc in loc..uoc {
                    for ic in lic..uic {
                        for ki in 0..self.kernel_height {
                            for kj in 0..self.kernel_width {
                                let spread_index = 
                                    (oc - loc) * self.input_channel_block * block_size 
                                    + (self.input_channel_block - 1 - (ic - lic)) * block_size 
                                    + ki * self.image_width_block + kj;
                                let weight_index = 
                                    ((oc * self.input_channels) + ic) * (self.kernel_height * self.kernel_width)
                                    + (self.kernel_height - ki - 1) * self.kernel_width
                                    + (self.kernel_width - kj - 1);
                                spread[spread_index] = inputs[weight_index];
                            }
                        }
                    }
                }
                let pt = encoder.encode_polynomial_new(&spread);
                current_channel.push(pt);
                lic += self.input_channel_block;
            }
            ret.push(current_channel);
            loc += self.output_channel_block;
        }
        Plain2d::new(ret)
    }

    /// Encode weights.
    pub fn encode_weights_ckks(&self, encoder: &CKKSEncoder, inputs: &[f64], parms_id: Option<ParmsID>, scale: f64) -> Plain2d {
        assert_eq!(inputs.len(), self.kernel_height * self.kernel_width * self.input_channels * self.output_channels);
        let block_size = self.image_height_block * self.image_width_block;
        let mut ret = Vec::with_capacity(ceil_div(self.output_channels, self.output_channel_block));
        let mut loc = 0; while loc < self.output_channels {
            let uoc = self.output_channels.min(loc + self.output_channel_block);
            let mut current_channel = Vec::with_capacity(ceil_div(self.input_channels, self.input_channel_block));
            let mut lic = 0; while lic < self.input_channels {
                let uic = self.input_channels.min(lic + self.input_channel_block);
                let mut spread = vec![0.0; self.input_channel_block * self.output_channel_block * self.image_width_block * self.image_height];
                for oc in loc..uoc {
                    for ic in lic..uic {
                        for ki in 0..self.kernel_height {
                            for kj in 0..self.kernel_width {
                                let spread_index = 
                                    (oc - loc) * self.input_channel_block * block_size 
                                    + (self.input_channel_block - 1 - (ic - lic)) * block_size 
                                    + ki * self.image_width_block + kj;
                                let weight_index = 
                                    ((oc * self.input_channels) + ic) * (self.kernel_height * self.kernel_width)
                                    + (self.kernel_height - ki - 1) * self.kernel_width
                                    + (self.kernel_width - kj - 1);
                                spread[spread_index] = inputs[weight_index];
                            }
                        }
                    }
                }
                let pt = encoder.encode_f64_polynomial_new(&spread, parms_id, scale);
                current_channel.push(pt);
                lic += self.input_channel_block;
            }
            ret.push(current_channel);
            loc += self.output_channel_block;
        }
        Plain2d::new(ret)
    }

    fn get_total_batch_size(&self) -> usize {
        let kh = self.kernel_height - 1;
        let kw = self.kernel_width - 1;
        let sh = ceil_div(self.image_height - kh, self.image_height_block - kh);
        let sw = ceil_div(self.image_width - kw, self.image_width_block - kw);
        ceil_div(self.batch_size, self.batch_block) * sh * sw
    }

    /// Encode inputs. They might be further encrypted with [Encryptor::encrypt].
    pub fn encode_inputs_bfv(&self, encoder: &BatchEncoder, inputs: &[u64]) -> Plain2d {
        assert_eq!(inputs.len(), self.batch_size * self.input_channels * self.image_height * self.image_width);
        
        let kh = self.kernel_height - 1;
        let kw = self.kernel_width - 1;
        let sh = ceil_div(self.image_height - kh, self.image_height_block - kh);
        let sw = ceil_div(self.image_width - kw, self.image_width_block - kw);
        let total_batch_size = ceil_div(self.batch_size, self.batch_block) * sh * sw;
        let image_size = self.image_height * self.image_width;
        let block_size = self.image_height_block * self.image_width_block;
        let mut ret = Vec::with_capacity(total_batch_size);

        let mut lb = 0; while lb < self.batch_size {
            let ub = self.batch_size.min(lb + self.batch_block);
            for ih in 0..sh {
                for iw in 0..sw {
                    let si = ih * (self.image_height_block - kh);
                    let sj = iw * (self.image_width_block - kw);
                    let ui = self.image_height.min(si + self.image_height_block);
                    let uj = self.image_width.min(sj + self.image_width_block);
                    let mut group = Vec::with_capacity(ceil_div(self.input_channels, self.input_channel_block));
                    let mut lci = 0; while lci < self.input_channels {
                        let uci = self.input_channels.min(lci + self.input_channel_block);
                        let mut vec = vec![0; self.slot_count];
                        for b in 0..ub-lb {
                            for tci in 0..uci-lci {
                                for ti in si..ui {
                                    for tj in sj..uj {
                                        let input_index = 
                                            (lb + b) * self.input_channels * image_size
                                            + (lci + tci) * image_size
                                            + ti * self.image_width + tj;
                                        let vec_index =
                                            b * self.input_channel_block * self.output_channel_block * block_size
                                            + tci * block_size + (ti - si) * self.image_width_block + (tj - sj);
                                        vec[vec_index] = inputs[input_index];
                                    }
                                }
                            }
                        }
                        let pt = encoder.encode_polynomial_new(&vec);
                        group.push(pt);
                        lci += self.input_channel_block;
                    }
                    ret.push(group);
                }
            }
            lb += self.batch_block;
        }
        Plain2d::new(ret)
    }

    /// Encode inputs. They might be further encrypted with [Encryptor::encrypt].
    pub fn encode_inputs_ckks(&self, encoder: &CKKSEncoder, inputs: &[f64], parms_id: Option<ParmsID>, scale: f64) -> Plain2d {
        assert_eq!(inputs.len(), self.batch_size * self.input_channels * self.image_height * self.image_width);
        
        let kh = self.kernel_height - 1;
        let kw = self.kernel_width - 1;
        let sh = ceil_div(self.image_height - kh, self.image_height_block - kh);
        let sw = ceil_div(self.image_width - kw, self.image_width_block - kw);
        let total_batch_size = ceil_div(self.batch_size, self.batch_block) * sh * sw;
        let image_size = self.image_height * self.image_width;
        let block_size = self.image_height_block * self.image_width_block;
        let mut ret = Vec::with_capacity(total_batch_size);

        let mut lb = 0; while lb < self.batch_size {
            let ub = self.batch_size.min(lb + self.batch_block);
            for ih in 0..sh {
                for iw in 0..sw {
                    let si = ih * (self.image_height_block - kh);
                    let sj = iw * (self.image_width_block - kw);
                    let ui = self.image_height.min(si + self.image_height_block);
                    let uj = self.image_width.min(sj + self.image_width_block);
                    let mut group = Vec::with_capacity(ceil_div(self.input_channels, self.input_channel_block));
                    let mut lci = 0; while lci < self.input_channels {
                        let uci = self.input_channels.min(lci + self.input_channel_block);
                        let mut vec = vec![0.0; self.slot_count];
                        for b in 0..ub-lb {
                            for tci in 0..uci-lci {
                                for ti in si..ui {
                                    for tj in sj..uj {
                                        let input_index = 
                                            (lb + b) * self.input_channels * image_size
                                            + (lci + tci) * image_size
                                            + ti * self.image_width + tj;
                                        let vec_index =
                                            b * self.input_channel_block * self.output_channel_block * block_size
                                            + tci * block_size + (ti - si) * self.image_width_block + (tj - sj);
                                        vec[vec_index] = inputs[input_index];
                                    }
                                }
                            }
                        }
                        let pt = encoder.encode_f64_polynomial_new(&vec, parms_id, scale);
                        group.push(pt);
                        lci += self.input_channel_block;
                    }
                    ret.push(group);
                }
            }
            lb += self.batch_block;
        }
        Plain2d::new(ret)
    }

    /// Encodes output. Useful for re-sharing conv2d output. 
    /// Call with a random tensor `s`, and add it to the conv2d result as `y0 = conv2d_result + s` [Cipher2d::add_plain_inplace].
    /// The other share is `y1 = -s`. Then 'y0' and 'y1' form a valid re-sharing of the conv2d result.
    pub fn encode_outputs_bfv(&self, encoder: &BatchEncoder, outputs: &[u64]) -> Plain2d {
        let interval = self.image_height_block * self.image_width_block;
        let yh = self.image_height_block - self.kernel_height + 1;
        let yw = self.image_width_block - self.kernel_width + 1;
        let oyh = self.image_height - self.kernel_height + 1;
        let oyw = self.image_width - self.kernel_width + 1;
        assert_eq!(outputs.len(), self.batch_size * self.output_channels * oyh * oyw);
        let kh = self.kernel_height - 1;
        let kw = self.kernel_width - 1;
        let sh = ceil_div(self.image_height - kh, self.image_height_block - kh);
        let sw = ceil_div(self.image_width - kw, self.image_width_block - kw);
        let total_batch_size = ceil_div(self.batch_size, self.batch_block) * sh * sw;
        let mut ret = Vec::with_capacity(total_batch_size);
        for eb in 0..total_batch_size {
            let ob = eb / (sh * sw);
            let si = (eb % (sh * sw)) / sw;
            let sj = eb % sw;
            let lb = ob * self.batch_block;
            let ub = self.batch_size.min(lb + self.batch_block);
            let mut group = Vec::with_capacity(ceil_div(self.output_channels, self.output_channel_block));
            let mut lc = 0; while lc < self.output_channels {
                let uc = self.output_channels.min(lc + self.output_channel_block);
                let mut mask = vec![0; self.slot_count];
                for b in lb..ub {
                    for c in lc..uc {
                        for i in 0..yh {
                            for j in 0..yw {
                                let mask_index = 
                                    ((b - lb) * self.input_channel_block * self.output_channel_block + (c - lc) * self.input_channel_block + self.input_channel_block - 1) * interval + (self.image_height_block - yh + i) * self.image_width_block + (self.image_width_block - yw + j);
                                let output_index = b * self.output_channels * oyh * oyw + c * oyh * oyw + (si * yh + i) * oyw + (sj * yw + j);
                                if si * yh + i < oyh && sj * yw + j < oyw {
                                    mask[mask_index] = outputs[output_index];
                                }
                            } 
                        }
                    }
                }
                let pt = encoder.encode_polynomial_new(&mask);
                group.push(pt);
                lc += self.output_channel_block;
            }
            ret.push(group);
        }
        Plain2d::new(ret)
    }

    /// Encodes output. Useful for re-sharing conv2d output. 
    /// Call with a random tensor `s`, and add it to the conv2d result as `y0 = conv2d_result + s` [Cipher2d::add_plain_inplace].
    /// The other share is `y1 = -s`. Then 'y0' and 'y1' form a valid re-sharing of the conv2d result.
    pub fn encode_outputs_ckks(&self, encoder: &CKKSEncoder, outputs: &[f64], parms_id: Option<ParmsID>, scale: f64) -> Plain2d {
        let interval = self.image_height_block * self.image_width_block;
        let yh = self.image_height_block - self.kernel_height + 1;
        let yw = self.image_width_block - self.kernel_width + 1;
        let oyh = self.image_height - self.kernel_height + 1;
        let oyw = self.image_width - self.kernel_width + 1;
        assert_eq!(outputs.len(), self.batch_size * self.output_channels * oyh * oyw);
        let kh = self.kernel_height - 1;
        let kw = self.kernel_width - 1;
        let sh = ceil_div(self.image_height - kh, self.image_height_block - kh);
        let sw = ceil_div(self.image_width - kw, self.image_width_block - kw);
        let total_batch_size = ceil_div(self.batch_size, self.batch_block) * sh * sw;
        let mut ret = Vec::with_capacity(total_batch_size);
        for eb in 0..total_batch_size {
            let ob = eb / (sh * sw);
            let si = (eb % (sh * sw)) / sw;
            let sj = eb % sw;
            let lb = ob * self.batch_block;
            let ub = self.batch_size.min(lb + self.batch_block);
            let mut group = Vec::with_capacity(ceil_div(self.output_channels, self.output_channel_block));
            let mut lc = 0; while lc < self.output_channels {
                let uc = self.output_channels.min(lc + self.output_channel_block);
                let mut mask = vec![0.0; self.slot_count];
                for b in lb..ub {
                    for c in lc..uc {
                        for i in 0..yh {
                            for j in 0..yw {
                                let mask_index = 
                                    ((b - lb) * self.input_channel_block * self.output_channel_block + (c - lc) * self.input_channel_block + self.input_channel_block - 1) * interval + (self.image_height_block - yh + i) * self.image_width_block + (self.image_width_block - yw + j);
                                let output_index = b * self.output_channels * oyh * oyw + c * oyh * oyw + (si * yh + i) * oyw + (sj * yw + j);
                                if si * yh + i < oyh && sj * yw + j < oyw {
                                    mask[mask_index] = outputs[output_index];
                                }
                            } 
                        }
                    }
                }
                let pt = encoder.encode_f64_polynomial_new(&mask, parms_id, scale);
                group.push(pt);
                lc += self.output_channel_block;
            }
            ret.push(group);
        }
        Plain2d::new(ret)
    }

    /// Returns the indices of the output terms in the encoded input plaintext/ciphertext.
    /// Useful with [Cipher2d::serialize_terms].
    pub fn output_terms(&self) -> Vec<usize> {
        let mut required = vec![];
        let interval = self.image_height_block * self.image_width_block;
        let yh = self.image_height_block - self.kernel_height + 1;
        let yw = self.image_width_block - self.kernel_width + 1;
        for b in 0..self.batch_block {
            for c in 0..self.output_channel_block {
                for i in 0..yh {
                    for j in 0..yw {
                        let mask_index = 
                            (b * self.input_channel_block * self.output_channel_block + c * self.input_channel_block + self.input_channel_block - 1) * interval + (self.image_height_block - yh + i) * self.image_width_block + (self.image_width_block - yw + j);
                        required.push(mask_index);
                    } 
                }
            }
        }
        required
    }
    
    /// Decrypt the outputs. Wrapper of [Decryptor::decrypt_new].
    pub fn decrypt_outputs_bfv(&self, encoder: &BatchEncoder, decryptor: &Decryptor, outputs: &Cipher2d) -> Vec<u64> {
        let interval = self.image_height_block * self.image_width_block;
        let yh = self.image_height_block - self.kernel_height + 1;
        let yw = self.image_width_block - self.kernel_width + 1;
        let oyh = self.image_height - self.kernel_height + 1;
        let oyw = self.image_width - self.kernel_width + 1;
        let kh = self.kernel_height - 1;
        let kw = self.kernel_width - 1;
        let sh = ceil_div(self.image_height - kh, self.image_height_block - kh);
        let sw = ceil_div(self.image_width - kw, self.image_width_block - kw);
        let total_batch_size = ceil_div(self.batch_size, self.batch_block) * sh * sw;
        let mut ret = vec![0; self.batch_size * self.output_channels * oyh * oyw];
        for eb in 0..total_batch_size {
            let ob = eb / (sh * sw);
            let si = (eb % (sh * sw)) / sw;
            let sj = eb % sw;
            let lb = ob * self.batch_block;
            let ub = self.batch_size.min(lb + self.batch_block);
            let mut lc = 0; while lc < self.output_channels {
                let uc = self.output_channels.min(lc + self.output_channel_block);
                let pt = decryptor.decrypt_new(&outputs.data[eb][lc / self.output_channel_block]);
                let buffer = encoder.decode_polynomial_new(&pt);
                for b in lb..ub {
                    for c in lc..uc {
                        for i in 0..yh {
                            for j in 0..yw {
                                let mask_index = 
                                    ((b - lb) * self.input_channel_block * self.output_channel_block + (c - lc) * self.input_channel_block + self.input_channel_block - 1) * interval + (self.image_height_block - yh + i) * self.image_width_block + (self.image_width_block - yw + j);
                                let output_index = b * self.output_channels * oyh * oyw + c * oyh * oyw + (si * yh + i) * oyw + (sj * yw + j);
                                if si * yh + i < oyh && sj * yw + j < oyw {
                                    ret[output_index] = buffer[mask_index];
                                }
                            } 
                        }
                    }
                }
                lc += self.output_channel_block;
            }
        }
        ret
    }
    
    /// Decrypt the outputs. Wrapper of [Decryptor::decrypt_new].
    pub fn decrypt_outputs_ckks(&self, encoder: &CKKSEncoder, decryptor: &Decryptor, outputs: &Cipher2d) -> Vec<f64> {
        let interval = self.image_height_block * self.image_width_block;
        let yh = self.image_height_block - self.kernel_height + 1;
        let yw = self.image_width_block - self.kernel_width + 1;
        let oyh = self.image_height - self.kernel_height + 1;
        let oyw = self.image_width - self.kernel_width + 1;
        let kh = self.kernel_height - 1;
        let kw = self.kernel_width - 1;
        let sh = ceil_div(self.image_height - kh, self.image_height_block - kh);
        let sw = ceil_div(self.image_width - kw, self.image_width_block - kw);
        let total_batch_size = ceil_div(self.batch_size, self.batch_block) * sh * sw;
        let mut ret = vec![0.0; self.batch_size * self.output_channels * oyh * oyw];
        for eb in 0..total_batch_size {
            let ob = eb / (sh * sw);
            let si = (eb % (sh * sw)) / sw;
            let sj = eb % sw;
            let lb = ob * self.batch_block;
            let ub = self.batch_size.min(lb + self.batch_block);
            let mut lc = 0; while lc < self.output_channels {
                let uc = self.output_channels.min(lc + self.output_channel_block);
                let pt = decryptor.decrypt_new(&outputs.data[eb][lc / self.output_channel_block]);
                let buffer = encoder.decode_polynomial_new(&pt);
                for b in lb..ub {
                    for c in lc..uc {
                        for i in 0..yh {
                            for j in 0..yw {
                                let mask_index = 
                                    ((b - lb) * self.input_channel_block * self.output_channel_block + (c - lc) * self.input_channel_block + self.input_channel_block - 1) * interval + (self.image_height_block - yh + i) * self.image_width_block + (self.image_width_block - yw + j);
                                let output_index = b * self.output_channels * oyh * oyw + c * oyh * oyw + (si * yh + i) * oyw + (sj * yw + j);
                                if si * yh + i < oyh && sj * yw + j < oyw {
                                    ret[output_index] = buffer[mask_index];
                                }
                            } 
                        }
                    }
                }
                lc += self.output_channel_block;
            }
        }
        ret
    }

    /// Conv2d `[y]=Conv2d([a], W)`.
    pub fn conv2d(&self, evaluator: &Evaluator, a: &Cipher2d, w: &Plain2d) -> Cipher2d {
        let total_batch_size = self.get_total_batch_size();
        let mut ret = Vec::with_capacity(total_batch_size);
        for b in 0..total_batch_size {
            let group_len = ceil_div(self.output_channels, self.output_channel_block);
            let mut group = Vec::with_capacity(group_len);
            for oc in 0..group_len {
                let mut cipher = Ciphertext::new();
                for i in 0..a.data[b].len() {
                    let prod = evaluator.multiply_plain_new(&a.data[b][i], &w.data[oc][i]);
                    if i == 0 {
                        cipher = prod;
                    } else {
                        evaluator.add_inplace(&mut cipher, &prod);
                    }
                }
                group.push(cipher);
            }
            ret.push(group);
        }
        Cipher2d::new(ret)
    }

    /// Conv2d `[y]=Conv2d(a, [W])`.
    pub fn conv2d_reverse(&self, evaluator: &Evaluator, a: &Plain2d, w: &Cipher2d) -> Cipher2d {
        let total_batch_size = self.get_total_batch_size();
        let mut ret = Vec::with_capacity(total_batch_size);
        for b in 0..total_batch_size {
            let group_len = ceil_div(self.output_channels, self.output_channel_block);
            let mut group = Vec::with_capacity(group_len);
            for oc in 0..group_len {
                let mut cipher = Ciphertext::new();
                for i in 0..a.data[b].len() {
                    let prod = evaluator.multiply_plain_new(&w.data[oc][i], &a.data[b][i]);
                    if i == 0 {
                        cipher = prod;
                    } else {
                        evaluator.add_inplace(&mut cipher, &prod);
                    }
                }
                group.push(cipher);
            }
            ret.push(group);
        }
        Cipher2d::new(ret)
    }

}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{EncryptionParameters, BatchEncoder, Encryptor, Decryptor, KeyGenerator, Evaluator, CoeffModulus, HeContext, ExpandSeed, SerializableWithHeContext};
    use super::super::matmul::cheetah::tests::{random_f64_array, random_u64_array};

    fn test_bfv_conv2d(
        poly_degree: usize, plain_modulus: u64, q_bits: Vec<usize>, 
        batch_size: usize, input_channels: usize, output_channels: usize,
        kernel_height: usize, kernel_width: usize,
        image_height: usize, image_width: usize,
    ) {
        let output_height = image_height - kernel_height + 1;
        let output_width = image_width - kernel_width + 1;
        // setup
        let params = EncryptionParameters::new(crate::SchemeType::BFV)
            .set_poly_modulus_degree(poly_degree)
            .set_plain_modulus_u64(plain_modulus)
            .set_coeff_modulus(&CoeffModulus::create(poly_degree, q_bits));
        let context = HeContext::new(params.clone(), true, crate::SecurityLevel::Tc128);
        let encoder = BatchEncoder::new(context.clone());
        let keygen = KeyGenerator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false)).set_secret_key(keygen.secret_key().clone());
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let evaluator = Evaluator::new(context.clone());
        // generate data
        let plain_modulus = params.plain_modulus();
        let inputs = random_u64_array(batch_size * input_channels * image_height * image_width, plain_modulus);
        let weights = random_u64_array(output_channels * input_channels * kernel_height * kernel_width, plain_modulus);
        let output_bias = random_u64_array(batch_size * output_channels * output_height * output_width, plain_modulus);
        // calc
        let helper = Conv2dHelper::new(
            batch_size, input_channels, output_channels,
            image_height, image_width, kernel_height, kernel_width,
            params.poly_modulus_degree(), Conv2dHelperObjective::CipherPlain);
        let inputs_encoded = helper.encode_inputs_bfv(&encoder, &inputs);
        let weights_encoded = helper.encode_weights_bfv(&encoder, &weights);
        let inputs_encrypted = inputs_encoded.encrypt_symmetric(&encryptor).expand_seed(&context);
        let mut inputs_serialized = vec![]; inputs_encrypted.serialize(&context, &mut inputs_serialized).unwrap();
        assert_eq!(inputs_serialized.len(), inputs_encrypted.serialized_size(&context));
        let inputs_encrypted = Cipher2d::deserialize(&context, &mut inputs_serialized.as_slice()).unwrap();
        let mut outputs_encrypted = helper.conv2d(&evaluator, &inputs_encrypted, &weights_encoded);  
        let output_bias_encoded = helper.encode_outputs_bfv(&encoder, &output_bias);
        outputs_encrypted.add_plain_inplace(&evaluator, &output_bias_encoded);
        let outputs_terms = helper.output_terms();
        let mut outputs_serialized = vec![];
        outputs_encrypted.serialize_terms(&context, &outputs_terms, &mut outputs_serialized).unwrap();
        assert_eq!(outputs_serialized.len(), outputs_encrypted.serialized_terms_size(&context, outputs_terms.len()));
        outputs_encrypted = Cipher2d::deserialize_terms(&context, &outputs_terms, &mut outputs_serialized.as_slice()).unwrap();
        let outputs = helper.decrypt_outputs_bfv(&encoder, &decryptor, &outputs_encrypted);
        // plain calc
        let mut outputs_plain = vec![0; batch_size * output_channels * output_height * output_width];
        for b in 0..batch_size {
            for oc in 0..output_channels {
                for i in 0..output_height {
                    for j in 0..output_width {
                        let output_index = b * output_channels * output_height * output_width + oc * output_height * output_width + i * output_width + j;
                        let mut sum = 0;
                        for ic in 0..input_channels {
                            for ki in 0..kernel_height {
                                for kj in 0..kernel_width {
                                    let input_index = b * input_channels * image_height * image_width + ic * image_height * image_width + (i + ki) * image_width + (j + kj);
                                    let weight_index = oc * input_channels * kernel_height * kernel_width + ic * kernel_height * kernel_width + ki * kernel_width + kj;
                                    sum += plain_modulus.reduce_u128(inputs[input_index] as u128 * weights[weight_index] as u128);
                                    sum = plain_modulus.reduce(sum);
                                }
                            }
                        }
                        outputs_plain[output_index] = plain_modulus.reduce(output_bias[output_index] + sum);
                    }
                }
            }
        }
        // check correct
        assert_eq!(outputs_plain, outputs);
    }

    
    fn test_ckks_conv2d(
        poly_degree: usize, scale: f64, q_bits: Vec<usize>,
        batch_size: usize, input_channels: usize, output_channels: usize,
        kernel_height: usize, kernel_width: usize,
        image_height: usize, image_width: usize,
    ) {
        let output_height = image_height - kernel_height + 1;
        let output_width = image_width - kernel_width + 1;
        // setup
        let params = EncryptionParameters::new(crate::SchemeType::CKKS)
            .set_poly_modulus_degree(poly_degree)
            .set_coeff_modulus(&CoeffModulus::create(poly_degree, q_bits));
        let context = HeContext::new(params.clone(), true, crate::SecurityLevel::Tc128);
        let encoder = CKKSEncoder::new(context.clone());
        let keygen = KeyGenerator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false)).set_secret_key(keygen.secret_key().clone());
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let evaluator = Evaluator::new(context.clone());
        // generate data
        let bound = 10.0;
        let inputs = random_f64_array(batch_size * input_channels * image_height * image_width, bound);
        let weights = random_f64_array(output_channels * input_channels * kernel_height * kernel_width, bound);
        let output_bias = random_f64_array(batch_size * output_channels * output_height * output_width, bound);
        // calc
        let helper = Conv2dHelper::new(
            batch_size, input_channels, output_channels,
            image_height, image_width, kernel_height, kernel_width,
            params.poly_modulus_degree(), Conv2dHelperObjective::CipherPlain);
        let inputs_encoded = helper.encode_inputs_ckks(&encoder, &inputs, None, scale);
        let weights_encoded = helper.encode_weights_ckks(&encoder, &weights, None, scale);
        let inputs_encrypted = inputs_encoded.encrypt_symmetric(&encryptor).expand_seed(&context);
        let mut inputs_serialized = vec![]; inputs_encrypted.serialize(&context, &mut inputs_serialized).unwrap();
        assert_eq!(inputs_serialized.len(), inputs_encrypted.serialized_size(&context));
        let inputs_encrypted = Cipher2d::deserialize(&context, &mut inputs_serialized.as_slice()).unwrap();
        let mut outputs_encrypted = helper.conv2d(&evaluator, &inputs_encrypted, &weights_encoded);  
        let output_bias_encoded = helper.encode_outputs_ckks(&encoder, &output_bias, None, scale * scale / params.coeff_modulus()[params.coeff_modulus().len() - 2].value() as f64);
        outputs_encrypted.rescale_to_next_inplace(&evaluator);
        outputs_encrypted.add_plain_inplace(&evaluator, &output_bias_encoded);
        let outputs_terms = helper.output_terms();
        let mut outputs_serialized = vec![];
        outputs_encrypted.serialize_terms(&context, &outputs_terms, &mut outputs_serialized).unwrap();
        assert_eq!(outputs_serialized.len(), outputs_encrypted.serialized_terms_size(&context, outputs_terms.len()));
        outputs_encrypted = Cipher2d::deserialize_terms(&context, &outputs_terms, &mut outputs_serialized.as_slice()).unwrap();
        let outputs = helper.decrypt_outputs_ckks(&encoder, &decryptor, &outputs_encrypted);
        // plain calc
        let mut outputs_plain = vec![0.0; batch_size * output_channels * output_height * output_width];
        for b in 0..batch_size {
            for oc in 0..output_channels {
                for i in 0..output_height {
                    for j in 0..output_width {
                        let output_index = b * output_channels * output_height * output_width + oc * output_height * output_width + i * output_width + j;
                        let mut sum = 0.0;
                        for ic in 0..input_channels {
                            for ki in 0..kernel_height {
                                for kj in 0..kernel_width {
                                    let input_index = b * input_channels * image_height * image_width + ic * image_height * image_width + (i + ki) * image_width + (j + kj);
                                    let weight_index = oc * input_channels * kernel_height * kernel_width + ic * kernel_height * kernel_width + ki * kernel_width + kj;
                                    sum += inputs[input_index] * weights[weight_index];
                                }
                            }
                        }
                        outputs_plain[output_index] = output_bias[output_index] + sum;
                    }
                }
            }
        }
        // check correct
        for i in 0..outputs_plain.len() {
            assert!((outputs_plain[i] - outputs[i]).abs() < 1e-1);
        }
    }

    #[test]
    fn bfv_conv2d() {
        test_bfv_conv2d(4096, 1<<20, vec![60, 49], 
            1, 3, 5, 
            3, 5, 
            16, 17,
        );  
        test_bfv_conv2d(4096, 1<<20, vec![60, 49], 
            4, 3, 16, 
            5, 5, 
            32, 32,
        );  
    }
    
    #[test]
    fn ckks_conv2d() {
        test_ckks_conv2d(8192, 2.0f64.powf(40.0), vec![60, 40, 40, 60], 
            1, 3, 5, 
            3, 5, 
            16, 17,
        );  
        test_ckks_conv2d(8192, 2.0f64.powf(40.0), vec![60, 40, 40, 60], 
            4, 3, 16, 
            5, 5, 
            32, 32,
        );  
    }
    
}