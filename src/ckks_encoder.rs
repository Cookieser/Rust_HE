use std::sync::Arc;

use crate::{
    util::{dwthandler::{Arithmetic, DWTHandler}, GALOIS_GENERATOR},
    util,
    HeContext, 
    ParmsID, 
    Plaintext, 
    PARMS_ID_ZERO,
    polymod, ValCheck
};
use num_complex::Complex;

#[derive(Clone, Copy, Default)]
struct ComplexArith {}
type FFTHandler = DWTHandler<ComplexArith>;

impl Arithmetic for ComplexArith {
    type Value = Complex<f64>;
    type Root = Complex<f64>;
    type Scalar = f64;

    #[inline]
    fn add(&self, a: &Self::Value, b: &Self::Value) -> Self::Value {
        a + b
    }

    #[inline]
    fn sub(&self, a: &Self::Value, b: &Self::Value) -> Self::Value {
        a - b
    }

    #[inline]
    fn mul_root(&self, a: &Self::Value, r: &Self::Root) -> Self::Value {
        a * r
    }

    #[inline]
    fn mul_scalar(&self, a: &Self::Value, s: &Self::Scalar) -> Self::Value {
        a * s
    }

    #[inline]
    fn guard(&self, a: &Self::Value) -> Self::Value {
        *a
    }
}

struct ComplexRoots {
    roots: Vec<Complex<f64>>,
    degree_of_roots: usize,
}


#[inline]
fn mirror(a: Complex<f64>) -> Complex<f64> {
    Complex::new(a.im, a.re)
}

impl ComplexRoots {

    pub fn new(degree_of_roots: usize) -> Self {
        // Generate 1/8 of all roots.
        // Alternatively, choose from precomputed high-precision roots in files.
        let roots = (0..=degree_of_roots / 8).map(|i| {
            Complex::from_polar(1.0, 2.0 * std::f64::consts::PI * (i as f64) / (degree_of_roots as f64))
        }).collect();
        Self {
            roots,
            degree_of_roots,
        }
    }

    pub fn get_root(&self, mut index: usize) -> Complex<f64> {
        index &= self.degree_of_roots - 1;

        // This express the 8-fold symmetry of all n-th roots.
        if index <= self.degree_of_roots / 8 {
            self.roots[index]
        } else if index <= self.degree_of_roots / 4 {
            mirror(self.roots[self.degree_of_roots / 4 - index])
        } else if index < self.degree_of_roots / 2 {
            -self.get_root(self.degree_of_roots / 2 - index).conj()
        } else if index <= 3 * self.degree_of_roots / 4 {
            -self.get_root(index - self.degree_of_roots / 2)
        } else {
            self.get_root(self.degree_of_roots - index).conj()
        }

    }

}

/// Provides SIMD encoding and decoding functionality for the [CKKS](crate::SchemeType::CKKS) scheme.
/// 
/// Provides functionality for encoding vectors of complex or real numbers into
/// plaintext polynomials to be encrypted and computed on using the CKKS scheme.
/// If the polynomial modulus degree is N, then CKKSEncoder converts vectors of
/// N/2 complex numbers into plaintext elements. Homomorphic operations performed
/// on such encrypted vectors are applied coefficient (slot-)wise, enabling
/// powerful SIMD functionality for computations that are vectorizable. This
/// functionality is often called "batching" in the homomorphic encryption
/// literature.
/// 
/// ## Mathematical Background
/// Mathematically speaking, if the polynomial modulus is X^N+1, N is a power of
/// two, the CKKSEncoder implements an approximation of the canonical embedding
/// of the ring of integers Z\[X\]/(X^N+1) into C^(N/2), where C denotes the complex
/// numbers. The Galois group of the extension is (Z/2NZ)* ~= Z/2Z x Z/(N/2)
/// whose action on the primitive roots of unity modulo coeff_modulus is easy to
/// describe. Since the batching slots correspond 1-to-1 to the primitive roots
/// of unity, applying Galois automorphisms on the plaintext acts by permuting
/// the slots. By applying generators of the two cyclic subgroups of the Galois
/// group, we can effectively enable cyclic rotations and complex conjugations
/// of the encrypted complex vectors.
pub struct CKKSEncoder {
    context: Arc<HeContext>,
    slots: usize,
    // complex_roots: Option<ComplexRoots>,
    root_powers: Vec<Complex<f64>>,
    inv_root_powers: Vec<Complex<f64>>,
    matrix_reps_index_map: Vec<usize>,
    // complex_arith: ComplexArith,
    fft_handler: FFTHandler,
}

impl CKKSEncoder {

    /// Creates a CKKSEncoder initialized with the specified [HeContext].
    pub fn new(context: Arc<HeContext>) -> Self {
        if !context.parameters_set() {
            panic!("[Invalid argument] Encryption parameters are not set correctly.");
        }
        let context_data = context.first_context_data().unwrap();
        if !context_data.is_ckks() {
            panic!("[Invalid argument] Unsupported scheme.");
        }
        let coeff_count = context_data.parms().poly_modulus_degree();
        let slots = coeff_count / 2;
        let logn = util::get_power_of_two(coeff_count as u64) as usize;

        let mut matrix_reps_index_map = vec![0; coeff_count];

        // Copy from the matrix to the value vectors
        let gen = GALOIS_GENERATOR;
        let mut pos = 1;
        let m = coeff_count * 2;
        for i in 0..slots {
            let index1 = (pos - 1) >> 1;
            let index2 = (m - pos - 1) >> 1;
            matrix_reps_index_map[i] = util::reverse_bits_u64(index1 as u64, logn) as usize;
            matrix_reps_index_map[i | slots] = util::reverse_bits_u64(index2 as u64, logn) as usize;
            pos = (pos * gen) & (m - 1);
        }

        // We need 1~(n-1)-th powers of the primitive 2n-th root, m = 2n
        let mut root_powers = vec![Complex::default(); coeff_count];
        let mut inv_root_powers = vec![Complex::default(); coeff_count];

        // Powers of the primitive 2n-th root have 4-fold symmetry
        let complex_roots;
        if m >= 8 {
            complex_roots = Some(ComplexRoots::new(m));
            for i in 1..coeff_count {
                root_powers[i] = complex_roots.as_ref().unwrap().get_root(util::reverse_bits_u64(i as u64, logn) as usize);
                inv_root_powers[i] = complex_roots.as_ref().unwrap().get_root(util::reverse_bits_u64((i - 1) as u64, logn) as usize + 1).conj();
            }
        } else if m == 4 {
            root_powers[1] = Complex::new(0.0, 1.0);
            inv_root_powers[1] = Complex::new(0.0, -1.0);
        }

        let complex_arith = ComplexArith::default();
        let fft_handler = FFTHandler::new(&complex_arith);


        Self {
            context,
            slots,
            root_powers,
            inv_root_powers,
            matrix_reps_index_map,
            fft_handler,
        }
    }
    
    /// Return the number of slots (coefficients) that are available for batching.
    pub fn slot_count(&self) -> usize {
        self.slots
    }

    /// Encodes a vector of complex numbers into a plaintext polynomial.
    /// The length of the vector must be at most [Self::slot_count()].
    fn encode_internal_c64_array(&self, values: &[Complex<f64>], parms_id: &ParmsID, scale: f64, destination: &mut Plaintext) {
        // Verify parameters.
        let context_data = self.context.get_context_data(parms_id);
        if context_data.is_none() {
            panic!("[Invalid argument] parms_id is not valid for encryption parameters.");
        }
        let context_data = context_data.unwrap();
        if !context_data.is_ckks() {
            panic!("[Invalid argument] Unsupported scheme.");
        }
        if values.len() > self.slots {
            panic!("[Invalid argument] Too many values to encode.");
        }

        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();

        // Check that scale is positive and not too large
        if scale <= 0.0 || (scale.log2() + 1.0 >= context_data.total_coeff_modulus_bit_count() as f64) {
            panic!("[Invalid argument] scale out of bounds.");
        }

        let ntt_tables = context_data.small_ntt_tables();

        let n = self.slots * 2;
        let mut conj_values = vec![Complex::default(); n];
        for i in 0..values.len() {
            conj_values[self.matrix_reps_index_map[i]] = values[i];
            conj_values[self.matrix_reps_index_map[i + self.slots]] = values[i].conj();
        }
        
        let fix = scale / (n as f64);
        self.fft_handler.transform_from_rev(&mut conj_values, 
            util::get_power_of_two(n as u64) as usize, &self.inv_root_powers, Some(&fix));
        
        let max_coeff = conj_values.iter()
            .map(|x| x.re.abs())
            .reduce(f64::max)
            .unwrap();
        // Verify that the values are not too large to fit in coeff_modulus
        // Note that we have an extra + 1 for the sign bit
        // Don't compute logarithmis of numbers less than 1
        let max_coeff_bit_count = max_coeff.max(1.0).log2().ceil() as usize;
        if max_coeff_bit_count >= context_data.total_coeff_modulus_bit_count() {
            panic!("[Invalid argument] Values are too large to encode.");
        }

        let two_pow_64 = 2.0_f64.powi(64);

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.set_parms_id(PARMS_ID_ZERO);
        destination.resize(coeff_count * coeff_modulus_size);
        
        // Use faster decomposition methods when possible
        if max_coeff_bit_count <= 64 {
            let destination_data = destination.data_mut();
            for i in 0..n {
                let coeffd = conj_values[i].re.round();
                let is_negative = coeffd < 0.0;
                let coeffu = coeffd.abs() as u64;
                if is_negative {
                    for j in 0..coeff_modulus_size {
                        destination_data[i + j * coeff_count] = util::negate_u64_mod(
                            coeff_modulus[j].reduce(coeffu), &coeff_modulus[j]);
                    }
                } else {
                    for j in 0..coeff_modulus_size {
                        destination_data[i + j * coeff_count] = coeff_modulus[j].reduce(coeffu);
                    }
                }
            }
        } else if max_coeff_bit_count <= 128 {
            let destination_data = destination.data_mut();
            for i in 0..n {
                let mut coeffd = conj_values[i].re.round();
                let is_negative = coeffd < 0.0;
                coeffd = coeffd.abs();
                let coeffu = [
                    (coeffd % two_pow_64) as u64,
                    (coeffd / two_pow_64) as u64
                ];
                if is_negative {
                    for j in 0..coeff_modulus_size {
                        destination_data[i + j * coeff_count] = util::negate_u64_mod(
                            util::barrett_reduce_u128(&coeffu, &coeff_modulus[j]), &coeff_modulus[j]);
                    }
                } else {
                    for j in 0..coeff_modulus_size {
                        destination_data[i + j * coeff_count] = 
                            util::barrett_reduce_u128(&coeffu, &coeff_modulus[j]);
                    }
                }
            }
        } else {
            let destination_data = destination.data_mut();
            // Slow case
            for i in 0..n {
                let mut coeffd = conj_values[i].re.round();
                let is_negative = coeffd < 0.0;
                coeffd = coeffd.abs();
                let mut coeffu = vec![0; coeff_modulus_size];
                let mut coeffu_index = 0;
                while coeffd >= 1.0 {
                    coeffu[coeffu_index] = (coeffd % two_pow_64) as u64;
                    coeffd /= two_pow_64;
                    coeffu_index += 1;
                }
                // Next decompose this coeff
                context_data.rns_tool().base_q().decompose(&mut coeffu);
                if is_negative {
                    for j in 0..coeff_modulus_size {
                        destination_data[i + j * coeff_count] = util::negate_u64_mod(
                            coeffu[j], &coeff_modulus[j]);
                    }
                } else {
                    for j in 0..coeff_modulus_size {
                        destination_data[i + j * coeff_count] = coeffu[j];
                    }
                }
            }
        }

        // Transform to NTT domain
        assert_eq!(ntt_tables.len(), coeff_modulus_size);
        polymod::ntt_p(destination.data_mut(), coeff_count, ntt_tables);

        destination.set_parms_id(*parms_id);
        destination.set_scale(scale);

    }

    fn encode_internal_f64_polynomial(&self, values: &[f64], parms_id: &ParmsID, scale: f64, destination: &mut Plaintext) {
        // Verify parameters.
        let context_data = self.context.get_context_data(parms_id);
        if context_data.is_none() {
            panic!("[Invalid argument] parms_id is not valid for encryption parameters.");
        }
        let context_data = context_data.unwrap();
        if !context_data.is_ckks() {
            panic!("[Invalid argument] Unsupported scheme.");
        }
        if values.len() > self.slots * 2 {
            panic!("[Invalid argument] Too many values to encode.");
        }

        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();
        let ntt_tables = context_data.small_ntt_tables();

        // Check that scale is positive and not too large
        if scale <= 0.0 || (scale.log2() + 1.0 >= context_data.total_coeff_modulus_bit_count() as f64) {
            panic!("[Invalid argument] scale out of bounds.");
        }

        let two_pow_64 = 2.0_f64.powi(64);

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.set_parms_id(PARMS_ID_ZERO);
        destination.resize(coeff_count * coeff_modulus_size);
        destination.data_mut().fill(0);
        
        let max_coeff = values.iter()
            .map(|x| x.abs())
            .reduce(f64::max)
            .unwrap();
        // Verify that the values are not too large to fit in coeff_modulus
        // Note that we have an extra + 1 for the sign bit
        // Don't compute logarithmis of numbers less than 1
        let max_coeff_bit_count = max_coeff.max(1.0).log2().ceil() as usize;
        if max_coeff_bit_count >= context_data.total_coeff_modulus_bit_count() {
            panic!("[Invalid argument] Values are too large to encode.");
        }

        let n = values.len();
        // Use faster decomposition methods when possible
        if max_coeff_bit_count <= 64 {
            let destination_data = destination.data_mut();
            for i in 0..n {
                let coeffd = (values[i] * scale).round();
                let is_negative = coeffd < 0.0;
                let coeffu = coeffd.abs() as u64;
                if is_negative {
                    for j in 0..coeff_modulus_size {
                        destination_data[i + j * coeff_count] = util::negate_u64_mod(
                            coeff_modulus[j].reduce(coeffu), &coeff_modulus[j]);
                    }
                } else {
                    for j in 0..coeff_modulus_size {
                        destination_data[i + j * coeff_count] = coeff_modulus[j].reduce(coeffu);
                    }
                }
            }
        } else if max_coeff_bit_count <= 128 {
            let destination_data = destination.data_mut();
            for i in 0..n {
                let mut coeffd = (values[i] * scale).round();
                let is_negative = coeffd < 0.0;
                coeffd = coeffd.abs();
                let coeffu = [
                    (coeffd % two_pow_64) as u64,
                    (coeffd / two_pow_64) as u64
                ];
                if is_negative {
                    for j in 0..coeff_modulus_size {
                        destination_data[i + j * coeff_count] = util::negate_u64_mod(
                            util::barrett_reduce_u128(&coeffu, &coeff_modulus[j]), &coeff_modulus[j]);
                    }
                } else {
                    for j in 0..coeff_modulus_size {
                        destination_data[i + j * coeff_count] = 
                            util::barrett_reduce_u128(&coeffu, &coeff_modulus[j]);
                    }
                }
            }
        } else {
            let destination_data = destination.data_mut();
            // Slow case
            for i in 0..n {
                let mut coeffd = (values[i] * scale).round();
                let is_negative = coeffd < 0.0;
                coeffd = coeffd.abs();
                let mut coeffu = vec![0; coeff_modulus_size];
                let mut coeffu_index = 0;
                while coeffd >= 1.0 {
                    coeffu[coeffu_index] = (coeffd % two_pow_64) as u64;
                    coeffd /= two_pow_64;
                    coeffu_index += 1;
                }
                // Next decompose this coeff
                context_data.rns_tool().base_q().decompose(&mut coeffu);
                if is_negative {
                    for j in 0..coeff_modulus_size {
                        destination_data[i + j * coeff_count] = util::negate_u64_mod(
                            coeffu[j], &coeff_modulus[j]);
                    }
                } else {
                    for j in 0..coeff_modulus_size {
                        destination_data[i + j * coeff_count] = coeffu[j];
                    }
                }
            }
        }

        // Transform to NTT domain
        assert_eq!(ntt_tables.len(), coeff_modulus_size);
        polymod::ntt_p(destination.data_mut(), coeff_count, ntt_tables);

        destination.set_parms_id(*parms_id);
        destination.set_scale(scale);
    }

    /// Encodes a complex number into a plaintext polynomial.
    /// This is equivalent to encoding a vector filled with the complex number.
    fn encode_internal_f64_single(&self, mut value: f64, parms_id: &ParmsID, scale: f64, destination: &mut Plaintext) {
        // Verify parameters.
        let context_data = self.context.get_context_data(parms_id);
        if context_data.is_none() {
            panic!("[Invalid argument] parms_id is not valid for encryption parameters.");
        }
        let context_data = context_data.unwrap();
        if !context_data.is_ckks() {
            panic!("[Invalid argument] Unsupported scheme.");
        }

        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();

        // Check that scale is positive and not too large
        if scale <= 0.0 || (scale.log2() + 1.0 >= context_data.total_coeff_modulus_bit_count() as f64) {
            panic!("[Invalid argument] scale out of bounds.");
        }

        value *= scale;
        
        let coeff_bit_count = value.abs().log2() as usize + 2;
        if coeff_bit_count >= context_data.total_coeff_modulus_bit_count() {
            panic!("[Invalid argument] Value is too large to encode.");
        }

        let two_pow_64 = 2.0_f64.powi(64);

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.set_parms_id(PARMS_ID_ZERO);
        destination.resize(coeff_count * coeff_modulus_size);

        let coeffd = value.round();
        let is_negative = coeffd < 0.0;
        let coeffd = coeffd.abs();

        // Use faster decomposition methods when possible
        if coeff_bit_count <= 64 {
            let coeffu = coeffd as u64;
            if is_negative {
                for (j, destination_component) in destination.data_mut().chunks_mut(coeff_count).enumerate() {
                    destination_component.fill(util::negate_u64_mod(coeff_modulus[j].reduce(coeffu), &coeff_modulus[j]));
                }
            } else {
                for (j, destination_component) in destination.data_mut().chunks_mut(coeff_count).enumerate() {
                    destination_component.fill(coeff_modulus[j].reduce(coeffu));
                }
            }
        } else if coeff_bit_count <= 128 {
            let coeffu = [
                (coeffd % two_pow_64) as u64,
                (coeffd / two_pow_64) as u64
            ];
            if is_negative {
                for (j, destination_component) in destination.data_mut().chunks_mut(coeff_count).enumerate() {
                    destination_component.fill(util::negate_u64_mod(
                        util::barrett_reduce_u128(&coeffu, &coeff_modulus[j]), &coeff_modulus[j]));
                }
            } else {
                for (j, destination_component) in destination.data_mut().chunks_mut(coeff_count).enumerate() {
                    destination_component.fill(util::barrett_reduce_u128(&coeffu, &coeff_modulus[j]));
                }
            }
        } else {
            // Slow case
            let mut coeffu = vec![0; coeff_modulus_size];
            let mut coeffu_index = 0;
            let mut coeffd = coeffd;
            while coeffd >= 1.0 {
                coeffu[coeffu_index] = (coeffd % two_pow_64) as u64;
                coeffd /= two_pow_64;
                coeffu_index += 1;
            }
            // Next decompose this coeff
            context_data.rns_tool().base_q().decompose(&mut coeffu);
            if is_negative {
                for (j, destination_component) in destination.data_mut().chunks_mut(coeff_count).enumerate() {
                    destination_component.fill(util::negate_u64_mod(coeffu[j], &coeff_modulus[j]));
                }
            } else {
                for (j, destination_component) in destination.data_mut().chunks_mut(coeff_count).enumerate() {
                    destination_component.fill(coeffu[j]);
                }
            }
        }

        destination.set_parms_id(*parms_id);
        destination.set_scale(scale);
    }

    /// Encodes [i64] number into a plaintext polynomial.
    /// This is equivalent to encoding a vector filled with the [i64] number.
    /// Note that the scale of this encoding is 1.
    fn encode_internal_i64_single(&self, value: i64, parms_id: &ParmsID, destination: &mut Plaintext) {
        // Verify parameters.
        let context_data = self.context.get_context_data(parms_id);
        if context_data.is_none() {
            panic!("[Invalid argument] parms_id is not valid for encryption parameters.");
        }
        let context_data = context_data.unwrap();
        if !context_data.is_ckks() {
            panic!("[Invalid argument] Unsupported scheme.");
        }

        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();

        let coeff_bit_count = util::get_significant_bit_count(value.unsigned_abs()) + 2;
        if coeff_bit_count >= context_data.total_coeff_modulus_bit_count() {
            panic!("[Invalid argument] Value is too large to encode.");
        }

        // Resize destination to appropriate size
        // Need to first set parms_id to zero, otherwise resize
        // will throw an exception.
        destination.set_parms_id(PARMS_ID_ZERO);
        destination.resize(coeff_count * coeff_modulus_size);

        if value < 0 {
            for (j, destination_component) in destination.data_mut().chunks_mut(coeff_count).enumerate() {
                let tmp = coeff_modulus[j].value().wrapping_sub((-value) as u64);
                let tmp = coeff_modulus[j].reduce(tmp);
                destination_component.fill(tmp);
            }
        } else {
            for (j, destination_component) in destination.data_mut().chunks_mut(coeff_count).enumerate() {
                let tmp = coeff_modulus[j].reduce(value as u64);
                destination_component.fill(tmp);
            }
        }

        destination.set_parms_id(*parms_id);
        destination.set_scale(1.0);
    }

    fn decode_internal(&self, plain: &Plaintext, destination: &mut Vec<Complex<f64>>) {
        destination.resize(self.slots, Complex::new(0.0, 0.0));
        // Verify parameters
        if !plain.is_ntt_form() {
            panic!("[Invalid argument] Plaintext is not in NTT form.");
        }
        if !plain.is_valid_for(self.context.as_ref()) {
            panic!("[Invalid argument] Plaintext is not valid for encryption parameters.");
        }

        let context_data = self.context.get_context_data(plain.parms_id()).unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();
        let rns_poly_u64_count = coeff_count * coeff_modulus_size;
        
        let ntt_tables = context_data.small_ntt_tables();

        if plain.scale() <= 0.0 || plain.scale().log2() as usize >= context_data.total_coeff_modulus_bit_count() {
            panic!("[Invalid argument] Plaintext scale is invalid.");
        }

        let decryption_modulus = context_data.total_coeff_modulus();
        let upper_half_threshold = context_data.upper_half_threshold();
        let logn = util::get_power_of_two(coeff_count as u64);

        // Quick sanity check
        if logn < 0 || !(util::HE_POLY_MOD_DEGREE_MIN..=util::HE_POLY_MOD_DEGREE_MAX).contains(&coeff_count) {
            panic!("[Logic error] Invalid poly_modulus_degree.");
        }
        let logn = logn as usize;

        let inv_scale = 1.0 / plain.scale();

        // Create mutable copy of input
        let mut plain_copy = plain.data().clone();
        assert_eq!(plain_copy.len(), rns_poly_u64_count);

        // Transform each polynomial from NTT domain
        assert_eq!(ntt_tables.len(), coeff_modulus_size);
        polymod::intt_p(&mut plain_copy, coeff_count, ntt_tables);



        // CRT-compose the polynomial
        context_data.rns_tool().base_q().compose_array(&mut plain_copy);

        // Create floating-point representations of the multi-precision integer coefficients
        let two_pow_64 = 2.0_f64.powi(64);
        let mut res = vec![Complex::new(0.0, 0.0); coeff_count];
        for i in 0..coeff_count {
            if util::is_greater_than_or_equal_uint(&plain_copy[i*coeff_modulus_size..(i+1)*coeff_modulus_size], upper_half_threshold) {
                let mut scaled_two_pow_64 = inv_scale;
                for j in 0..coeff_modulus_size {
                    if plain_copy[i * coeff_modulus_size + j] > decryption_modulus[j] {
                        let diff = plain_copy[i * coeff_modulus_size + j] - decryption_modulus[j];
                        res[i] += if diff != 0 {(diff as f64) * scaled_two_pow_64} else {0.0};
                    } else {
                        let diff = decryption_modulus[j] - plain_copy[i * coeff_modulus_size + j];
                        res[i] -= if diff != 0 {(diff as f64) * scaled_two_pow_64} else {0.0};
                    }
                    scaled_two_pow_64 *= two_pow_64;
                }
            } else {
                let mut scaled_two_pow_64 = inv_scale;
                for j in 0..coeff_modulus_size {
                    let curr_coeff = plain_copy[i * coeff_modulus_size + j];
                    res[i] += if curr_coeff != 0 {(curr_coeff as f64) * scaled_two_pow_64} else {0.0};
                    scaled_two_pow_64 *= two_pow_64;
                }
            }
        }

        self.fft_handler.transform_to_rev(&mut res, logn, &self.root_powers, None);
        for i in 0..self.slots {
            destination[i] = res[self.matrix_reps_index_map[i]];
        }
    }

    fn decode_polynomial_internal(&self, plain: &Plaintext, destination: &mut Vec<f64>) {
        destination.resize(self.slots * 2, 0.0);
        // Verify parameters
        if !plain.is_ntt_form() {
            panic!("[Invalid argument] Plaintext is not in NTT form.");
        }
        if !plain.is_valid_for(self.context.as_ref()) {
            panic!("[Invalid argument] Plaintext is not valid for encryption parameters.");
        }

        let context_data = self.context.get_context_data(plain.parms_id()).unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();
        let rns_poly_u64_count = coeff_count * coeff_modulus_size;
        
        let ntt_tables = context_data.small_ntt_tables();

        if plain.scale() <= 0.0 || plain.scale().log2() as usize >= context_data.total_coeff_modulus_bit_count() {
            panic!("[Invalid argument] Plaintext scale is invalid.");
        }

        let decryption_modulus = context_data.total_coeff_modulus();
        let upper_half_threshold = context_data.upper_half_threshold();
        let logn = util::get_power_of_two(coeff_count as u64);

        // Quick sanity check
        if logn < 0 || !(util::HE_POLY_MOD_DEGREE_MIN..=util::HE_POLY_MOD_DEGREE_MAX).contains(&coeff_count) {
            panic!("[Logic error] Invalid poly_modulus_degree.");
        }

        let inv_scale = 1.0 / plain.scale();

        // Create mutable copy of input
        let mut plain_copy = plain.data().clone();
        assert_eq!(plain_copy.len(), rns_poly_u64_count);

        // Transform each polynomial from NTT domain
        assert_eq!(ntt_tables.len(), coeff_modulus_size);
        polymod::intt_p(&mut plain_copy, coeff_count, ntt_tables);

        // CRT-compose the polynomial
        context_data.rns_tool().base_q().compose_array(&mut plain_copy);

        // Create floating-point representations of the multi-precision integer coefficients
        let two_pow_64 = 2.0_f64.powi(64);
        let mut res = vec![Complex::new(0.0, 0.0); coeff_count];
        for i in 0..coeff_count {
            if util::is_greater_than_or_equal_uint(&plain_copy[i*coeff_modulus_size..(i+1)*coeff_modulus_size], upper_half_threshold) {
                let mut scaled_two_pow_64 = inv_scale;
                for j in 0..coeff_modulus_size {
                    if plain_copy[i * coeff_modulus_size + j] > decryption_modulus[j] {
                        let diff = plain_copy[i * coeff_modulus_size + j] - decryption_modulus[j];
                        res[i] += if diff != 0 {(diff as f64) * scaled_two_pow_64} else {0.0};
                    } else {
                        let diff = decryption_modulus[j] - plain_copy[i * coeff_modulus_size + j];
                        res[i] -= if diff != 0 {(diff as f64) * scaled_two_pow_64} else {0.0};
                    }
                    scaled_two_pow_64 *= two_pow_64;
                }
            } else {
                let mut scaled_two_pow_64 = inv_scale;
                for j in 0..coeff_modulus_size {
                    let curr_coeff = plain_copy[i * coeff_modulus_size + j];
                    res[i] += if curr_coeff != 0 {(curr_coeff as f64) * scaled_two_pow_64} else {0.0};
                    scaled_two_pow_64 *= two_pow_64;
                }
            }
        }

        for i in 0..self.slots * 2 {
            destination[i] = res[i].re;
        }
    }

    fn encode_internal_c64_single(&self, value: Complex<f64>, parms_id: &ParmsID, scale: f64, destination: &mut Plaintext) {
        let input = (0..self.slots).map(|_| value).collect::<Vec<_>>();
        self.encode_internal_c64_array(&input, parms_id, scale, destination);
    }

    /// Encodes a vector of double-precision floating-point real or complex numbers
    /// into a plaintext polynomial. Append zeros if vector size is less than N/2.
    /// The coefficients will be scaled up by the given scale as precision.
    /// If `parms_id` is not provided, encode using the [HeContext::first_parms_id()]
    /// 
    /// ```rust
    /// use heathcliff::create_ckks_decryptor_suite;
    /// use num_complex::Complex;
    /// let (params, context, encoder, _, _, _)
    ///     = create_ckks_decryptor_suite(8192, vec![60, 60, 60]);
    /// let message = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    /// let scale = (1u64<<40) as f64;
    /// let plain = encoder.encode_c64_array_new(&message, None, scale);
    /// let decoded = encoder.decode_new(&plain);
    /// for i in 0..2 {assert!((decoded[i] - message[i]).norm() < 0.01);}
    /// for i in 2..4096 {assert!(decoded[i].norm() < 0.01);}
    /// ```
    pub fn encode_c64_array(&self, values: &[Complex<f64>], parms_id: Option<ParmsID>, scale: f64, destination: &mut Plaintext) {
        let parms_id = parms_id.unwrap_or_else(|| *self.context.first_parms_id());
        self.encode_internal_c64_array(values, &parms_id, scale, destination)
    }

    /// See [Self::encode_c64_array].
    pub fn encode_c64_array_new(&self, values: &[Complex<f64>], parms_id: Option<ParmsID>, scale: f64) -> Plaintext {
        let parms_id = parms_id.unwrap_or_else(|| *self.context.first_parms_id());
        let mut destination = Plaintext::default();
        self.encode_internal_c64_array(values, &parms_id, scale, &mut destination);
        destination
    }

    /// Encodes a double-precision floating-point real number into a plaintext
    /// polynomial. The number repeats for N/2 times to fill all slots. 
    /// The coefficients will be scaled up by the given scale as precision.
    /// If `parms_id` is not provided, encode using the [HeContext::first_parms_id()]
    /// 
    /// ```rust
    /// use heathcliff::create_ckks_decryptor_suite;
    /// use num_complex::Complex;
    /// let (params, context, encoder, _, _, _)
    ///     = create_ckks_decryptor_suite(8192, vec![60, 60, 60]);
    /// let message = 42.0;
    /// let scale = (1u64<<40) as f64;
    /// let plain = encoder.encode_f64_single_new(message, None, scale);
    /// let decoded = encoder.decode_new(&plain);
    /// for i in 0..4096 {assert!((decoded[i] - message).norm() < 0.01);}
    /// ```
    pub fn encode_f64_single(&self, value: f64, parms_id: Option<ParmsID>, scale: f64, destination: &mut Plaintext) {
        let parms_id = parms_id.unwrap_or_else(|| *self.context.first_parms_id());
        self.encode_internal_f64_single(value, &parms_id, scale, destination)
    }

    /// See [Self::encode_f64_single].
    pub fn encode_f64_single_new(&self, value: f64, parms_id: Option<ParmsID>, scale: f64) -> Plaintext {
        let parms_id = parms_id.unwrap_or_else(|| *self.context.first_parms_id());
        let mut destination = Plaintext::default();
        self.encode_internal_f64_single(value, &parms_id, scale, &mut destination);
        destination
    }

    /// Encode a plaintext polynomial, given polynomial coefficients.
    pub fn encode_f64_polynomial(&self, value: &[f64], parms_id: Option<ParmsID>, scale: f64, destination: &mut Plaintext) {
        let parms_id = parms_id.unwrap_or_else(|| *self.context.first_parms_id());
        self.encode_internal_f64_polynomial(value, &parms_id, scale, destination)
    }

    /// See [Self::encode_f64_polynomial].
    pub fn encode_f64_polynomial_new(&self, value: &[f64], parms_id: Option<ParmsID>, scale: f64) -> Plaintext {
        let parms_id = parms_id.unwrap_or_else(|| *self.context.first_parms_id());
        let mut destination = Plaintext::default();
        self.encode_internal_f64_polynomial(value, &parms_id, scale, &mut destination);
        destination
    }

    /// Encodes a double-precision complex number into a plaintext polynomial.
    /// Append zeros to fill all slots. 
    /// The coefficients will be scaled up by the given scale as precision.
    /// If `parms_id` is not provided, encode using the [HeContext::first_parms_id()]
    /// 
    /// ```rust
    /// use heathcliff::create_ckks_decryptor_suite;
    /// use num_complex::Complex;
    /// let (params, context, encoder, _, _, _)
    ///     = create_ckks_decryptor_suite(8192, vec![60, 60, 60]);
    /// let message = Complex::new(42.0, 63.0);
    /// let scale = (1u64<<40) as f64;
    /// let plain = encoder.encode_c64_single_new(message, None, scale);
    /// let decoded = encoder.decode_new(&plain);
    /// for i in 0..4096 {assert!((decoded[i] - message).norm() < 0.01);}
    /// ```
    pub fn encode_c64_single(&self, value: Complex<f64>, parms_id: Option<ParmsID>, scale: f64, destination: &mut Plaintext) {
        let parms_id = parms_id.unwrap_or_else(|| *self.context.first_parms_id());
        self.encode_internal_c64_single(value, &parms_id, scale, destination)
    }

    /// See [Self::encode_c64_single].
    pub fn encode_c64_single_new(&self, value: Complex<f64>, parms_id: Option<ParmsID>, scale: f64) -> Plaintext {
        let parms_id = parms_id.unwrap_or_else(|| *self.context.first_parms_id());
        let mut destination = Plaintext::default();
        self.encode_internal_c64_single(value, &parms_id, scale, &mut destination);
        destination
    }

    /// Encodes an integer number into a plaintext polynomial without any scaling.
    /// The number repeats for N/2 times to fill all slots.
    /// If `parms_id` is not provided, encode using the [HeContext::first_parms_id()]
    /// 
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(8192, vec![60, 60, 60]);
    /// let evaluator = Evaluator::new(context.clone());
    /// 
    /// let message = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    /// let scale = (1u64<<40) as f64;
    /// let message_encoded = encoder.encode_c64_array_new(&message, None, scale);
    /// let message_encrypted = encryptor.encrypt_new(&message_encoded);
    /// 
    /// let scalar = 2;
    /// let scalar_encoded = encoder.encode_i64_single_new(scalar, None);
    /// 
    /// let multiplied_encrypted = evaluator.multiply_plain_new(&message_encrypted, &scalar_encoded);
    /// let multiplied_encoded = decryptor.decrypt_new(&multiplied_encrypted);
    /// let decoded = encoder.decode_new(&multiplied_encoded);
    /// for i in 0..2 {assert!((decoded[i] - message[i] * 2.0).norm() < 0.01);}
    /// for i in 2..4096 {assert!(decoded[i].norm() < 0.01);}
    /// ```
    pub fn encode_i64_single(&self, value: i64, parms_id: Option<ParmsID>, destination: &mut Plaintext) {
        let parms_id = parms_id.unwrap_or_else(|| *self.context.first_parms_id());
        self.encode_internal_i64_single(value, &parms_id, destination)
    }
    
    /// See [Self::encode_i64_single].
    pub fn encode_i64_single_new(&self, value: i64, parms_id: Option<ParmsID>) -> Plaintext {
        let parms_id = parms_id.unwrap_or_else(|| *self.context.first_parms_id());
        let mut destination = Plaintext::default();
        self.encode_internal_i64_single(value, &parms_id, &mut destination);
        destination
    }

    /// Decodes a plaintext polynomial into double-precision floating-point
    /// complex numbers. The scale stored in the ciphertext will be used to
    /// scale down the coefficients of the plaintext polynomial.
    /// See the encoding methods for examples.
    pub fn decode(&self, plain: &Plaintext, destination: &mut Vec<Complex<f64>>) {
        self.decode_internal(plain, destination)
    }

    /// See [Self::decode].
    pub fn decode_new(&self, plain: &Plaintext) -> Vec<Complex<f64>> {
        let mut destination = vec![Complex::default(); self.slots];
        self.decode_internal(plain, &mut destination);
        destination
    }

    /// Decodes a plaintext polynomial into as their coefficients.
    pub fn decode_polynomial(&self, plain: &Plaintext, destination: &mut Vec<f64>) {
        self.decode_polynomial_internal(plain, destination)
    }

    /// See [Self::decode_polynomial]
    pub fn decode_polynomial_new(&self, plain: &Plaintext) -> Vec<f64> {
        let mut destination = vec![0.0; self.slots * 2];
        self.decode_polynomial_internal(plain, &mut destination);
        destination
    }

    /// Alias of [Self::slot_count].
    pub fn slots(&self) -> usize {
        self.slots
    }
    

}

#[cfg(test)]
mod tests {
    use num_complex::Complex;
    use rand::Rng;
    use super::*;
    use crate::CoeffModulus;
    use crate::EncryptionParameters;
    use crate::HeContext;
    use crate::SchemeType;
    use crate::SecurityLevel;


    #[test]
    fn test_vector() {

        let mut rng = rand::thread_rng();


        let slots = 32;
        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(slots << 1)
            .set_coeff_modulus(&CoeffModulus::create(slots<<1, vec![40, 40, 40, 40]));
        let context = HeContext::new(parms, false, SecurityLevel::None);

        let values = (0..slots)
            .map(|_| Complex::new(0.0, 0.0)).collect::<Vec<_>>();

        let encoder = CKKSEncoder::new(context.clone());
        let delta = 2.0_f64.powi(16);
        let plain = encoder.encode_c64_array_new(&values, None, delta);
        let result = encoder.decode_new(&plain);
        result.into_iter().zip(values).for_each(|(a, b)| {
            let tmp = (a.re - b.re).abs();
            assert!(tmp < 0.5);
        });


        let slots = 32;
        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(slots << 1)
            .set_coeff_modulus(&CoeffModulus::create(slots<<1, vec![60, 60, 60, 60]));
        let context = HeContext::new(parms, false, SecurityLevel::None);

        let data_bound = 0..(1 << 30);
        let values = (0..slots)
            .map(|_| 
                Complex::new(rng.gen_range(data_bound.clone()) as f64, 0.0)
            )
            .collect::<Vec<_>>();

        let encoder = CKKSEncoder::new(context.clone());
        let delta = 2.0_f64.powf(40.0);
        let plain = encoder.encode_c64_array_new(&values, None, delta);
        let result = encoder.decode_new(&plain);
        result.into_iter().zip(values).for_each(|(a, b)| {
            let tmp = (a.re - b.re).abs();
            assert!(tmp < 0.5);
        });


        let slots = 64;
        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(slots << 1)
            .set_coeff_modulus(&CoeffModulus::create(slots<<1, vec![60, 60, 60]));
        let context = HeContext::new(parms, false, SecurityLevel::None);

        let data_bound = 0..(1 << 30);
        let values = (0..slots)
            .map(|_| 
                Complex::new(rng.gen_range(data_bound.clone()) as f64, 0.0)
            )
            .collect::<Vec<_>>();

        let encoder = CKKSEncoder::new(context.clone());
        let delta = 2.0_f64.powf(40.0);
        let plain = encoder.encode_c64_array_new(&values, None, delta);
        let result = encoder.decode_new(&plain);
        result.into_iter().zip(values).for_each(|(a, b)| {
            let tmp = (a.re - b.re).abs();
            assert!(tmp < 0.5);
        });


        let slots = 64;
        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(slots << 1)
            .set_coeff_modulus(&CoeffModulus::create(slots<<1, vec![30; 5]));
        let context = HeContext::new(parms, false, SecurityLevel::None);

        let data_bound = 0..(1 << 30);
        let values = (0..slots)
            .map(|_| 
                Complex::new(rng.gen_range(data_bound.clone()) as f64, 0.0)
            )
            .collect::<Vec<_>>();

        let encoder = CKKSEncoder::new(context.clone());
        let delta = 2.0_f64.powf(40.0);
        let plain = encoder.encode_c64_array_new(&values, None, delta);
        let result = encoder.decode_new(&plain);
        result.into_iter().zip(values).for_each(|(a, b)| {
            let tmp = (a.re - b.re).abs();
            assert!(tmp < 0.5);
        });


        let slots = 32;
        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(128)
            .set_coeff_modulus(&CoeffModulus::create(128, vec![30; 5]));
        let context = HeContext::new(parms, false, SecurityLevel::None);

        let data_bound = 0..(1 << 30);
        let values = (0..slots)
            .map(|_| 
                Complex::new(rng.gen_range(data_bound.clone()) as f64, 0.0)
            )
            .collect::<Vec<_>>();

        let encoder = CKKSEncoder::new(context.clone());
        let delta = 2.0_f64.powf(40.0);
        let plain = encoder.encode_c64_array_new(&values, None, delta);
        let result = encoder.decode_new(&plain);
        result.into_iter().zip(values).for_each(|(a, b)| {
            let tmp = (a.re - b.re).abs();
            assert!(tmp < 0.5);
        });


        let slots = 32;
        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(128)
            .set_coeff_modulus(&CoeffModulus::create(128, vec![30; 19]));
        let context = HeContext::new(parms, false, SecurityLevel::None);

        let data_bound = 0..(1 << 30);
        let values = (0..slots)
            .map(|_| 
                Complex::new(rng.gen_range(data_bound.clone()) as f64, 0.0)
            )
            .collect::<Vec<_>>();

        let encoder = CKKSEncoder::new(context.clone());
        let delta = 2.0_f64.powf(40.0);
        let plain = encoder.encode_c64_array_new(&values, None, delta);
        let result = encoder.decode_new(&plain);
        result.into_iter().zip(values).for_each(|(a, b)| {
            let tmp = (a.re - b.re).abs();
            assert!(tmp < 0.5);
        });


        let slots = 64;
        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(slots<<1)
            .set_coeff_modulus(&CoeffModulus::create(slots<<1, vec![40; 5]));
        let context = HeContext::new(parms, false, SecurityLevel::None);

        let data_bound = 0..(1 << 20);
        let values = (0..slots)
            .map(|_| 
                Complex::new(rng.gen_range(data_bound.clone()) as f64, 0.0)
            )
            .collect::<Vec<_>>();

        let encoder = CKKSEncoder::new(context.clone());

        let delta = 2.0_f64.powf(110.0);
        let plain = encoder.encode_c64_array_new(&values, None, delta);
        let result = encoder.decode_new(&plain);
        result.into_iter().zip(values.iter()).for_each(|(a, b)| {
            let tmp = (a.re - b.re).abs();
            assert!(tmp < 0.5);
        });

        let delta = 2.0_f64.powf(130.0);
        let plain = encoder.encode_c64_array_new(&values, None, delta);
        let result = encoder.decode_new(&plain);
        result.into_iter().zip(values).for_each(|(a, b)| {
            let tmp = (a.re - b.re).abs();
            assert!(tmp < 0.5);
        });

    }

    #[test]
    fn test_single() {

        let mut rng = rand::thread_rng();

        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(64)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![40; 4]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let encoder = CKKSEncoder::new(context.clone());
        let data_bound = 0..(1 << 20);

        let delta = 2.0_f64.powi(16);
        for _ in 0..50 {
            let value = rng.gen_range(data_bound.clone()) as f64;
            let plain = encoder.encode_f64_single_new(value, None, delta);
            let result = encoder.decode_new(&plain);
            result.into_iter().for_each(|a| {
                let tmp = (a.re - value).abs();
                assert!(tmp < 0.5);
            });
        }
        let delta = 2.0_f64.powi(60);
        for _ in 0..50 {
            let value = rng.gen_range(data_bound.clone()) as f64;
            let plain = encoder.encode_f64_single_new(value, None, delta);
            let result = encoder.decode_new(&plain);
            result.into_iter().for_each(|a| {
                let tmp = (a.re - value).abs();
                assert!(tmp < 0.5);
            });
        }
        let delta = 2.0_f64.powi(90);
        for _ in 0..50 {
            let value = rng.gen_range(data_bound.clone()) as f64;
            let plain = encoder.encode_f64_single_new(value, None, delta);
            let result = encoder.decode_new(&plain);
            result.into_iter().for_each(|a| {
                let tmp = (a.re - value).abs();
                assert!(tmp < 0.5);
            });
        }


        let slots = 32;
        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(slots<<1)
            .set_coeff_modulus(&CoeffModulus::create(slots<<1, vec![40; 4]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let encoder = CKKSEncoder::new(context.clone());

        let data_bound = 0..(1 << 30);
        for _ in 0..50 {
            let value = rng.gen_range(data_bound.clone()) as i64;
            let plain = encoder.encode_i64_single_new(value, None);
            let result = encoder.decode_new(&plain);
            result.into_iter().for_each(|a| {
                let tmp = (a.re - value as f64).abs();
                assert!(tmp < 0.5);
            });
        }
        for _ in 0..50 {
            let value = rng.gen::<i64>() % (1 << 39);
            let plain = encoder.encode_i64_single_new(value, None);
            let result = encoder.decode_new(&plain);
            result.into_iter().for_each(|a| {
                let tmp = (a.re - value as f64).abs();
                assert!(tmp < 0.5);
            });
        }

    }

    #[test]
    fn test_polynomial() {
        use crate::{create_ckks_decryptor_suite, Evaluator};
        let (_params, context, encoder, _keygen, encryptor, decryptor)
            = create_ckks_decryptor_suite(8192, vec![60, 60, 60]);
        let evaluator = Evaluator::new(context.clone());
        let scale = (1u64<<40) as f64;
        let x = vec![1.0, 2.0, 3.0];
        let y = vec![4.0, 5.0, 6.0];
        let x_encoded = encoder.encode_f64_polynomial_new(&x, None, scale);
        let y_encoded = encoder.encode_f64_polynomial_new(&y, None, scale);
        let x_decoded = encoder.decode_polynomial_new(&x_encoded);
        x.iter().zip(x_decoded.iter()).for_each(|(a, b)| {
            let tmp = (a - b).abs();
            assert!(tmp < 0.5);
        });
        let x_encrypted = encryptor.encrypt_new(&x_encoded);
        let y_encrypted = encryptor.encrypt_new(&y_encoded);
        let result = evaluator.multiply_new(&x_encrypted, &y_encrypted);
        let result_decrypted = decryptor.decrypt_new(&result);
        let result = encoder.decode_polynomial_new(&result_decrypted);
        let expected = vec![4.0, 13.0, 28.0, 27.0, 18.0];
        result.into_iter().zip(expected).for_each(|(a, b)| {
            let tmp = (a - b).abs();
            assert!(tmp < 0.5);
        });

    }

}