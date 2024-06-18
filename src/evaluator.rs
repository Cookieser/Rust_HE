use std::sync::Arc;

use crate::{
    util,
    Ciphertext, Plaintext,
    ContextData, HeContext, ValCheck, ParmsID, Modulus,
    polymod, SchemeType, KSwitchKeys, RelinKeys, GaloisKeys, ExpandSeed, PARMS_ID_ZERO,
};

/// Provides operations on [Ciphertext] objects. 
/// 
/// Provides operations on ciphertexts. Due to the properties of the encryption scheme, the arithmetic operations pass
/// through the encryption layer to the underlying plaintext, changing it according to the type of the operation. Since
/// the plaintext elements are fundamentally polynomials in the polynomial quotient ring Z_T\[x\]/(X^N+1), where T is the
/// plaintext modulus and X^N+1 is the polynomial modulus, this is the ring where the arithmetic operations will take
/// place. BatchEncoder (batching) provider an alternative possibly more convenient view of the plaintext elements as
/// 2-by-(N2/2) matrices of integers modulo the plaintext modulus. In the batching view the arithmetic operations act on
/// the matrices element-wise. Some of the operations only apply in the batching view, such as matrix row and column
/// rotations. Other operations such as relinearization have no semantic meaning but are necessary for performance
/// reasons.
/// 
/// ## Arithmetic Operations
/// The core operations are arithmetic operations, in particular multiplication and addition of ciphertexts. In addition
/// to these, we also provide negation, subtraction, squaring, exponentiation, and multiplication and addition of
/// several ciphertexts for convenience. in many cases some of the inputs to a computation are plaintext elements rather
/// than ciphertexts. For this we provide fast "plain" operations: plain addition, plain subtraction, and plain
/// multiplication.
/// 
/// ## Relinearization
/// One of the most important non-arithmetic operations is relinearization, which takes as input a ciphertext of size
/// K+1 and relinearization keys (at least K-1 keys are needed), and changes the size of the ciphertext down to 2
/// (minimum size). For most use-cases only one relinearization key suffices, in which case relinearization should be
/// performed after every multiplication. Homomorphic multiplication of ciphertexts of size K+1 and L+1 outputs a
/// ciphertext of size K+L+1, and the computational cost of multiplication is proportional to K*L. Plain multiplication
/// and addition operations of any type do not change the size. Relinearization requires relinearization keys to have
/// been generated.
/// 
/// ## Rotations
/// When batching is enabled, we provide operations for rotating the plaintext matrix rows cyclically left or right, and
/// for rotating the columns (swapping the rows). Rotations require Galois keys to have been generated.
/// 
/// ## Other Operations
/// We also provide operations for transforming ciphertexts to NTT form and back, and for transforming plaintext
/// polynomials to NTT form. These can be used in a very fast plain multiplication variant, that assumes the inputs to
/// be in NTT form. Since the NTT has to be done in any case in plain multiplication, this function can be used when
/// e.g. one plaintext input is used in several plain multiplication, and transforming it several times would not make
/// sense.
/// 
/// ## NTT form
/// When using the BFV/BGV scheme (SchemeType::bfv/bgv), all plaintexts and ciphertexts should remain by default in the
/// usual coefficient representation, i.e., not in NTT form. When using the CKKS scheme (SchemeType::ckks), all
/// plaintexts and ciphertexts should remain by default in NTT form. We call these scheme-specific NTT states the
/// "default NTT form". Some functions, such as add, work even if the inputs are not in the default state, but others,
/// such as multiply, will throw an exception. The output of all evaluation functions will be in the same state as the
/// input(s), with the exception of the transformTo_ntt and transformFrom_ntt functions, which change the state.
/// Ideally, unless these two functions are called, all other functions should "just work".
/// 
/// - See [EncryptionParameters](crate::EncryptionParameters) for more details on encryption parameters.
/// - See [BatchEncoder](crate::BatchEncoder) for more details on batching
/// - See [RelinKeys] for more details on relinearization keys.
/// - See [GaloisKeys] for more details on Galois keys.
pub struct Evaluator {
    context: Arc<HeContext>,
}

impl Evaluator {

    /// Create a evaluator with the specified [HeContext].
    pub fn new(context: Arc<HeContext>) -> Self {
        if !context.parameters_set() {
            panic!("[Invalid argument] Encryption parameters are not set correctly.");
        }
        Self {
            context,
        }
    }

    pub(crate) fn check_ciphertext(&self, ciphertext: &Ciphertext) {
        if !ciphertext.is_valid_for(self.context.as_ref()) {
            panic!("[Invalid argument] Ciphertext is not valid for encryption parameters.");
        }
        if ciphertext.contains_seed() {
            panic!("[Invalid argument] Ciphertext should be expanded before computation.");
        }
    }

    pub(crate) fn check_plaintext(&self, plaintext: &Plaintext) {
        if !plaintext.is_valid_for(self.context.as_ref()) {
            panic!("[Invalid argument] Plaintext is not valid for encryption parameters.");
        }
    }

    fn check_public_key<K: ExpandSeed>(&self, key: &K) {
        if key.contains_seed() {
            panic!("[Invalid argument] Key should be expanded from seed before use.");
        }
    }

    pub(crate) fn get_context_data(&self, parms_id: &ParmsID) -> Arc<ContextData> {
        self.context.get_context_data(parms_id).unwrap()
    }

    fn are_same_scale(&self, ciphertext1: &Ciphertext, ciphertext2: &Ciphertext) -> bool {
        util::are_close_f64(ciphertext1.scale(), ciphertext2.scale())
    }

    fn match_parms_id(&self, ciphertext1: &Ciphertext, ciphertext2: &Ciphertext) {
        if ciphertext1.parms_id() != ciphertext2.parms_id() {
            panic!("[Invalid argument] Ciphertexts do not have same encryption parameters.");
        }
    }

    fn match_scale(&self, ciphertext1: &Ciphertext, ciphertext2: &Ciphertext) {
        if !self.are_same_scale(ciphertext1, ciphertext2) {
            panic!("[Invalid argument] Ciphertexts do not have same scale.");
        }
    }


    fn balance_correction_factors(factor1: u64, factor2: u64, plain_modulus: &Modulus) -> (u64, u64, u64) {
        let t = plain_modulus.value();
        let half_t = t >> 1;
        let sum_abs = |x: u64, y: u64| {
            let x_bal = if x > half_t {x as i64 - t as i64} else {x as i64};
            let y_bal = if y > half_t {y as i64 - t as i64} else {y as i64};
            x_bal.abs() + y_bal.abs()
        };
        // ratio = f2 / f1 mod p
        let mut ratio = 1;
        if !util::try_invert_u64_mod(factor1, plain_modulus, &mut ratio) {
            panic!("[Logic error] Cannot invert factor1 mod plain_modulus.");
        }
        ratio = util::multiply_u64_mod(ratio, factor2, plain_modulus);
        let mut e1 = ratio;
        let mut e2 = 1;
        let mut sum = sum_abs(e1, e2);
        // Extended Euclidean
        let mut prev_a = plain_modulus.value() as i64;
        let mut prev_b = 0_i64;
        let mut a = ratio as i64;
        let mut b = 1_i64;
        while a != 0 {
            let q = prev_a / a;
            let temp = prev_a % a;
            prev_a = a;
            a = temp;
            let temp = prev_b - q * b;
            prev_b = b;
            b = temp;
            let mut a_mod = util::barrett_reduce_u64(a.unsigned_abs(), plain_modulus);
            if a < 0 {a_mod = util::negate_u64_mod(a_mod, plain_modulus);}
            let mut b_mod = util::barrett_reduce_u64(b.unsigned_abs(), plain_modulus);
            if b < 0 {b_mod = util::negate_u64_mod(b_mod, plain_modulus);}
            if a_mod != 0 && util::gcd(a_mod, t) == 1 {
                let new_sum = sum_abs(a_mod, b_mod);
                if new_sum < sum {
                    e1 = a_mod;
                    e2 = b_mod;
                    sum = new_sum;
                }
            }
        }
        (util::multiply_u64_mod(e1, factor1, plain_modulus), e1, e2)
    }
    
    fn is_scale_within_bounds(scale: f64, context_data: &ContextData) -> bool {
        let scheme = context_data.parms().scheme();
        let scale_bit_count_bound = 
        match scheme {
            SchemeType::BFV | SchemeType::BGV => context_data.parms().plain_modulus().bit_count() as isize,
            SchemeType::CKKS => context_data.total_coeff_modulus_bit_count() as isize,
            _ => -1,
        };
        !(scale <= 0.0 || scale.log2() as isize >= scale_bit_count_bound)
    }

    /// Returns a reference to the [HeContext] used by the evaluator.
    pub fn context(&self) -> &Arc<HeContext> {
        &self.context
    }

    /// See [Evaluator::negate].
    pub fn negate_inplace(&self, ciphertext: &mut Ciphertext) {
        self.check_ciphertext(ciphertext); // Verify parameters
        let context_data = self.get_context_data(ciphertext.parms_id());
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let poly_count = ciphertext.size();
        let poly_degree = parms.poly_modulus_degree();
        polymod::negate_inplace_ps(ciphertext.data_mut(), poly_count, poly_degree, coeff_modulus);
    }

    /// Negates a ciphertext.
    /// 
    /// # BFV/BGV example
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Evaluator};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let plain_modulus = params.plain_modulus().value();
    /// let message = vec![1, 2, 3, 4];
    /// let mut encrypted = encryptor.encrypt_new(&encoder.encode_new(&message));
    /// evaluator.negate_inplace(&mut encrypted);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted));
    /// for i in 0..4 {assert_eq!(result[i], plain_modulus - message[i]);}
    /// ```
    /// 
    /// # CKKS example
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(4096, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let message = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    /// let mut encrypted = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message, None, (1u64<<40) as f64));
    /// evaluator.negate_inplace(&mut encrypted);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted));
    /// for i in 0..2 {assert!((result[i] - (-message[i])).norm() < 1e-3);}
    #[inline]
    pub fn negate(&self, ciphertext: &Ciphertext, destination: &mut Ciphertext) {
        *destination = ciphertext.clone();
        self.negate_inplace(destination);
    }

    /// See [Evaluator::negate].
    #[inline]
    pub fn negate_new(&self, ciphertext: &Ciphertext) -> Ciphertext {
        let mut destination = ciphertext.clone();
        self.negate_inplace(&mut destination);
        destination
    }

    /// See [Evaluator::add].
    pub fn add_inplace(&self, ciphertext1: &mut Ciphertext, ciphertext2: &Ciphertext) {
        self.check_ciphertext(ciphertext1); // Verify parameters
        self.check_ciphertext(ciphertext2);
        self.match_parms_id(ciphertext1, ciphertext2);
        if ciphertext1.is_ntt_form() != ciphertext2.is_ntt_form() {
            panic!("[Invalid argument] Ciphertexts' NTT forms do not conform.");
        }
        self.match_scale(ciphertext1, ciphertext2);
        let context_data = self.get_context_data(ciphertext1.parms_id());
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let ciphertext1_size = ciphertext1.size();
        let ciphertext2_size = ciphertext2.size();
        let max_count = ciphertext1_size.max(ciphertext2_size);
        let min_count = ciphertext1_size.min(ciphertext2_size);
        let plain_modulus = parms.plain_modulus();
        let coeff_count = parms.poly_modulus_degree();

        if ciphertext1.correction_factor() != ciphertext2.correction_factor() {
            // Balance correction factors and multiply by scalars before addition in BGV
            let factors = Self::balance_correction_factors(
                ciphertext1.correction_factor(),
                ciphertext2.correction_factor(),
                plain_modulus
            );
            polymod::multiply_scalar_inplace_ps(
                ciphertext1.data_mut(),
                factors.1,
                ciphertext1_size,
                coeff_count,
                coeff_modulus
            );
            let mut ciphertext2_copy = ciphertext2.clone();
            polymod::multiply_scalar_inplace_ps(
                ciphertext2_copy.data_mut(),
                factors.2,
                ciphertext2_size,
                coeff_count,
                coeff_modulus
            );
            // Set new correction factor
            ciphertext1.set_correction_factor(factors.0);
            ciphertext2_copy.set_correction_factor(factors.0);
            self.add_inplace(ciphertext1, &ciphertext2_copy);
        } else {
            // Prepare destination
            ciphertext1.resize(&self.context, context_data.parms_id(), max_count);
            polymod::add_inplace_ps(
                ciphertext1.data_mut(),
                ciphertext2.data(),
                min_count,
                coeff_count,
                coeff_modulus
            );
            // Copy the remainding polys of the array with larger count into encrypted1
            if ciphertext1_size < ciphertext2_size {
                ciphertext1.polys_mut(ciphertext1_size, ciphertext2_size).copy_from_slice(
                    ciphertext2.polys(ciphertext1_size, ciphertext2_size)
                );
            }
        }
    }

    /// Adds a ciphertext to another.
    /// 
    /// # BFV/BGV example
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Evaluator};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let plain_modulus = params.plain_modulus().value();
    /// let message1 = vec![1, 2, 3, 4];
    /// let message2 = vec![5, 6, 7, 8];
    /// let mut encrypted1 = encryptor.encrypt_new(&encoder.encode_new(&message1));
    /// let     encrypted2 = encryptor.encrypt_new(&encoder.encode_new(&message2));
    /// evaluator.add_inplace(&mut encrypted1, &encrypted2);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..4 {assert_eq!(result[i], message1[i] + message2[i]);}
    /// ```
    /// 
    /// # CKKS example
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(4096, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let message1 = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    /// let message2 = vec![Complex::new(5.0, 6.0), Complex::new(7.0, 8.0)];
    /// let mut encrypted1 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message1, None, (1u64<<40) as f64));
    /// let     encrypted2 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message2, None, (1u64<<40) as f64));
    /// evaluator.add_inplace(&mut encrypted1, &encrypted2);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..2 {assert!((result[i] - (message1[i] + message2[i])).norm() < 1e-3);}
    #[inline]
    pub fn add(&self, ciphertext1: &Ciphertext, ciphertext2: &Ciphertext, destination: &mut Ciphertext) {
        *destination = ciphertext1.clone();
        self.add_inplace(destination, ciphertext2);
    }

    /// See [Evaluator::add].
    #[inline]
    pub fn add_new(&self, ciphertext1: &Ciphertext, ciphertext2: &Ciphertext) -> Ciphertext {
        let mut destination = ciphertext1.clone();
        self.add_inplace(&mut destination, ciphertext2);
        destination
    }

    /// Add many ciphertexts. Check [Evaluator::add].
    pub fn add_many(&self, operands: &[Ciphertext], destination: &mut Ciphertext) {
        if operands.is_empty() {
            panic!("[Invalid argument] operands vector must be non-empty.");
        }
        *destination = operands[0].clone();
        for i in 1..operands.len() {
            self.add_inplace(destination, &operands[i]);
        }
    }

    /// Add many ciphertexts. Check [Evaluator::add].
    pub fn add_many_new(&self, operands: &[Ciphertext]) -> Ciphertext {
        if operands.is_empty() {
            panic!("[Invalid argument] operands vector must be non-empty.");
        }
        let mut destination = Ciphertext::new();
        self.add_many(operands, &mut destination);
        destination
    }

    /// See [Evaluator::sub].
    pub fn sub_inplace(&self, ciphertext1: &mut Ciphertext, ciphertext2: &Ciphertext) {
        self.check_ciphertext(ciphertext1); // Verify parameters
        self.check_ciphertext(ciphertext2);
        self.match_parms_id(ciphertext1, ciphertext2);
        if ciphertext1.is_ntt_form() != ciphertext2.is_ntt_form() {
            panic!("[Invalid argument] Ciphertexts' NTT forms do not conform.");
        }
        self.match_scale(ciphertext1, ciphertext2);
        let context_data = self.get_context_data(ciphertext1.parms_id());
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let ciphertext1_size = ciphertext1.size();
        let ciphertext2_size = ciphertext2.size();
        let coeff_modulus_size = coeff_modulus.len();
        let max_count = ciphertext1_size.max(ciphertext2_size);
        let min_count = ciphertext1_size.min(ciphertext2_size);
        let plain_modulus = parms.plain_modulus();
        let coeff_count = parms.poly_modulus_degree();

        if ciphertext1.correction_factor() != ciphertext2.correction_factor() {
            // Balance correction factors and multiply by scalars before addition in BGV
            let factors = Self::balance_correction_factors(
                ciphertext1.correction_factor(),
                ciphertext2.correction_factor(),
                plain_modulus
            );
            polymod::multiply_scalar_inplace_ps(
                ciphertext1.data_mut(),
                factors.1,
                ciphertext1_size,
                coeff_count,
                coeff_modulus
            );
            let mut ciphertext2_copy = ciphertext2.clone();
            polymod::multiply_scalar_inplace_ps(
                ciphertext2_copy.data_mut(),
                factors.2,
                ciphertext2_size,
                coeff_count,
                coeff_modulus
            );
            // Set new correction factor
            ciphertext1.set_correction_factor(factors.0);
            ciphertext2_copy.set_correction_factor(factors.0);
            self.sub_inplace(ciphertext1, &ciphertext2_copy);
        } else {
            // Prepare destination
            ciphertext1.resize(&self.context, context_data.parms_id(), max_count);
            polymod::sub_inplace_ps(
                ciphertext1.data_mut(),
                ciphertext2.data(),
                min_count,
                coeff_count,
                coeff_modulus
            );
            // Copy the remainding polys of the array with larger count into encrypted1
            if ciphertext1_size < ciphertext2_size {
                let d = coeff_count*coeff_modulus_size;
                polymod::negate_ps(
                    ciphertext2.polys(ciphertext1_size, ciphertext2_size), 
                    ciphertext2_size - ciphertext1_size, 
                    coeff_count, coeff_modulus,
                    ciphertext1.polys_mut(ciphertext1_size,ciphertext2_size*d), 
                );
            }
        }
    }

    /// Substract a ciphertext from another.
    /// 
    /// # BFV/BGV example
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Evaluator};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let plain_modulus = params.plain_modulus().value();
    /// let message1 = vec![1, 2, 3, 4];
    /// let message2 = vec![5, 6, 7, 8];
    /// let mut encrypted1 = encryptor.encrypt_new(&encoder.encode_new(&message1));
    /// let     encrypted2 = encryptor.encrypt_new(&encoder.encode_new(&message2));
    /// evaluator.sub_inplace(&mut encrypted1, &encrypted2);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..4 {assert_eq!(
    ///     result[i], 
    ///     (plain_modulus + message1[i] - message2[i]) % plain_modulus
    /// );}
    /// ```
    /// 
    /// # CKKS example
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(4096, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let message1 = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    /// let message2 = vec![Complex::new(5.0, 6.0), Complex::new(7.0, 8.0)];
    /// let mut encrypted1 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message1, None, (1u64<<40) as f64));
    /// let     encrypted2 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message2, None, (1u64<<40) as f64));
    /// evaluator.sub_inplace(&mut encrypted1, &encrypted2);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..2 {assert!((result[i] - (message1[i] - message2[i])).norm() < 1e-3);}
    #[inline]
    pub fn sub(&self, ciphertext1: &Ciphertext, ciphertext2: &Ciphertext, destination: &mut Ciphertext) {
        *destination = ciphertext1.clone();
        self.sub_inplace(destination, ciphertext2);
    }

    /// See [Evaluator::sub].
    #[inline]
    pub fn sub_new(&self, ciphertext1: &Ciphertext, ciphertext2: &Ciphertext) -> Ciphertext {
        let mut destination = ciphertext1.clone();
        self.sub_inplace(&mut destination, ciphertext2);
        destination
    }

    #[allow(non_snake_case)]
    fn bfv_multiply(&self, encrypted1: &mut Ciphertext, encrypted2: &Ciphertext) {
        if encrypted1.is_ntt_form() || encrypted2.is_ntt_form() {
            panic!("[Invalid argument] Ciphertexts must not be in NTT form.");
        }

        // Extract encryption parameters.
        let context_data = self.get_context_data(encrypted1.parms_id());
        let parms = context_data.parms();
        let coeff_count = parms.poly_modulus_degree();
        let base_q_size = parms.coeff_modulus().len();
        let encrypted1_size = encrypted1.size();
        let encrypted2_size = encrypted2.size();
        let plain_modulus = parms.plain_modulus();
        let rns_tool = context_data.rns_tool();
        let base_Bsk_size = rns_tool.base_Bsk().len();
        let base_Bsk_m_tilde_size = rns_tool.base_Bsk_m_tilde().len();

        // Determine destination.size()
        let dest_size = encrypted1_size + encrypted2_size - 1;

        let base_q = parms.coeff_modulus();
        let base_Bsk = rns_tool.base_Bsk().base();

        let base_q_ntt_tables = context_data.small_ntt_tables();
        let base_Bsk_ntt_tables = rns_tool.base_Bsk_ntt_tables();

        // Microsoft SEAL uses BEHZ-style RNS multiplication. This process is somewhat complex and consists of the
        // following steps:
        //
        // (1) Lift encrypted1 and encrypted2 (initially in base q) to an extended base q U Bsk U {m_tilde}
        // (2) Remove extra multiples of q from the results with Montgomery reduction, switching base to q U Bsk
        // (3) Transform the data to NTT form
        // (4) Compute the ciphertext polynomial product using dyadic multiplication
        // (5) Transform the data back from NTT form
        // (6) Multiply the result by t (plain_modulus)
        // (7) Scale the result by q using a divide-and-floor algorithm, switching base to Bsk
        // (8) Use Shenoy-Kumaresan method to convert the result to base q

        encrypted1.resize(&self.context, context_data.parms_id(), dest_size);
        // Allocate space for a base q output of behz_extend_base_convertToNtt for encrypted1
        let mut encrypted1_q = vec![0; encrypted1_size * coeff_count * base_q_size];
        // Allocate space for a base Bsk output of behz_extend_base_convertToNtt for encrypted1
        let mut encrypted1_Bsk = vec![0; encrypted1_size * coeff_count * base_Bsk_size];
        
        // Perform BEHZ steps (1)-(3) for encrypted1
        // Make copy of input polynomial (in base q) and convert to NTT form
        encrypted1_q.copy_from_slice(encrypted1.polys(0, encrypted1_size));
        // Lazy reduction
        polymod::ntt_lazy_ps(&mut encrypted1_q, encrypted1_size, coeff_count, base_q_ntt_tables);
        for i in 0..encrypted1_size {
            // Allocate temporary space for a polynomial in the Bsk U {m_tilde} base
            let mut temp = vec![0; coeff_count * base_Bsk_m_tilde_size];
            // (1) Convert from base q to base Bsk U {m_tilde}
            rns_tool.fastbconv_m_tilde(encrypted1.poly(i), &mut temp);
            // (2) Reduce q-overflows in with Montgomery reduction, switching base to Bsk
            let encrypted_Bsk_poly_i = &mut encrypted1_Bsk[i*coeff_count*base_Bsk_size..(i+1)*coeff_count*base_Bsk_size];
            rns_tool.sm_mrq(&temp, encrypted_Bsk_poly_i);
        }
        // Transform to NTT form in base Bsk
        polymod::ntt_lazy_ps(&mut encrypted1_Bsk, encrypted1_size, coeff_count, base_Bsk_ntt_tables);

        // Repeat for encrypted2
        let mut encrypted2_q = vec![0; encrypted2_size * coeff_count * base_q_size];
        let mut encrypted2_Bsk = vec![0; encrypted2_size * coeff_count * base_Bsk_size];
        encrypted2_q.copy_from_slice(encrypted2.polys(0, encrypted2_size));
        polymod::ntt_lazy_ps(&mut encrypted2_q, encrypted2_size, coeff_count, base_q_ntt_tables);
        for i in 0..encrypted2_size {
            let mut temp = vec![0; coeff_count * base_Bsk_m_tilde_size];
            rns_tool.fastbconv_m_tilde(encrypted2.poly(i), &mut temp);
            let encrypted_Bsk_poly_i = &mut encrypted2_Bsk[i*coeff_count*base_Bsk_size..(i+1)*coeff_count*base_Bsk_size];
            rns_tool.sm_mrq(&temp, encrypted_Bsk_poly_i);
        }
        polymod::ntt_lazy_ps(&mut encrypted2_Bsk, encrypted1_size, coeff_count, base_Bsk_ntt_tables);
        
        // Allocate temporary space for the output of step (4)
        // We allocate space separately for the base q and the base Bsk components
        let mut temp_dest_q = vec![0; dest_size * coeff_count * base_q_size];
        let mut temp_dest_Bsk = vec![0; dest_size * coeff_count * base_Bsk_size];
        
        // Perform BEHZ step (4): dyadic multiplication on arbitrary size ciphertexts
        for i in 0..dest_size {
            // We iterate over relevant components of encrypted1 and encrypted2 in increasing order for
            // encrypted1 and reversed (decreasing) order for encrypted2. The bounds for the indices of
            // the relevant terms are obtained as follows.
            let curr_encrypted1_last = i.min(encrypted1_size - 1);
            let curr_encrypted2_first = i.min(encrypted2_size - 1);
            let curr_encrypted1_first = i - curr_encrypted2_first;
            // let curr_encrypted2_last = i - curr_encrypted1_last;
            let steps = curr_encrypted1_last - curr_encrypted1_first + 1;

            // Perform the BEHZ ciphertext product both for base q and base Bsk
            let d = coeff_count * base_q_size;
            let mut temp = vec![0; coeff_count * base_q_size];
            for j in 0..steps {
                let shift1 = (curr_encrypted1_first + j) * d;
                let shift_reversed2 = (curr_encrypted2_first - j) * d;
                polymod::dyadic_product_p(
                    &encrypted1_q[shift1..shift1 + base_q_size * coeff_count],
                    &encrypted2_q[shift_reversed2..shift_reversed2 + base_q_size * coeff_count],
                    coeff_count,
                    base_q,
                    &mut temp,
                );
                let shift_out = i * d;
                polymod::add_inplace_p(
                    &mut temp_dest_q[shift_out..shift_out + base_q_size * coeff_count],
                    &temp,
                    coeff_count,
                    base_q,
                );
            }
            let mut temp = vec![0; coeff_count * base_Bsk_size];
            let d = coeff_count * base_Bsk_size;
            for j in 0..steps {
                let shift1 = (curr_encrypted1_first + j) * d;
                let shift_reversed2 = (curr_encrypted2_first - j) * d;
                polymod::dyadic_product_p(
                    &encrypted1_Bsk[shift1..shift1 + base_Bsk_size * coeff_count],
                    &encrypted2_Bsk[shift_reversed2..shift_reversed2 + base_Bsk_size * coeff_count],
                    coeff_count,
                    base_Bsk,
                    &mut temp,
                );
                let shift_out = i * d;
                polymod::add_inplace_p(
                    &mut temp_dest_Bsk[shift_out..shift_out + base_Bsk_size * coeff_count],
                    &temp,
                    coeff_count,
                    base_Bsk,
                );
            }
        }

        // Perform BEHZ step (5): transform data from NTT form
        // Lazy reduction here. The following multiplyPolyScalarCoeffmod will correct the value back to [0, p)
        polymod::intt_ps(&mut temp_dest_q, dest_size, coeff_count, base_q_ntt_tables);
        polymod::intt_ps(&mut temp_dest_Bsk, dest_size, coeff_count, base_Bsk_ntt_tables);

        // Perform BEHZ steps (6)-(8)
        for i in 0..dest_size {
            // Bring together the base q and base Bsk components into a single allocation
            let mut temp_q_Bsk = vec![0; coeff_count * (base_q_size + base_Bsk_size)];
            // Step (6): multiply base q components by t (plain_modulus)
            polymod::multiply_scalar_p(
                &temp_dest_q[i*coeff_count*base_q_size..(i+1)*coeff_count*base_q_size],
                plain_modulus.value(),
                coeff_count,
                base_q,
                &mut temp_q_Bsk[0..coeff_count*base_q_size],
            );
            polymod::multiply_scalar_p(
                &temp_dest_Bsk[i*coeff_count*base_Bsk_size..(i+1)*coeff_count*base_Bsk_size],
                plain_modulus.value(),
                coeff_count,
                base_Bsk,
                &mut temp_q_Bsk[coeff_count*base_q_size..],
            );
            let mut temp_Bsk = vec![0; coeff_count * base_Bsk_size];
            // Step (7): divide by q and floor, producing a result in base Bsk
            rns_tool.fast_floor(&temp_q_Bsk, &mut temp_Bsk);
            // Step (8): use Shenoy-Kumaresan method to convert the result to base q and write to encrypted1
            rns_tool.fastbconv_sk(&temp_Bsk, encrypted1.poly_mut(i));
        }
    }

    fn ckks_multiply(&self, encrypted1: &mut Ciphertext, encrypted2: &Ciphertext) {
        if !encrypted1.is_ntt_form() || !encrypted2.is_ntt_form() {
            panic!("[Invalid argument] Ciphertexts must be in NTT form");
        }
        
        // Extract encryption parameters.
        let context_data = self.get_context_data(encrypted1.parms_id());
        let parms = context_data.parms();
        let coeff_count = parms.poly_modulus_degree();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let encrypted1_size = encrypted1.size();
        let encrypted2_size = encrypted2.size();

        // Determine destination.size()
        let dest_size = encrypted1_size + encrypted2_size - 1;

        encrypted1.resize(&self.context, context_data.parms_id(), dest_size);

        let mut temp = vec![0; dest_size * coeff_count * coeff_modulus_size];

        for i in 0..dest_size {
            // We iterate over relevant components of encrypted1 and encrypted2 in increasing order for
            // encrypted1 and reversed (decreasing) order for encrypted2. The bounds for the indices of
            // the relevant terms are obtained as follows.
            let curr_encrypted1_last = i.min(encrypted1_size - 1);
            let curr_encrypted2_first = i.min(encrypted2_size - 1);
            let curr_encrypted1_first = i - curr_encrypted2_first;
            // let curr_encrypted2_last = i - curr_encrypted1_last;
            let steps = curr_encrypted1_last - curr_encrypted1_first + 1;

            let d = coeff_count * coeff_modulus_size;
            let mut prod = vec![0; d];
            for j in 0..steps {
                let shift1 = (curr_encrypted1_first + j) * d;
                let shift_reversed2 = (curr_encrypted2_first - j) * d;
                let shift_out = i * d;
                polymod::dyadic_product_p(
                    &encrypted1.data()[shift1..shift1 + d],
                    &encrypted2.data()[shift_reversed2..shift_reversed2 + d],
                    coeff_count,
                    coeff_modulus,
                    &mut prod,
                );
                polymod::add_inplace_p(
                    &mut temp[shift_out..shift_out + d],
                    &prod,
                    coeff_count,
                    coeff_modulus,
                );
            }
        }

        encrypted1.data_mut().copy_from_slice(&temp);
        encrypted1.set_scale(encrypted1.scale() * encrypted2.scale());
        if !Self::is_scale_within_bounds(encrypted1.scale(), &context_data) {
            panic!("[Invalid argument] Scale out of bounds");
        }
    }

    fn bgv_multiply(&self, encrypted1: &mut Ciphertext, encrypted2: &Ciphertext) {
        if encrypted1.is_ntt_form() || encrypted2.is_ntt_form() {
            panic!("[Invalid argument] Ciphertexts must not be in NTT form");
        }

        // Extract encryption parameters.
        let context_data = self.get_context_data(encrypted1.parms_id());
        let parms = context_data.parms();
        let coeff_count = parms.poly_modulus_degree();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let encrypted1_size = encrypted1.size();
        let encrypted2_size = encrypted2.size();
        let ntt_table = context_data.small_ntt_tables();

        let dest_size = encrypted1_size + encrypted2_size - 1;
        
        encrypted1.resize(&self.context, context_data.parms_id(), dest_size);
        
        polymod::ntt_ps(encrypted1.polys_mut(0, encrypted1_size), encrypted1_size, coeff_count, ntt_table);
        let mut encrypted2_copy = encrypted2.clone();
        polymod::ntt_ps(encrypted2_copy.polys_mut(0, encrypted2_size), encrypted2_size, coeff_count, ntt_table);
        
        let mut temp = vec![0; dest_size * coeff_count * coeff_modulus_size];

        for i in 0..dest_size {
            // We iterate over relevant components of encrypted1 and encrypted2 in increasing order for
            // encrypted1 and reversed (decreasing) order for encrypted2. The bounds for the indices of
            // the relevant terms are obtained as follows.
            let curr_encrypted1_last = i.min(encrypted1_size - 1);
            let curr_encrypted2_first = i.min(encrypted2_size - 1);
            let curr_encrypted1_first = i - curr_encrypted2_first;
            // let curr_encrypted2_last = i - curr_encrypted1_last;
            let steps = curr_encrypted1_last - curr_encrypted1_first + 1;

            let d = coeff_count * coeff_modulus_size;
            let mut prod = vec![0; d];
            for j in 0..steps {
                let shift1 = (curr_encrypted1_first + j) * d;
                let shift_reversed2 = (curr_encrypted2_first - j) * d;
                let shift_out = i * d;
                polymod::dyadic_product_p(
                    &encrypted1.data()[shift1..shift1 + d],
                    &encrypted2_copy.data()[shift_reversed2..shift_reversed2 + d],
                    coeff_count,
                    coeff_modulus,
                    &mut prod,
                );
                polymod::add_inplace_p(
                    &mut temp[shift_out..shift_out + d],
                    &prod,
                    coeff_count,
                    coeff_modulus,
                );
            }
        }
        encrypted1.polys_mut(0, dest_size).copy_from_slice(&temp);
        polymod::intt_ps(encrypted1.data_mut(), dest_size, coeff_count, ntt_table);
        encrypted1.set_correction_factor(
            util::multiply_u64_mod(
                encrypted1.correction_factor(), 
                encrypted2.correction_factor(), 
                parms.plain_modulus()
            )
        );
    }

    /// See [Evaluator::multiply].
    pub fn multiply_inplace(&self, encrypted1: &mut Ciphertext, encrypted2: &Ciphertext) {
        self.check_ciphertext(encrypted1); // Verify parameters
        self.check_ciphertext(encrypted2);
        self.match_parms_id(encrypted1, encrypted2);
        let scheme = self.context.first_context_data().unwrap().parms().scheme();
        match scheme {
            SchemeType::BFV => self.bfv_multiply(encrypted1, encrypted2),
            SchemeType::CKKS => self.ckks_multiply(encrypted1, encrypted2),
            SchemeType::BGV => self.bgv_multiply(encrypted1, encrypted2),
            _ => panic!("[Invalid argument] Unsupported scheme")
        }
    }

    /// Multiply a ciphertext with another. The result is not relinearized.
    /// 
    /// # BFV/BGV example
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Evaluator};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let plain_modulus = params.plain_modulus().value();
    /// let message1 = vec![1, 2, 3, 4];
    /// let message2 = vec![5, 6, 7, 8];
    /// let mut encrypted1 = encryptor.encrypt_new(&encoder.encode_new(&message1));
    /// let     encrypted2 = encryptor.encrypt_new(&encoder.encode_new(&message2));
    /// evaluator.multiply_inplace(&mut encrypted1, &encrypted2);
    /// assert_eq!(encrypted1.size(), 3);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..4 {assert_eq!(result[i], message1[i] * message2[i]);}
    /// ```
    /// 
    /// # CKKS example
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(8192, vec![60, 60, 60]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let message1 = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    /// let message2 = vec![Complex::new(5.0, 6.0), Complex::new(7.0, 8.0)];
    /// let mut encrypted1 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message1, None, (1u64<<40) as f64));
    /// let     encrypted2 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message2, None, (1u64<<40) as f64));
    /// evaluator.multiply_inplace(&mut encrypted1, &encrypted2);
    /// assert_eq!(encrypted1.size(), 3);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..2 {assert!((result[i] - (message1[i] * message2[i])).norm() < 1e-3);}
    #[inline]
    pub fn multiply(&self, encrypted1: &Ciphertext, encrypted2: &Ciphertext, destination: &mut Ciphertext) {
        *destination = encrypted1.clone();
        self.multiply_inplace(destination, encrypted2);
    }

    /// See [Evaluator::multiply].
    #[inline]
    pub fn multiply_new(&self, encrypted1: &Ciphertext, encrypted2: &Ciphertext) -> Ciphertext {
        let mut destination = encrypted1.clone();
        self.multiply_inplace(&mut destination, encrypted2);
        destination
    }

    #[allow(non_snake_case)]
    fn bfv_square(&self, encrypted: &mut Ciphertext) {
        if encrypted.is_ntt_form() {
            panic!("[Invalid argument] Ciphertext must not be in NTT form.");
        }

        // Extract encryption parameters.
        let context_data = self.get_context_data(encrypted.parms_id());
        let parms = context_data.parms();
        let coeff_count = parms.poly_modulus_degree();
        let base_q_size = parms.coeff_modulus().len();
        let encrypted_size = encrypted.size();

        if encrypted_size != 2 {
            self.bfv_multiply(encrypted, &encrypted.clone());
            return;
        }

        let plain_modulus = parms.plain_modulus();
        let rns_tool = context_data.rns_tool();
        let base_Bsk_size = rns_tool.base_Bsk().len();
        let base_Bsk_m_tilde_size = rns_tool.base_Bsk_m_tilde().len();

        let dest_size = encrypted_size + encrypted_size - 1;
        assert_eq!(dest_size, 3);

        let base_q = parms.coeff_modulus();
        let base_Bsk = rns_tool.base_Bsk().base();

        let base_q_ntt_tables = context_data.small_ntt_tables();
        let base_Bsk_ntt_tables = rns_tool.base_Bsk_ntt_tables();

        // Microsoft SEAL uses BEHZ-style RNS multiplication. This process is somewhat complex and consists of the
        // following steps:
        //
        // (1) Lift encrypted1 and encrypted2 (initially in base q) to an extended base q U Bsk U {m_tilde}
        // (2) Remove extra multiples of q from the results with Montgomery reduction, switching base to q U Bsk
        // (3) Transform the data to NTT form
        // (4) Compute the ciphertext polynomial product using dyadic multiplication
        // (5) Transform the data back from NTT form
        // (6) Multiply the result by t (plain_modulus)
        // (7) Scale the result by q using a divide-and-floor algorithm, switching base to Bsk
        // (8) Use Shenoy-Kumaresan method to convert the result to base q

        encrypted.resize(&self.context, context_data.parms_id(), dest_size);
        // Allocate space for a base q output of behz_extend_base_convertToNtt for encrypted1
        let mut encrypted_q = vec![0; encrypted_size * coeff_count * base_q_size];
        // Allocate space for a base Bsk output of behz_extend_base_convertToNtt for encrypted1
        let mut encrypted_Bsk = vec![0; encrypted_size * coeff_count * base_Bsk_size];
        
         // Perform BEHZ steps (1)-(3) for encrypted1
        for i in 0..encrypted_size {
            // Make copy of input polynomial (in base q) and convert to NTT form
            let encrypted_q_poly_i = &mut encrypted_q[i*coeff_count*base_q_size..(i+1)*coeff_count*base_q_size];
            encrypted_q_poly_i.copy_from_slice(encrypted.poly(i));
            // Lazy reduction
            polymod::ntt_lazy_p(encrypted_q_poly_i, coeff_count, base_q_ntt_tables);
            // Allocate temporary space for a polynomial in the Bsk U {m_tilde} base
            let mut temp = vec![0; coeff_count * base_Bsk_m_tilde_size];
            // (1) Convert from base q to base Bsk U {m_tilde}
            rns_tool.fastbconv_m_tilde(encrypted.poly(i), &mut temp);
            // (2) Reduce q-overflows in with Montgomery reduction, switching base to Bsk
            let encrypted_Bsk_poly_i = &mut encrypted_Bsk[i*coeff_count*base_Bsk_size..(i+1)*coeff_count*base_Bsk_size];
            rns_tool.sm_mrq(&temp, encrypted_Bsk_poly_i);
            // Transform to NTT form in base Bsk
            polymod::ntt_lazy_p(encrypted_Bsk_poly_i, coeff_count, base_Bsk_ntt_tables);
        }

        // Allocate temporary space for the output of step (4)
        // We allocate space separately for the base q and the base Bsk components
        let mut temp_dest_q = vec![0; dest_size * coeff_count * base_q_size];
        let mut temp_dest_Bsk = vec![0; dest_size * coeff_count * base_Bsk_size];

        // Perform the BEHZ ciphertext square both for base q and base Bsk
        let d_q = coeff_count * base_q_size;
        let d_Bsk = coeff_count * base_Bsk_size;

        // Compute c0^2
        let eq0 = &encrypted_q[0*d_q..1*d_q];
        let eq1 = &encrypted_q[1*d_q..2*d_q];
        polymod::dyadic_product_p(eq0, eq0, coeff_count, base_q, &mut temp_dest_q[0*d_q..1*d_q]);
        // Compute 2*c0*c1
        polymod::dyadic_product_p(eq0, eq1, coeff_count, base_q, &mut temp_dest_q[1*d_q..2*d_q]);
        unsafe {
            let tq1 = std::slice::from_raw_parts(temp_dest_q[1*d_q..2*d_q].as_ptr(), d_q);
            polymod::add_inplace_p(&mut temp_dest_q[1*d_q..2*d_q], tq1, coeff_count, base_q);
        }
        // Compute c1^2
        polymod::dyadic_product_p(eq1, eq1, coeff_count, base_q, &mut temp_dest_q[2*d_q..3*d_q]);

        let eb0 = &encrypted_Bsk[0*d_Bsk..1*d_Bsk];
        let eb1 = &encrypted_Bsk[1*d_Bsk..2*d_Bsk];
        polymod::dyadic_product_p(eb0, eb0, coeff_count, base_Bsk, &mut temp_dest_Bsk[0*d_Bsk..1*d_Bsk]);
        polymod::dyadic_product_p(eb0, eb1, coeff_count, base_Bsk, &mut temp_dest_Bsk[1*d_Bsk..2*d_Bsk]);
        unsafe {
            let tb1 = std::slice::from_raw_parts(temp_dest_Bsk[1*d_Bsk..2*d_Bsk].as_ptr(), d_Bsk);
            polymod::add_inplace_p(&mut temp_dest_Bsk[1*d_Bsk..2*d_Bsk], tb1, coeff_count, base_Bsk);
        }
        polymod::dyadic_product_p(eb1, eb1, coeff_count, base_Bsk, &mut temp_dest_Bsk[2*d_Bsk..3*d_Bsk]);
        
        // Perform BEHZ step (5): transform data from NTT form
        // Lazy reduction here. The following multiplyPolyScalarCoeffmod will correct the value back to [0, p)
        polymod::intt_ps(&mut temp_dest_q, dest_size, coeff_count, base_q_ntt_tables);
        polymod::intt_ps(&mut temp_dest_Bsk, dest_size, coeff_count, base_Bsk_ntt_tables);

        // Perform BEHZ steps (6)-(8)
        for i in 0..dest_size {
            // Bring together the base q and base Bsk components into a single allocation
            let mut temp_q_Bsk = vec![0; coeff_count * (base_q_size + base_Bsk_size)];
            // Step (6): multiply base q components by t (plain_modulus)
            polymod::multiply_scalar_p(
                &temp_dest_q[i*coeff_count*base_q_size..(i+1)*coeff_count*base_q_size],
                plain_modulus.value(),
                coeff_count,
                base_q,
                &mut temp_q_Bsk[0..coeff_count*base_q_size],
            );
            polymod::multiply_scalar_p(
                &temp_dest_Bsk[i*coeff_count*base_Bsk_size..(i+1)*coeff_count*base_Bsk_size],
                plain_modulus.value(),
                coeff_count,
                base_Bsk,
                &mut temp_q_Bsk[coeff_count*base_q_size..],
            );
            let mut temp_Bsk = vec![0; coeff_count * base_Bsk_size];
            // Step (7): divide by q and floor, producing a result in base Bsk
            rns_tool.fast_floor(&temp_q_Bsk, &mut temp_Bsk);
            // Step (8): use Shenoy-Kumaresan method to convert the result to base q and write to encrypted1
            rns_tool.fastbconv_sk(&temp_Bsk, encrypted.poly_mut(i));
        }
    }

    fn ckks_square(&self, encrypted: &mut Ciphertext) {
        if !encrypted.is_ntt_form() {
            panic!("[Invalid argument] Ciphertexts must be in NTT form");
        }
        
        // Extract encryption parameters.
        let context_data = self.get_context_data(encrypted.parms_id());
        let parms = context_data.parms();
        let coeff_count = parms.poly_modulus_degree();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let encrypted_size = encrypted.size();

        if encrypted_size != 2 {
            self.ckks_multiply(encrypted, &encrypted.clone());
            return;
        }

        // Determine destination.size()
        let dest_size = encrypted_size + encrypted_size - 1;

        encrypted.resize(&self.context, context_data.parms_id(), dest_size);
        let d = coeff_count * coeff_modulus_size;

        unsafe {
            let c0mut = std::slice::from_raw_parts_mut(encrypted.poly_mut(0).as_mut_ptr(), d);
            let c1mut = std::slice::from_raw_parts_mut(encrypted.poly_mut(1).as_mut_ptr(), d);
            let c2mut = std::slice::from_raw_parts_mut(encrypted.poly_mut(2).as_mut_ptr(), d);
            let c0 = std::slice::from_raw_parts(encrypted.poly(0).as_ptr(), d);
            let c1 = std::slice::from_raw_parts(encrypted.poly(1).as_ptr(), d);
            // let c2 = std::slice::from_raw_parts(encrypted.poly(2).as_ptr(), d);
            polymod::dyadic_product_p(c1, c1, coeff_count, coeff_modulus, c2mut);
            polymod::dyadic_product_p(c0, c1, coeff_count, coeff_modulus, c1mut);
            polymod::add_inplace_p(c1mut, c1, coeff_count, coeff_modulus);
            polymod::dyadic_product_p(c0, c0, coeff_count, coeff_modulus, c0mut);
        }

        encrypted.set_scale(encrypted.scale() * encrypted.scale());
        if !Self::is_scale_within_bounds(encrypted.scale(), &context_data) {
            panic!("[Invalid argument] Scale out of bounds");
        }
    }

    fn bgv_square(&self, encrypted: &mut Ciphertext) {
        if encrypted.is_ntt_form() {
            panic!("[Invalid argument] Ciphertexts must not be in NTT form");
        }

        // Extract encryption parameters.
        let context_data = self.get_context_data(encrypted.parms_id());
        let parms = context_data.parms();
        let coeff_count = parms.poly_modulus_degree();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let encrypted_size = encrypted.size();
        let ntt_table = context_data.small_ntt_tables();

        if encrypted_size != 2 {
            self.bgv_multiply(encrypted, &encrypted.clone());
            return;
        }

        let dest_size = encrypted_size + encrypted_size - 1;
        
        encrypted.resize(&self.context, context_data.parms_id(), dest_size);
        
        polymod::ntt_ps(encrypted.polys_mut(0, encrypted_size), encrypted_size, coeff_count, ntt_table);
        
        let mut temp = vec![0; dest_size * coeff_count * coeff_modulus_size];
        let d_q = coeff_count * coeff_modulus_size;

        // Compute c0^2
        unsafe {
            let eq0 = &encrypted.data()[0*d_q..1*d_q];
            let eq1 = &encrypted.data()[1*d_q..2*d_q];
            polymod::dyadic_product_p(eq0, eq0, coeff_count, coeff_modulus, &mut temp[0*d_q..1*d_q]);
            // Compute 2*c0*c1
            polymod::dyadic_product_p(eq0, eq1, coeff_count, coeff_modulus, &mut temp[1*d_q..2*d_q]);
            let tq1 = std::slice::from_raw_parts(temp[1*d_q..2*d_q].as_ptr(), d_q);
            polymod::add_inplace_p(&mut temp[1*d_q..2*d_q], tq1, coeff_count, coeff_modulus);
            // Compute c1^2
            polymod::dyadic_product_p(eq1, eq1, coeff_count, coeff_modulus, &mut temp[2*d_q..3*d_q]);
        }

        encrypted.polys_mut(0, dest_size).copy_from_slice(&temp);
        polymod::intt_ps(encrypted.data_mut(), dest_size, coeff_count, ntt_table);
        encrypted.set_correction_factor(
            util::multiply_u64_mod(
                encrypted.correction_factor(), 
                encrypted.correction_factor(), 
                parms.plain_modulus()
            )
        );
    }

    /// See [Evaluator::square].
    pub fn square_inplace(&self, encrypted: &mut Ciphertext) {
        self.check_ciphertext(encrypted); // Verify parameters
        let scheme = self.context.first_context_data().unwrap().parms().scheme();
        match scheme {
            SchemeType::BFV => self.bfv_square(encrypted),
            SchemeType::CKKS => self.ckks_square(encrypted),
            SchemeType::BGV => self.bgv_square(encrypted),
            _ => panic!("[Invalid argument] Unsupported scheme")
        }
    }

    /// Square a ciphertext. The result is not relinearized.
    /// 
    /// # BFV/BGV example
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Evaluator};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let plain_modulus = params.plain_modulus().value();
    /// let message = vec![1, 2, 3, 4];
    /// let mut encrypted = encryptor.encrypt_new(&encoder.encode_new(&message));
    /// evaluator.square_inplace(&mut encrypted);
    /// assert_eq!(encrypted.size(), 3);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted));
    /// for i in 0..4 {assert_eq!(result[i], message[i] * message[i]);}
    /// ```
    /// 
    /// # CKKS example
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(8192, vec![60, 60, 60]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let message = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    /// let mut encrypted = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message, None, (1u64<<40) as f64));
    /// evaluator.square_inplace(&mut encrypted);
    /// assert_eq!(encrypted.size(), 3);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted));
    /// for i in 0..2 {assert!((result[i] - (message[i] * message[i])).norm() < 1e-3);}
    pub fn square(&self, encrypted: &Ciphertext, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.square_inplace(destination);
    }

    /// See [Evaluator::square].
    pub fn square_new(&self, encrypted: &Ciphertext) -> Ciphertext {
        let mut result = encrypted.clone();
        self.square_inplace(&mut result);
        result
    }

    /// See [Evaluator::apply_keyswitching].
    pub fn apply_keyswitching_inplace(&self, encrypted: &mut Ciphertext, keyswitching_key: &KSwitchKeys) {
        assert_eq!(keyswitching_key.data().len(), 1);
        assert_eq!(encrypted.size(), 2);
        // due to the semantics of `switch_key_inplace_internal`, we should first get the c0 out
        // and then clear the original c0 in the encrypted.
        let target = encrypted.poly(1).to_vec();
        encrypted.poly_mut(1).fill(0);
        self.switch_key_inplace_internal(encrypted, &target, keyswitching_key, 0)
    }

    /// Apply keyswitching to another secret key.
    pub fn apply_keyswitching(&self, encrypted: &Ciphertext, keyswitching_key: &KSwitchKeys, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.apply_keyswitching_inplace(destination, keyswitching_key);
    }

    /// See [Evaluator::apply_keyswitching].
    pub fn apply_keyswitching_new(&self, encrypted: &Ciphertext, keyswitching_key: &KSwitchKeys) -> Ciphertext {
        let mut destination = encrypted.clone();
        self.apply_keyswitching_inplace(&mut destination, keyswitching_key);
        destination
    }

    /// Suppose kswitch_keys[kswitch_kes_index] is generated with s' on a KeyGenerator of secret key s.
    /// Then the semantic of this function is as follows: `target` is supposed to multiply with s' to contribute to the
    /// decrypted result, now we apply this function, to decompose (target * s') into (c0, c1) such that c0 + c1 * s = target * s.
    /// And then we add c0, c1 to the original c0, c1 in the `encrypted`.
    fn switch_key_inplace_internal(&self, encrypted: &mut Ciphertext, target: &[u64], kswitch_keys: &KSwitchKeys, kswitch_kes_index: usize) {
        self.check_ciphertext(encrypted);
        if !self.context.using_keyswitching() {
            panic!("[Invalid argument] Key switching is not supported");
        }
        if kswitch_keys.parms_id() != self.context.key_parms_id() {
            panic!("[Invalid argument] Key switch keys parms mismatch");
        }
        if kswitch_kes_index >= kswitch_keys.data().len() {
            panic!("[Out of range] Key switch keys index out of range");
        }

        let parms_id = encrypted.parms_id();
        let context_data = self.get_context_data(parms_id);
        let parms = context_data.parms();
        let key_context_data = self.context.key_context_data().unwrap();
        let key_parms = key_context_data.parms();
        let scheme = parms.scheme();
        match scheme {
            SchemeType::BFV | SchemeType::BGV => {
                if encrypted.is_ntt_form() {
                    panic!("[Invalid argument] Ciphertexts must not be in NTT form");
                }
            },
            SchemeType::CKKS => {
                if !encrypted.is_ntt_form() {
                    panic!("[Invalid argument] Ciphertexts must be in NTT form");
                }
            },
            _ => panic!("[Invalid argument] Unsupported scheme")
        }

        let coeff_count = parms.poly_modulus_degree();
        let decomp_modulus_size = parms.coeff_modulus().len();
        let key_modulus = key_parms.coeff_modulus();
        let key_modulus_size = key_modulus.len();
        let rns_modulus_size = decomp_modulus_size + 1;
        let key_ntt_tables = key_context_data.small_ntt_tables();
        let modswitch_factors = key_context_data.rns_tool().inv_q_last_mod_q();
    
        let key_vector = &kswitch_keys.data()[kswitch_kes_index];
        let key_component_count = key_vector[0].as_ciphertext().size();
        for key in key_vector {
            if !key.is_valid_for(&self.context) {
                panic!("[Invalid argument] Switch keys not valid for encryption parameters");
            }
        }

        let mut target_copied = target.to_vec();
        assert_eq!(target.len(), decomp_modulus_size * coeff_count);

        // In CKKS target is in NTT form; switch back to normal form
        if scheme == SchemeType::CKKS {
            polymod::intt_p(&mut target_copied, coeff_count, &key_ntt_tables[..decomp_modulus_size]);
        }
        
        // Temporary result
        let mut poly_prod = vec![0; key_component_count * coeff_count * rns_modulus_size];
        let mut poly_lazy = vec![0; key_component_count * coeff_count * 2];
        let mut temp_ntt = vec![0; coeff_count];
        for i in 0..rns_modulus_size {
            let key_index =  if i == decomp_modulus_size {key_modulus_size - 1} else {i};

            // Product of two numbers is up to 60 + 60 = 120 bits, so we can sum up to 256 of them without reduction.
            let lazy_reduction_summand_bound = util::HE_MULTIPLY_ACCUMULATE_USER_MOD_MAX;
            let mut lazy_reduction_counter = lazy_reduction_summand_bound;

            // Allocate memory for a lazy accumulator (128-bit coefficients)
            poly_lazy.fill(0);
            let poly_coeff_count = 2 * coeff_count;

            // Multiply with keys and perform lazy reduction on product's coefficients
            temp_ntt.fill(0);
            for j in 0..decomp_modulus_size {
                let temp_operand = if (scheme == SchemeType::CKKS) && (i == j) {
                    &target[j * coeff_count..(j + 1) * coeff_count]
                } else {
                    if key_modulus[j] <= key_modulus[key_index] {
                        temp_ntt.copy_from_slice(&target_copied[j * coeff_count..(j + 1) * coeff_count])
                    } else {
                        polymod::modulo(&target_copied[j * coeff_count..(j + 1) * coeff_count], &key_modulus[key_index], &mut temp_ntt);
                    }
                    polymod::ntt_lazy(&mut temp_ntt, &key_ntt_tables[key_index]);
                    &temp_ntt
                };
                
                // Multiply with keys and modular accumulate products in a lazy fashion
                let mut qword = [0; 2];
                for k in 0..key_component_count {
                    let key_vector_jk_offset = key_vector[j].as_ciphertext().poly_component(k, key_index);
                    let accumulator = &mut poly_lazy[k*poly_coeff_count..(k+1)*poly_coeff_count];
                    if lazy_reduction_counter == 0 {
                        for (l, (accumulator_l, temp_operand)) in accumulator.chunks_mut(2).zip(temp_operand.iter()).enumerate() {
                            util::multiply_u64_u64(*temp_operand, key_vector_jk_offset[l], &mut qword);
                            accumulator_l[0] = util::barrett_reduce_u128(&qword, &key_modulus[key_index]);
                            accumulator_l[1] = 0;
                        }
                    } else {
                        for (l, (accumulator_l, temp_operand)) in accumulator.chunks_mut(2).zip(temp_operand.iter()).enumerate() {
                            util::multiply_u64_u64(*temp_operand, key_vector_jk_offset[l], &mut qword);
                            util::add_u128_inplace(&mut qword, accumulator_l);
                            accumulator_l[0] = qword[0];
                            accumulator_l[1] = qword[1];
                        }
                    }
                }
                lazy_reduction_counter -= 1;
                if lazy_reduction_counter == 0 {
                    lazy_reduction_counter = lazy_reduction_summand_bound;
                }

                let poly_prod_i = &mut poly_prod[i * coeff_count..];
                // Final modular reduction
                for (k, accumulator) in poly_lazy.chunks(poly_coeff_count).enumerate() {
                    let poly_prod_i = &mut poly_prod_i[k * coeff_count * rns_modulus_size..k * coeff_count * rns_modulus_size + coeff_count];
                    if lazy_reduction_counter == lazy_reduction_summand_bound {
                        for (_l, (accumulator_l, poly_prod_i)) in accumulator.chunks(2).zip(poly_prod_i.iter_mut()).enumerate() {
                            *poly_prod_i = accumulator_l[0];
                        }
                    } else {
                        for (_l, (accumulator_l, poly_prod_i)) in accumulator.chunks(2).zip(poly_prod_i.iter_mut()).enumerate() {
                            *poly_prod_i = util::barrett_reduce_u128(accumulator_l, &key_modulus[key_index]);
                        }
                    }
                }
            }
        } // i

        let mut k = vec![0; coeff_count];
        let mut delta = vec![0; coeff_count];
        let mut c_mod_qi = vec![0; coeff_count];
        let mut temp_ntt = vec![0; coeff_count];
        for i in 0..key_component_count {
            if scheme == SchemeType::BGV {
                let plain_modulus = parms.plain_modulus();
                let qk = key_modulus[key_modulus_size - 1].value();
                let qk_inv_qp = key_context_data.rns_tool().inv_q_last_mod_t();
                // Lazy reduction; this needs to be then reduced mod qi
                let t_last = unsafe {
                    let t_last_offset = coeff_count * rns_modulus_size * i + decomp_modulus_size * coeff_count;
                    std::slice::from_raw_parts_mut(poly_prod.as_mut_ptr().add(t_last_offset), coeff_count) 
                };
                polymod::intt(t_last, &key_ntt_tables[key_modulus_size - 1]);
                polymod::modulo(t_last, plain_modulus, &mut k);
                polymod::negate_inplace(&mut k, plain_modulus);
                if qk_inv_qp != 1 {
                    polymod::multiply_scalar_inplace(&mut k, qk_inv_qp, plain_modulus);
                }
                for j in 0..decomp_modulus_size {
                    let poly_prod_component = {
                        let poly_prod_index = i * coeff_count * rns_modulus_size + j * coeff_count;
                        &mut poly_prod[poly_prod_index..poly_prod_index + coeff_count]
                    };
                    polymod::intt(poly_prod_component, &key_ntt_tables[j]);
                    // delta = k mod q_i
                    polymod::modulo(&k, &key_modulus[j], &mut delta);
                    // delta = k * q_k mod q_i
                    polymod::multiply_scalar_inplace(&mut delta, qk, &key_modulus[j]);
                    
                    // c mod q_i
                    polymod::modulo(t_last, &key_modulus[j], &mut c_mod_qi);
                    // delta = c + k * q_k mod q_i
                    // c_{i} = c_{i} - delta mod q_i
                    let lqi = key_modulus[j].value() * 2;
                    for k in 0..coeff_count {
                        poly_prod_component[k] += lqi - (delta[k] + c_mod_qi[k]);
                    }
                    polymod::multiply_operand_inplace(
                        poly_prod_component, 
                        &modswitch_factors[j], &key_modulus[j]);
                    polymod::add_inplace(
                        encrypted.poly_component_mut(i, j), 
                        poly_prod_component, 
                        &key_modulus[j]);
                }
            } else {
                // Lazy reduction; this needs to be then reduced mod qi
                let t_last = unsafe {
                    let t_last_offset = coeff_count * rns_modulus_size * i + decomp_modulus_size * coeff_count;
                    std::slice::from_raw_parts_mut(poly_prod.as_mut_ptr().add(t_last_offset), coeff_count) 
                };
                polymod::intt_lazy(t_last, &key_ntt_tables[key_modulus_size - 1]);
                // Add (p-1)/2 to change from flooring to rounding.
                let qk = key_modulus[key_modulus_size - 1].value();
                let qk_half = qk >> 1;
                for j in 0..coeff_count {
                    t_last[j] = key_modulus[key_modulus_size - 1].reduce(t_last[j] + qk_half);
                }
                for j in 0..decomp_modulus_size {
                    let poly_prod_component = {
                        let poly_prod_index = i * coeff_count * rns_modulus_size + j * coeff_count;
                        &mut poly_prod[poly_prod_index..poly_prod_index + coeff_count]
                    };
                    let qi = key_modulus[j].value();
                    if qk > qi {
                        polymod::modulo(t_last, &key_modulus[j], &mut temp_ntt);
                    } else {
                        temp_ntt.copy_from_slice(t_last);
                    }
                    let fix = qi - key_modulus[j].reduce(qk_half);
                    for k in 0..coeff_count {temp_ntt[k] += fix;}
                    let mut qi_lazy = qi << 1;
                    if scheme == SchemeType::CKKS {
                        polymod::ntt_lazy(&mut temp_ntt, &key_ntt_tables[j]);
                        qi_lazy = qi << 2;
                    } else {
                        polymod::intt_lazy(poly_prod_component, &key_ntt_tables[j]);
                    }
                    for k in 0..coeff_count {
                        poly_prod_component[k] += qi_lazy - temp_ntt[k];
                    }
                    polymod::multiply_operand_inplace(
                        poly_prod_component, 
                        &modswitch_factors[j], &key_modulus[j]);
                    polymod::add_inplace(
                        encrypted.poly_component_mut(i, j), 
                        poly_prod_component, 
                        &key_modulus[j]);
                }
            }
        }
    }

    fn relinearize_internal(&self, encrypted: &mut Ciphertext, relin_keys: &RelinKeys, destination_size: usize) {
        self.check_ciphertext(encrypted);
        self.check_public_key(relin_keys);
        let context_data = self.context.get_context_data(encrypted.parms_id());
        if context_data.is_none() {
            panic!("[Invalid argument] Encryption parameters are not valid for encryption context");
        }
        let context_data = context_data.unwrap();
        if relin_keys.parms_id() != self.context.key_parms_id() {
            panic!("[Invalid argument] Relinearization keys are not valid for encryption context");
        }
        let mut encrypted_size = encrypted.size();
        if encrypted_size < 2 || destination_size > encrypted_size {
            panic!("[Invalid argument] Destination size must be at least 2 and less/equal to the size of the encrypted polynomial");
        }
        if destination_size == encrypted_size {
            return;
        }
        let relins_needed = encrypted_size - destination_size;
        for _i in 0..relins_needed {
            let target = unsafe {
                let last_poly = encrypted.poly(encrypted_size - 1);
                std::slice::from_raw_parts(last_poly.as_ptr(), last_poly.len())
            };
            self.switch_key_inplace_internal(encrypted, target, relin_keys.as_kswitch_keys(), RelinKeys::get_index(encrypted_size - 1));
            encrypted_size -= 1;
        }
        encrypted.resize(&self.context, context_data.parms_id(), destination_size);
    }

    /// See [Evaluator::relinearize].
    pub fn relinearize_inplace(&self, encrypted: &mut Ciphertext, relin_keys: &RelinKeys) {
        self.relinearize_internal(encrypted, relin_keys, 2);
    }

    /// Relinearizes a ciphertext to 2 polynomials.
    /// 
    /// # BFV/BGV example
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Evaluator};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let relin_keys = keygen.create_relin_keys(false);
    /// let plain_modulus = params.plain_modulus().value();
    /// let message1 = vec![1, 2, 3, 4];
    /// let message2 = vec![5, 6, 7, 8];
    /// let mut encrypted1 = encryptor.encrypt_new(&encoder.encode_new(&message1));
    /// let     encrypted2 = encryptor.encrypt_new(&encoder.encode_new(&message2));
    /// evaluator.multiply_inplace(&mut encrypted1, &encrypted2);
    /// assert_eq!(encrypted1.size(), 3);
    /// evaluator.relinearize_inplace(&mut encrypted1, &relin_keys);
    /// assert_eq!(encrypted1.size(), 2);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..4 {assert_eq!(result[i], message1[i] * message2[i]);}
    /// ```
    /// 
    /// # CKKS example
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(8192, vec![60, 60, 60]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let relin_keys = keygen.create_relin_keys(false);
    /// let message1 = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    /// let message2 = vec![Complex::new(5.0, 6.0), Complex::new(7.0, 8.0)];
    /// let mut encrypted1 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message1, None, (1u64<<40) as f64));
    /// let     encrypted2 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message2, None, (1u64<<40) as f64));
    /// evaluator.multiply_inplace(&mut encrypted1, &encrypted2);
    /// assert_eq!(encrypted1.size(), 3);
    /// evaluator.relinearize_inplace(&mut encrypted1, &relin_keys);
    /// assert_eq!(encrypted1.size(), 2);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..2 {assert!((result[i] - (message1[i] * message2[i])).norm() < 1e-3);}
    #[inline]
    pub fn relinearize(&self, encrypted: &Ciphertext, relin_keys: &RelinKeys, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.relinearize_inplace(destination, relin_keys)
    }

    /// See [Evaluator::relinearize].
    #[inline]
    pub fn relinearize_new(&self, encrypted: &Ciphertext, relin_keys: &RelinKeys) -> Ciphertext {
        let mut result = encrypted.clone();
        self.relinearize_inplace(&mut result, relin_keys);
        result
    }

    fn mod_switch_scale_to_next_internal(&self, encrypted: &Ciphertext, destination: &mut Ciphertext) {
        // Assuming at this point encrypted is already validated.
        let parms_id = encrypted.parms_id();
        let context_data = self.get_context_data(parms_id);
        let parms = context_data.parms();
        let scheme = parms.scheme();
        match scheme {
            SchemeType::BFV | SchemeType::BGV => {
                if encrypted.is_ntt_form() {
                    panic!("[Invalid argument] Ciphertexts must not be in NTT form");
                }
            },
            SchemeType::CKKS => {
                if !encrypted.is_ntt_form() {
                    panic!("[Invalid argument] Ciphertexts must be in NTT form");
                }
            },
            _ => panic!("[Invalid argument] Unsupported scheme")
        }
        let next_context_data = context_data.next_context_data();
        if next_context_data.is_none() {
            panic!("[Invalid argument] Cannot mod switch to next level");
        }
        let next_context_data = next_context_data.unwrap();
        let next_parms = next_context_data.parms();
        let rns_tool = context_data.rns_tool();

        let encrypted_size = encrypted.size();
        let coeff_count = next_parms.poly_modulus_degree();
        let next_coeff_modulus_size = next_parms.coeff_modulus().len();

        let mut encrypted_copy = encrypted.clone();
        match scheme {
            SchemeType::BFV => {
                for i in 0..encrypted_size {rns_tool.divide_and_round_q_last_inplace(encrypted_copy.poly_mut(i));}
            },
            SchemeType::CKKS => {
                for i in 0..encrypted_size {rns_tool.divide_and_round_q_last_ntt_inplace(encrypted_copy.poly_mut(i), context_data.small_ntt_tables());}
            },
            SchemeType::BGV => {
                for i in 0..encrypted_size {rns_tool.mod_t_and_divide_q_last_inplace(encrypted_copy.poly_mut(i));}
            },
            _ => unreachable!()
        }

        destination.resize(&self.context, next_context_data.parms_id(), encrypted_size);
        for i in 0..encrypted_size {
            destination.poly_mut(i).copy_from_slice(&encrypted_copy.poly(i)[..coeff_count * next_coeff_modulus_size]);
        }

        destination.set_is_ntt_form(encrypted.is_ntt_form());
        if scheme == SchemeType::CKKS {
            destination.set_scale(encrypted.scale() / parms.coeff_modulus().last().unwrap().value() as f64);
        } else if scheme == SchemeType::BGV {
            destination.set_correction_factor(util::multiply_u64_mod(
                encrypted.correction_factor(), rns_tool.inv_q_last_mod_t(), next_parms.plain_modulus()
            ));
        }
    }

    fn mod_switch_drop_to_next_internal(&self, encrypted: &Ciphertext, destination: &mut Ciphertext) {
        // Assuming at this point encrypted is already validated.
        let context_data = self.get_context_data(encrypted.parms_id());
        let parms = context_data.parms();
        let scheme = parms.scheme();
        if scheme == SchemeType::CKKS && !encrypted.is_ntt_form() {
            panic!("[Invalid argument] Ciphertexts must be in NTT form");
        }
        let next_context_data = context_data.next_context_data();
        if next_context_data.is_none() {
            panic!("[Invalid argument] Cannot mod switch to next level");
        }
        let next_context_data = next_context_data.unwrap();
        let next_parms = next_context_data.parms();
        if !Self::is_scale_within_bounds(encrypted.scale(), &next_context_data) {
            panic!("[Invalid argument] Scale is out of bounds");
        }
        let encrypted_size = encrypted.size();
        let coeff_count = next_parms.poly_modulus_degree();
        let next_coeff_modulus_size = next_parms.coeff_modulus().len();
        destination.resize(&self.context, next_context_data.parms_id(), encrypted.size());
        for i in 0..encrypted_size {
            destination.poly_mut(i).copy_from_slice(&encrypted.poly(i)[..coeff_count * next_coeff_modulus_size]);
        }
        destination.set_is_ntt_form(encrypted.is_ntt_form());
        destination.set_scale(encrypted.scale());
        destination.set_correction_factor(encrypted.correction_factor());
    }

    fn mod_switch_drop_to_next_plain_internal(&self, plain: &mut Plaintext) {
        // Assuming at this point encrypted is already validated.
        if !plain.is_ntt_form() {
            panic!("[Invalid argument] Plaintexts must be in NTT form");
        }
        let context_data = self.get_context_data(plain.parms_id());
        let next_context_data = context_data.next_context_data();
        if next_context_data.is_none() {
            panic!("[Invalid argument] Cannot mod switch to next level");
        }
        let next_context_data = next_context_data.unwrap();
        let next_parms = next_context_data.parms();
        if !Self::is_scale_within_bounds(plain.scale(), &next_context_data) {
            panic!("[Invalid argument] Scale is out of bounds");
        }
        let coeff_count = next_parms.poly_modulus_degree();
        let next_coeff_modulus_size = next_parms.coeff_modulus().len();
        let dest_size = coeff_count * next_coeff_modulus_size;
        plain.set_parms_id(PARMS_ID_ZERO);
        plain.resize(dest_size);
        plain.set_parms_id(*next_context_data.parms_id());
    }

    /// Modulus switches the given ciphertext to the next level in the modulus switching chain.
    /// Note that for CKKS scheme, this function does not rescale.
    /// To rescale to the next level, see [Evaluator::rescale_to_next].

    /// Relinearizes a ciphertext to 2 polynomials.
    /// 
    /// # BFV/BGV example
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Evaluator};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let plain_modulus = params.plain_modulus().value();
    /// let message1 = vec![1, 2, 3, 4];
    /// let message2 = vec![5, 6, 7, 8];
    /// let mut encrypted1 = encryptor.encrypt_new(&encoder.encode_new(&message1));
    /// let     encrypted2 = encryptor.encrypt_new(&encoder.encode_new(&message2));
    /// evaluator.multiply_inplace(&mut encrypted1, &encrypted2);
    /// assert_eq!(encrypted1.size(), 3);
    /// evaluator.mod_switch_to_next_inplace(&mut encrypted1);
    /// assert_eq!(encrypted1.size(), 3);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..4 {assert_eq!(result[i], message1[i] * message2[i]);}
    /// ```
    /// 
    /// # CKKS example
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(8192, vec![30, 30, 30, 30, 30]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let message1 = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    /// let message2 = vec![Complex::new(5.0, 6.0), Complex::new(7.0, 8.0)];
    /// let mut encrypted1 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message1, None, (1u64<<30) as f64));
    /// let     encrypted2 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message2, None, (1u64<<30) as f64));
    /// evaluator.multiply_inplace(&mut encrypted1, &encrypted2);
    /// assert_eq!(encrypted1.size(), 3);
    /// evaluator.mod_switch_to_next_inplace(&mut encrypted1);
    /// assert_eq!(encrypted1.size(), 3);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..2 {assert!((result[i] - (message1[i] * message2[i])).norm() < 1e-3);}
    pub fn mod_switch_to_next(&self, encrypted: &Ciphertext, destination: &mut Ciphertext) {
        self.check_ciphertext(encrypted);
        if self.context.last_parms_id() == encrypted.parms_id() {
            // println!("last parms id = {}, this parms id = {}, encrypted size = {}", self.context.last_parms_id(), encrypted.parms_id(), encrypted.size());
            panic!("[Invalid argument] End of modulus switching chain reached");
        }
        match self.context.first_context_data().unwrap().parms().scheme() {
            SchemeType::BFV => self.mod_switch_scale_to_next_internal(encrypted, destination),
            SchemeType::CKKS => self.mod_switch_drop_to_next_internal(encrypted, destination),
            SchemeType::BGV => self.mod_switch_scale_to_next_internal(encrypted, destination),
            _ => panic!("[Invalid argument] Unsupported scheme")
        }
    }

    /// See [Evaluator::mod_switch_to_next].
    pub fn mod_switch_to_next_inplace(&self, encrypted: &mut Ciphertext) {
        let cloned = encrypted.clone();
        self.mod_switch_to_next(&cloned, encrypted);
    }

    /// See [Evaluator::mod_switch_to_next].
    pub fn mod_switch_to_next_new(&self, encrypted: &Ciphertext) -> Ciphertext {
        let mut result = Ciphertext::new();
        self.mod_switch_to_next(encrypted, &mut result);
        result
    }

    /// Modulus switches the given plaintext to the next level in the modulus switching chain.
    /// Similar to [Evaluator::mod_switch_to_next], but this function operates on plaintexts.
    pub fn mod_switch_to_next_plain(&self, plain: &Plaintext, destination: &mut Plaintext) {
        self.check_plaintext(plain);
        *destination = plain.clone();
        self.mod_switch_drop_to_next_plain_internal(destination);
    }

    /// See [Evaluator::mod_switch_to_next_plain].
    pub fn mod_switch_to_next_plain_inplace(&self, plain: &mut Plaintext) {
        self.check_plaintext(plain);
        self.mod_switch_drop_to_next_plain_internal(plain);
    }

    /// See [Evaluator::mod_switch_to_next_plain].
    pub fn mod_switch_to_next_plain_new(&self, plain: &Plaintext) -> Plaintext {
        let mut result = plain.clone();
        self.mod_switch_drop_to_next_plain_internal(&mut result);
        result
    }

    /// See [Evaluator::mod_switch_to].
    pub fn mod_switch_to_inplace(&self, encrypted: &mut Ciphertext, parms_id: &ParmsID) {
        let context_data = self.get_context_data(encrypted.parms_id());
        let target_context_data = self.get_context_data(parms_id);
        if context_data.chain_index() < target_context_data.chain_index() {
            panic!("[Invalid argument] Cannot mod switch to a higher level");
        }
        while encrypted.parms_id() != parms_id {
            self.mod_switch_to_next_inplace(encrypted);
        }
    }

    /// Modulus switches the given ciphertext to the given level in the modulus switching chain.
    /// Similar to [Evaluator::mod_switch_to_next], but this function specifies
    /// the level, rather than switch to the next level.
    pub fn mod_switch_to(&self, encrypted: &Ciphertext, parms_id: &ParmsID, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.mod_switch_to_inplace(destination, parms_id);
    }

    /// See [Evaluator::mod_switch_to].
    pub fn mod_switch_to_new(&self, encrypted: &Ciphertext, parms_id: &ParmsID) -> Ciphertext {
        let mut result = encrypted.clone();
        self.mod_switch_to_inplace(&mut result, parms_id);
        result
    }

    /// See [Evaluator::mod_switch_plain_to].
    pub fn mod_switch_plain_to_inplace(&self, plain: &mut Plaintext, parms_id: &ParmsID) {
        if !plain.is_ntt_form() {
            panic!("[Invalid argument] Plaintexts must be in NTT form");
        }
        let context_data = self.get_context_data(plain.parms_id());
        let target_context_data = self.get_context_data(parms_id);
        if context_data.chain_index() < target_context_data.chain_index() {
            panic!("[Invalid argument] Cannot mod switch to a higher level");
        }
        while plain.parms_id() != parms_id {
            self.mod_switch_to_next_plain_inplace(plain);
        }
    }

    /// Modulus switches the given plaintext to the given level in the modulus switching chain.
    /// Similar to [Evaluator::mod_switch_to_next_plain], but this function specifies
    /// the level, rather than switch to the next level.
    pub fn mod_switch_plain_to(&self, plain: &Plaintext, parms_id: &ParmsID, destination: &mut Plaintext) {
        *destination = plain.clone();
        self.mod_switch_plain_to_inplace(destination, parms_id);
    }

    /// See [Evaluator::mod_switch_plain_to].
    pub fn mod_switch_plain_to_new(&self, plain: &Plaintext, parms_id: &ParmsID) -> Plaintext {
        let mut result = plain.clone();
        self.mod_switch_plain_to_inplace(&mut result, parms_id);
        result
    }

    /// Rescale the ciphertext to the next level in the modulus switching chain.
    /// Only works for CKKS scheme.
    /// 
    /// # CKKS example
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(8192, vec![30, 30, 30, 30]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let message1 = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    /// let message2 = vec![Complex::new(5.0, 6.0), Complex::new(7.0, 8.0)];
    /// let mut encrypted1 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message1, None, (1u64<<30) as f64));
    /// let     encrypted2 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message2, None, (1u64<<30) as f64));
    /// evaluator.multiply_inplace(&mut encrypted1, &encrypted2);
    /// assert_eq!(encrypted1.size(), 3);
    /// evaluator.rescale_to_next_inplace(&mut encrypted1);
    /// assert_eq!(encrypted1.size(), 3);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..2 {assert!((result[i] - (message1[i] * message2[i])).norm() < 1e-3);}
    pub fn rescale_to_next(&self, encrypted: &Ciphertext, destination: &mut Ciphertext) {
        self.check_ciphertext(encrypted);
        if self.context.last_parms_id() == encrypted.parms_id() {
            panic!("[Invalid argument] End of modulus switching chain reached");
        }
        match self.context.first_context_data().unwrap().parms().scheme() {
            SchemeType::BFV | SchemeType::BGV => 
                panic!("[Invalid argument] Rescale is only supported for CKKS scheme"),
            SchemeType::CKKS => self.mod_switch_scale_to_next_internal(encrypted, destination),
            _ => panic!("[Invalid argument] Unsupported scheme")
        }
    }

    /// See [Evaluator::rescale_to_next].
    pub fn rescale_to_next_inplace(&self, encrypted: &mut Ciphertext) {
        let cloned = encrypted.clone();
        self.rescale_to_next(&cloned, encrypted);
    }

    /// See [Evaluator::rescale_to_next].
    pub fn rescale_to_next_new(&self, encrypted: &Ciphertext) -> Ciphertext {
        let mut result = Ciphertext::new();
        self.rescale_to_next(encrypted, &mut result);
        result
    }
    
    /// Rescale the ciphertext to the specified level in the modulus switching chain.
    /// Only works for CKKS scheme. Similar to [Evaluator::rescale_to_next], but this function specifies
    /// the level, rather than rescale to the next level.
    pub fn rescale_to(&self, encrypted: &Ciphertext, parms_id: &ParmsID, destination: &mut Ciphertext) {
        self.check_ciphertext(encrypted);
        if self.context.last_parms_id() == encrypted.parms_id() {
            panic!("[Invalid argument] End of modulus switching chain reached");
        }
        match self.context.first_context_data().unwrap().parms().scheme() {
            SchemeType::BFV | SchemeType::BGV => 
                panic!("[Invalid argument] Rescale is only supported for CKKS scheme"),
            SchemeType::CKKS => 
                while encrypted.parms_id() != parms_id {
                    self.mod_switch_scale_to_next_internal(encrypted, destination);
                },
            _ => panic!("[Invalid argument] Unsupported scheme")
        }
    }

    /// See [Evaluator::rescale_to].
    pub fn rescale_to_inplace(&self, encrypted: &mut Ciphertext, parms_id: &ParmsID) {
        let cloned = encrypted.clone();
        self.rescale_to(&cloned, parms_id, encrypted);
    }

    /// See [Evaluator::rescale_to].
    pub fn rescale_to_new(&self, encrypted: &Ciphertext, parms_id: &ParmsID) -> Ciphertext {
        let mut result = Ciphertext::new();
        self.rescale_to(encrypted, parms_id, &mut result);
        result
    }

    /// **This function is not tested.**
    /// It is recommended to use [Evaluator::multiply] and arrange
    /// the multiplication order manually.
    #[cold]
    pub fn multiply_many(&self, operands: &[Ciphertext], relin_keys: &RelinKeys, destination: &mut Ciphertext) {
        if operands.is_empty() {
            panic!("[Invalid argument] Operands cannot be empty");
        }
        let context_data = self.get_context_data(operands[0].parms_id());
        let parms = context_data.parms();
        if parms.scheme() != SchemeType::BFV && parms.scheme() != SchemeType::BGV {
            panic!("[Invalid argument] Can only do multiply_many for BGV/BFV scheme");
        }
        if operands.len() == 1 {
            *destination = operands[0].clone();
            return;
        }
        let mut product_vec = vec![];
        let mut i = 0;
        while i < operands.len() {
            let mut product = Ciphertext::new();
            self.multiply(&operands[i], &operands[i + 1], &mut product);
            self.relinearize_inplace(&mut product, relin_keys);
            product_vec.push(product);
            i += 2;
        }
        if operands.len() % 2 == 1 {
            product_vec.push(operands[operands.len() - 1].clone());
        }
        i = 0;
        while i < product_vec.len() - 1 {
            let mut product = Ciphertext::new();
            self.multiply(&product_vec[i], &product_vec[i + 1], &mut product);
            self.relinearize_inplace(&mut product, relin_keys);
            product_vec[i] = product;
            i += 2;
        }
        *destination = product_vec[product_vec.len() - 1].clone();
    }

    /// See [Evaluator::add_plain].
    pub fn add_plain_inplace(&self, encrypted: &mut Ciphertext, plain: &Plaintext) {
        self.check_ciphertext(encrypted);
        self.check_plaintext(plain);
        let context_data = self.get_context_data(encrypted.parms_id());
        let parms = context_data.parms();
        let scheme = parms.scheme();
        match scheme {
            SchemeType::BFV | SchemeType::BGV => {
                if encrypted.is_ntt_form() {
                    panic!("[Invalid argument] Ciphertexts must not be in NTT form");
                }
            },
            SchemeType::CKKS => {
                if !encrypted.is_ntt_form() {
                    panic!("[Invalid argument] Ciphertexts must be in NTT form");
                }
                if !util::are_close_f64(encrypted.scale(), plain.scale()) {
                    panic!("[Invalid argument] Ciphertext and plaintext scales do not match");
                }
            },
            _ => panic!("[Invalid argument] Unsupported scheme")
        }
        if encrypted.is_ntt_form() != plain.is_ntt_form() {
            panic!("[Invalid argument] Ciphertext and plaintext NTT form mismatch");
        }
        let coeff_count = parms.poly_modulus_degree();
        let coeff_modulus = parms.coeff_modulus();

        match scheme {
            SchemeType::BFV => {
                util::scaling_variant::multiply_add_plain(plain, &context_data, encrypted.poly_mut(0));
            },
            SchemeType::CKKS => {
                polymod::add_inplace_p(encrypted.poly_mut(0), plain.data(), coeff_count, coeff_modulus);
            },
            SchemeType::BGV => {
                let mut plain_copy = plain.clone();
                polymod::multiply_scalar(plain.data(), encrypted.correction_factor(), parms.plain_modulus(), plain_copy.data_mut());
                util::scaling_variant::add_plain(&plain_copy, &context_data, encrypted.poly_mut(0));
            },
            _ => panic!("[Invalid argument] Unsupported scheme")
        }
    }


    /// Add a ciphertext with a plaintext.
    /// 
    /// # BFV/BGV example
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Evaluator};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let plain_modulus = params.plain_modulus().value();
    /// let message1 = vec![1, 2, 3, 4];
    /// let message2 = vec![5, 6, 7, 8];
    /// let mut encrypted1 = encryptor.encrypt_new(&encoder.encode_new(&message1));
    /// let         plain2 = encoder.encode_new(&message2);
    /// evaluator.add_plain_inplace(&mut encrypted1, &plain2);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..4 {assert_eq!(result[i], message1[i] + message2[i]);}
    /// ```
    /// 
    /// # CKKS example
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(4096, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let message1 = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    /// let message2 = vec![Complex::new(5.0, 6.0), Complex::new(7.0, 8.0)];
    /// let mut encrypted1 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message1, None, (1u64<<40) as f64));
    /// let         plain2 = encoder
    ///     .encode_c64_array_new(&message2, None, (1u64<<40) as f64);
    /// evaluator.add_plain_inplace(&mut encrypted1, &plain2);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..2 {assert!((result[i] - (message1[i] + message2[i])).norm() < 1e-3);}
    #[inline]
    pub fn add_plain(&self, encrypted: &Ciphertext, plain: &Plaintext, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.add_plain_inplace(destination, plain);
    }

    /// See [Evaluator::add_plain].
    #[inline]
    pub fn add_plain_new(&self, encrypted: &Ciphertext, plain: &Plaintext) -> Ciphertext {
        let mut result = encrypted.clone();
        self.add_plain_inplace(&mut result, plain);
        result
    }

    /// See [Evaluator::sub_plain].
    pub fn sub_plain_inplace(&self, encrypted: &mut Ciphertext, plain: &Plaintext) {
        self.check_ciphertext(encrypted);
        self.check_plaintext(plain);
        let context_data = self.get_context_data(encrypted.parms_id());
        let parms = context_data.parms();
        let scheme = parms.scheme();
        match scheme {
            SchemeType::BFV | SchemeType::BGV => {
                if encrypted.is_ntt_form() {
                    panic!("[Invalid argument] Ciphertexts must not be in NTT form");
                }
            },
            SchemeType::CKKS => {
                if !encrypted.is_ntt_form() {
                    panic!("[Invalid argument] Ciphertexts must be in NTT form");
                }
                if !util::are_close_f64(encrypted.scale(), plain.scale()) {
                    panic!("[Invalid argument] Ciphertext and plaintext scales do not match");
                }
            },
            _ => panic!("[Invalid argument] Unsupported scheme")
        }
        if encrypted.is_ntt_form() != plain.is_ntt_form() {
            panic!("[Invalid argument] Ciphertext and plaintext NTT form mismatch");
        }
        let coeff_count = parms.poly_modulus_degree();
        let coeff_modulus = parms.coeff_modulus();

        match scheme {
            SchemeType::BFV => {
                util::scaling_variant::multiply_sub_plain(plain, &context_data, encrypted.poly_mut(0));
            },
            SchemeType::CKKS => {
                polymod::sub_inplace_p(encrypted.poly_mut(0), plain.data(), coeff_count, coeff_modulus);
            },
            SchemeType::BGV => {
                let mut plain_copy = plain.clone();
                polymod::multiply_scalar(plain.data(), encrypted.correction_factor(), parms.plain_modulus(), plain_copy.data_mut());
                util::scaling_variant::sub_plain(&plain_copy, &context_data, encrypted.poly_mut(0));
            },
            _ => panic!("[Invalid argument] Unsupported scheme")
        }
    }

    /// Substract a ciphertext with a plaintext.
    /// 
    /// # BFV/BGV example
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Evaluator};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let plain_modulus = params.plain_modulus().value();
    /// let message1 = vec![1, 2, 3, 4];
    /// let message2 = vec![5, 6, 7, 8];
    /// let mut encrypted1 = encryptor.encrypt_new(&encoder.encode_new(&message1));
    /// let         plain2 = encoder.encode_new(&message2);
    /// evaluator.sub_plain_inplace(&mut encrypted1, &plain2);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..4 {assert_eq!(
    ///     result[i], 
    ///     (plain_modulus + message1[i] - message2[i]) % plain_modulus
    /// );}
    /// ```
    /// 
    /// # CKKS example
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(4096, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let message1 = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    /// let message2 = vec![Complex::new(5.0, 6.0), Complex::new(7.0, 8.0)];
    /// let mut encrypted1 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message1, None, (1u64<<40) as f64));
    /// let         plain2 = encoder
    ///     .encode_c64_array_new(&message2, None, (1u64<<40) as f64);
    /// evaluator.sub_plain_inplace(&mut encrypted1, &plain2);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..2 {assert!((result[i] - (message1[i] - message2[i])).norm() < 1e-3);}
    #[inline]
    pub fn sub_plain(&self, encrypted: &Ciphertext, plain: &Plaintext, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.sub_plain_inplace(destination, plain);
    }

    /// See [Evaluator::sub_plain].
    #[inline]
    pub fn sub_plain_new(&self, encrypted: &Ciphertext, plain: &Plaintext) -> Ciphertext {
        let mut result = encrypted.clone();
        self.sub_plain_inplace(&mut result, plain);
        result
    }

    fn multiply_plain_normal(&self, encrypted: &mut Ciphertext, plain: &Plaintext) {
        let context_data = self.get_context_data(encrypted.parms_id());
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();

        let plain_upper_half_threshold = context_data.plain_upper_half_threshold();
        let plain_upper_half_increment = context_data.plain_upper_half_increment();
        let ntt_tables = context_data.small_ntt_tables();

        let encrypted_size = encrypted.size();
        let plain_coeff_count = plain.coeff_count();
        let plain_nonzero_coeff_count = plain.nonzero_coeff_count();

        /*
        Optimizations for constant / monomial multiplication can lead to the presence of a timing side-channel in
        use-cases where the plaintext data should also be kept private.
        */
        if plain_nonzero_coeff_count == 1 {
            let mono_exponent = plain.significant_coeff_count() - 1;
            if plain.data_at(mono_exponent) >= plain_upper_half_threshold {
                if !context_data.qualifiers().using_fast_plain_lift {
                    let mut temp = vec![0; coeff_modulus_size];
                    // We need to adjust the monomial modulo each coeff_modulus prime separately when the coeff_modulus
                    // primes may be larger than the plain_modulus. We add plain_upper_half_increment (i.e., q-t) to
                    // the monomial to ensure it is smaller than coeff_modulus and then do an RNS multiplication. Note
                    // that in this case plain_upper_half_increment contains a multi-precision integer, so after the
                    // addition we decompose the multi-precision integer into RNS components, and then multiply.
                    util::add_uint_u64(plain_upper_half_increment, plain.data_at(mono_exponent), &mut temp);
                    context_data.rns_tool().base_q().decompose(&mut temp);
                    polymod::negacyclic_multiply_mononomials_inplace_ps(
                        encrypted.data_mut(), 
                        &temp, 
                        mono_exponent, 
                        encrypted_size, 
                        coeff_count, 
                        coeff_modulus);
                } else {
                    // Every coeff_modulus prime is larger than plain_modulus, so there is no need to adjust the
                    // monomial. Instead, just do an RNS multiplication.
                    polymod::negacyclic_multiply_mononomial_inplace_ps(
                        encrypted.data_mut(), 
                        plain.data_at(mono_exponent), 
                        mono_exponent, 
                        encrypted_size, 
                        coeff_count, 
                        coeff_modulus);
                }
            } else {
                // The monomial represents a positive number, so no RNS multiplication is needed.
                polymod::negacyclic_multiply_mononomial_inplace_ps(
                    encrypted.data_mut(), 
                    plain.data_at(mono_exponent), 
                    mono_exponent, 
                    encrypted_size, 
                    coeff_count, 
                    coeff_modulus);
            }
            if parms.scheme() == SchemeType::CKKS {
                encrypted.set_scale(encrypted.scale() * plain.scale());
                if !Self::is_scale_within_bounds(encrypted.scale(), &context_data) {
                    panic!("[Invalid argument] Scale out of bounds.");
                }
            }
            return;
        }

        // Generic case: any plaintext polynomial
        // Allocate temporary space for an entire RNS polynomial
        let mut temp = vec![0; coeff_count * coeff_modulus_size];
        if !context_data.qualifiers().using_fast_plain_lift {
            for i in 0..plain_coeff_count {
                let plain_value = plain.data_at(i);
                if plain_value >= plain_upper_half_threshold {
                    util::add_uint_u64(plain_upper_half_increment, plain_value, &mut temp[i*coeff_modulus_size..(i+1)*coeff_modulus_size]);
                } else {
                    temp[coeff_modulus_size * i] = plain_value;
                }
            }
            context_data.rns_tool().base_q().decompose_array(&mut temp);
        } else {
            // Note that in this case plain_upper_half_increment holds its value in RNS form modulo the coeff_modulus
            // primes.
            for i in 0..coeff_modulus_size {
                for j in 0..plain_coeff_count {
                    temp[i * coeff_count + j] = if plain.data_at(j) >= plain_upper_half_threshold {plain.data_at(j) + plain_upper_half_increment[i]} else {plain.data()[j]};
                }
            }
        }

        // Need to multiply each component in encrypted with temp; first step is to transform to NTT form
        // RNSIter temp_iter(temp.get(), coeff_count);
        polymod::ntt_p(&mut temp, coeff_count, ntt_tables);
        polymod::ntt_lazy_ps(encrypted.data_mut(), encrypted_size, coeff_count, ntt_tables);
        for i in 0..encrypted_size {
            polymod::dyadic_product_inplace_p(encrypted.poly_mut(i), &temp, coeff_count, coeff_modulus);
        }
        polymod::intt_ps(encrypted.data_mut(), encrypted_size, coeff_count, ntt_tables);
        
        if parms.scheme() == SchemeType::CKKS {
            encrypted.set_scale(encrypted.scale() * plain.scale());
            if !Self::is_scale_within_bounds(encrypted.scale(), &context_data) {
                panic!("[Invalid argument] Scale out of bounds.");
            }
        }
    }

    fn multiply_plain_ntt(&self, encrypted: &mut Ciphertext, plain: &Plaintext) {
        if !plain.is_ntt_form() {
            panic!("[Invalid argument] Plainn must be ntt form.");
        }
        if encrypted.parms_id() != plain.parms_id() {
            panic!("[Invalid argument] Ciphertext and plaintext must have the same parms_id.");
        }

        let context_data = self.context.get_context_data(encrypted.parms_id()).unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_count = parms.poly_modulus_degree();
        let encrypted_size = encrypted.size();

        for i in 0..encrypted_size {
            polymod::dyadic_product_inplace_p(
                encrypted.poly_mut(i),
                plain.data(),
                coeff_count,
                coeff_modulus);
        }

        if parms.scheme() == SchemeType::CKKS {
            encrypted.set_scale(encrypted.scale() * plain.scale());
            if !Self::is_scale_within_bounds(encrypted.scale(), &context_data) {
                panic!("[Invalid argument] Scale out of bounds.");
            }
        }
    }

    /// See [Evaluator::multiply_plain].
    #[inline]
    pub fn multiply_plain_inplace(&self, encrypted: &mut Ciphertext, plain: &Plaintext) {
        self.check_ciphertext(encrypted); 
        self.check_plaintext(plain);
        if encrypted.is_ntt_form() != plain.is_ntt_form() {
            panic!("[Invalid argument] NTT form mismatch.");
        }
        if encrypted.is_ntt_form() {
            self.multiply_plain_ntt(encrypted, plain);
        } else {
            self.multiply_plain_normal(encrypted, plain);
        }
    }

    /// Multiplies a ciphertext with a plaintext.
    /// 
    /// # BFV/BGV example
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Evaluator};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let plain_modulus = params.plain_modulus().value();
    /// let message1 = vec![1, 2, 3, 4];
    /// let message2 = vec![5, 6, 7, 8];
    /// let mut encrypted1 = encryptor.encrypt_new(&encoder.encode_new(&message1));
    /// let         plain2 = encoder.encode_new(&message2);
    /// evaluator.multiply_plain_inplace(&mut encrypted1, &plain2);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..4 {assert_eq!(result[i], message1[i] * message2[i]);}
    /// ```
    /// 
    /// # CKKS example
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(8192, vec![60, 60, 60]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let message1 = vec![Complex::new(1.0, 2.0), Complex::new(3.0, 4.0)];
    /// let message2 = vec![Complex::new(5.0, 6.0), Complex::new(7.0, 8.0)];
    /// let mut encrypted1 = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message1, None, (1u64<<30) as f64));
    /// let         plain2 = encoder
    ///     .encode_c64_array_new(&message2, None, (1u64<<30) as f64);
    /// evaluator.multiply_plain_inplace(&mut encrypted1, &plain2);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&encrypted1));
    /// for i in 0..2 {assert!((result[i] - (message1[i] * message2[i])).norm() < 1e-3);}
    #[inline]
    pub fn multiply_plain(&self, encrypted: &Ciphertext, plain: &Plaintext, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.multiply_plain_inplace(destination, plain);
    }

    /// See [Evaluator::multiply_plain].
    #[inline]
    pub fn multiply_plain_new(&self, encrypted: &Ciphertext, plain: &Plaintext) -> Ciphertext {
        let mut result = encrypted.clone();
        self.multiply_plain_inplace(&mut result, plain);
        result
    }

    /// Transforms a plaintext from normal form to NTT form.
    pub fn transform_plain_to_ntt_inplace(&self, plain: &mut Plaintext, parms_id: &ParmsID) {
        self.check_plaintext(plain);
        if plain.is_ntt_form() {
            panic!("[Invalid argument] Plaintext is already in NTT form.");
        }
        let context_data = self.context.get_context_data(parms_id);
        if context_data.is_none() {
            panic!("[Invalid argument] parms_id is not valid.");
        }
        let context_data = context_data.unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();
        let plain_coeff_count = plain.coeff_count();

        plain.resize(coeff_count * coeff_modulus_size);

        let plain_upper_half_threshold = context_data.plain_upper_half_threshold();
        let plain_upper_half_increment = context_data.plain_upper_half_increment();
        let ntt_tables = context_data.small_ntt_tables();

        if !context_data.qualifiers().using_fast_plain_lift {
            let mut temp = vec![0; coeff_count * coeff_modulus_size];
            for i in 0..plain_coeff_count {
                let plain_value = plain.data_at(i);
                if plain_value >= plain_upper_half_threshold {
                    util::add_uint_u64(plain_upper_half_increment, plain_value, &mut temp[i*coeff_modulus_size..(i+1)*coeff_modulus_size]);
                } else {
                    temp[coeff_modulus_size * i] = plain_value;
                }
            }
            context_data.rns_tool().base_q().decompose_array(&mut temp);
            plain.data_mut().copy_from_slice(&temp);
        } else {
            // Note that in this case plain_upper_half_increment holds its value in RNS form modulo the coeff_modulus
            // primes.
            for i in 0..coeff_modulus_size {
                for j in 0..plain_coeff_count {
                    let plain_index = (coeff_modulus_size - 1 - i) * coeff_count + j;
                    let increment_index = coeff_modulus_size - 1 - i;
                    plain.data_mut()[plain_index] = if plain.data_at(j) >= plain_upper_half_threshold 
                        {plain.data_at(j) + plain_upper_half_increment[increment_index]} 
                        else {plain.data_at(j)};
                }
            }
        }
        polymod::ntt_p(plain.data_mut(), coeff_count, ntt_tables);
        plain.set_parms_id(*parms_id);
    }

    /// Transforms a plaintext from normal form to NTT form.
    #[inline]
    pub fn transform_plain_to_ntt(&self, plain: &Plaintext, parms_id: &ParmsID, destination: &mut Plaintext) {
        *destination = plain.clone();
        self.transform_plain_to_ntt_inplace(destination, parms_id);
    }

    /// Transforms a plaintext from normal form to NTT form.
    #[inline]
    pub fn transform_plain_to_ntt_new(&self, plain: &Plaintext, parms_id: &ParmsID) -> Plaintext {
        let mut result = plain.clone();
        self.transform_plain_to_ntt_inplace(&mut result, parms_id);
        result
    }

    /// Transforms a ciphertext from normal form to NTT form.
    pub fn transform_to_ntt_inplace(&self, encrypted: &mut Ciphertext) {
        self.check_ciphertext(encrypted);
        if encrypted.is_ntt_form() {
            panic!("[Invalid argument] Ciphertext is already in NTT form.");
        }
        let context_data = self.context.get_context_data(encrypted.parms_id());
        if context_data.is_none() {
            panic!("[Invalid argument] parms_id is not valid.");
        }
        let context_data = context_data.unwrap();
        let parms = context_data.parms();
        let coeff_count = parms.poly_modulus_degree();
        let encrypted_size = encrypted.size();

        let ntt_tables = context_data.small_ntt_tables();

        polymod::ntt_ps(encrypted.data_mut(), encrypted_size, coeff_count, ntt_tables);
        encrypted.set_is_ntt_form(true);
    }

    /// Transforms a ciphertext from normal form to NTT form.
    #[inline]
    pub fn transform_to_ntt(&self, encrypted: &Ciphertext, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.transform_to_ntt_inplace(destination);
    }

    /// Transforms a ciphertext from normal form to NTT form.
    #[inline]
    pub fn transform_to_ntt_new(&self, encrypted: &Ciphertext) -> Ciphertext {
        let mut result = encrypted.clone();
        self.transform_to_ntt_inplace(&mut result);
        result
    }


    /// Transforms a ciphertext from NTT form to normal form.
    pub fn transform_from_ntt_inplace(&self, encrypted: &mut Ciphertext) {
        self.check_ciphertext(encrypted);
        if !encrypted.is_ntt_form() {
            panic!("[Invalid argument] Ciphertext is already in normal form.");
        }
        let context_data = self.context.get_context_data(encrypted.parms_id());
        if context_data.is_none() {
            panic!("[Invalid argument] parms_id is not valid.");
        }
        let context_data = context_data.unwrap();
        let parms = context_data.parms();
        let coeff_count = parms.poly_modulus_degree();
        let encrypted_size = encrypted.size();

        let ntt_tables = context_data.small_ntt_tables();

        polymod::intt_ps(encrypted.data_mut(), encrypted_size, coeff_count, ntt_tables);
        encrypted.set_is_ntt_form(false);
    }

    /// Transforms a ciphertext from NTT form to normal form.
    #[inline]
    pub fn transform_from_ntt(&self, encrypted: &Ciphertext, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.transform_from_ntt_inplace(destination);
    }

    /// Transforms a ciphertext from NTT form to normal form.
    #[inline]
    pub fn transform_from_ntt_new(&self, encrypted: &Ciphertext) -> Ciphertext {
        let mut result = encrypted.clone();
        self.transform_from_ntt_inplace(&mut result);
        result
    }

    /// See [Evaluator::apply_galois].
    pub fn apply_galois_inplace(&self, encrypted: &mut Ciphertext, galois_elt: usize, galois_keys: &GaloisKeys) {
        self.check_ciphertext(encrypted);
        self.check_public_key(galois_keys);
        if galois_keys.parms_id() != self.context.key_parms_id() {
            panic!("[Invalid argument] Galois keys are not valid for encryption parameters.");
        }
        let context_data = self.context.get_context_data(encrypted.parms_id()).unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();
        let encrypted_size = encrypted.size();
        let key_context_data = self.context.key_context_data().unwrap();
        let galois_tool = key_context_data.galois_tool();

        if !galois_keys.has_key(galois_elt) {
            panic!("[Invalid argument] Galois keys not present for galois_elt.");
        }
        let m = coeff_count * 2;
        if galois_elt & 1 == 0 || galois_elt > m {
            panic!("[Invalid argument] Galois element not valid");
        }
        if encrypted_size > 2 {
            panic!("[Invalid argument] Encrypted size must be 2");
        }
        let mut temp = vec![0; coeff_count * coeff_modulus_size];
        
        // DO NOT CHANGE EXECUTION ORDER OF FOLLOWING SECTION
        // BEGIN: Apply Galois for each ciphertext
        // Execution order is sensitive, since apply_galois is not inplace!
        match encrypted.is_ntt_form() {
            false => {
                galois_tool.apply_p(encrypted.poly_mut(0), galois_elt, coeff_modulus, &mut temp);
                encrypted.poly_mut(0).copy_from_slice(&temp);
                galois_tool.apply_p(encrypted.poly_mut(1), galois_elt, coeff_modulus, &mut temp);
            },
            true => {
                galois_tool.apply_ntt_p(encrypted.poly_mut(0), coeff_modulus_size, galois_elt, &mut temp);
                encrypted.poly_mut(0).copy_from_slice(&temp);
                galois_tool.apply_ntt_p(encrypted.poly_mut(1), coeff_modulus_size, galois_elt, &mut temp);
            },
        }
        encrypted.poly_mut(1).fill(0);
        self.switch_key_inplace_internal(encrypted, &temp, galois_keys.as_kswitch_keys(), GaloisKeys::get_index(galois_elt));
    }

    /// Apply Galois automorphism on a ciphertext.
    /// This is not supposed to be called by a user unless
    /// he is apparently aware of the underlying math.
    /// Instead, use [Evaluator::rotate_rows], [Evaluator::rotate_columns] for BFV/BGV
    /// and [Evaluator::rotate_vector], [Evaluator::complex_conjugate] for CKKS.
    #[inline]
    pub fn apply_galois(&self, encrypted: &Ciphertext, galois_elt: usize, galois_keys: &GaloisKeys, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.apply_galois_inplace(destination, galois_elt, galois_keys);
    }

    /// See [Evaluator::apply_galois].
    #[inline]
    pub fn apply_galois_new(&self, encrypted: &Ciphertext, galois_elt: usize, galois_keys: &GaloisKeys) -> Ciphertext {
        let mut result = encrypted.clone();
        self.apply_galois_inplace(&mut result, galois_elt, galois_keys);
        result
    }

    /// See [Evaluator::apply_galois_plain]. Note that you could have done galois
    /// automorphism in the message domain, if you are using polynomial encoding.
    pub fn apply_galois_plain_inplace(&self, plain: &mut Plaintext, galois_elt: usize) {
        self.check_plaintext(plain);
        let context_data = if plain.is_ntt_form() {
            self.context.get_context_data(plain.parms_id()).unwrap()
        } else {
            self.context.key_context_data().unwrap()
        };
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();
        let key_context_data = self.context.key_context_data().unwrap();
        let galois_tool = key_context_data.galois_tool();

        let m = coeff_count * 2;
        if galois_elt & 1 == 0 || galois_elt > m {
            panic!("[Invalid argument] Galois element not valid");
        }
        let mut temp = vec![0; plain.data().len()];
        
        // DO NOT CHANGE EXECUTION ORDER OF FOLLOWING SECTION
        // BEGIN: Apply Galois for each ciphertext
        // Execution order is sensitive, since apply_galois is not inplace!
        match plain.is_ntt_form() {
            false => {
                if context_data.is_ckks() {
                    galois_tool.apply_p(plain.data(), galois_elt, coeff_modulus, &mut temp);
                } else {
                    galois_tool.apply(plain.data(), galois_elt, context_data.parms().plain_modulus(), &mut temp);
                }
            },
            true => {
                galois_tool.apply_ntt_p(plain.data(), coeff_modulus_size, galois_elt, &mut temp);
            },
        }
        plain.data_mut().copy_from_slice(&temp);
    }

    /// Apply Galois automorphism on a plaintext.
    /// This is not supposed to be called by a user unless
    /// he is apparently aware of the underlying math. Note that you could have done galois
    /// automorphism in the message domain, if you are using polynomial encoding.
    #[inline]
    pub fn apply_galois_plain(&self, plain: &Plaintext, galois_elt: usize, destination: &mut Plaintext) {
        *destination = plain.clone();
        self.apply_galois_plain_inplace(destination, galois_elt);
    }

    /// See [Evaluator::apply_galois_plain].
    #[inline]
    pub fn apply_galois_plain_new(&self, encrypted: &Plaintext, galois_elt: usize) -> Plaintext {
        let mut result = encrypted.clone();
        self.apply_galois_plain_inplace(&mut result, galois_elt);
        result
    }


    fn rotate_internal(&self, encrypted: &mut Ciphertext, steps: isize, galois_keys: &GaloisKeys) {
        let context_data = self.context.get_context_data(encrypted.parms_id());
        if context_data.is_none() {
            panic!("[Invalid argument] Ciphertext parms_id is not valid.");
        }
        let context_data = context_data.unwrap();
        if !context_data.qualifiers().using_batching {
            panic!("[Invalid argument] Encryption parameters does not support batching.");
        }
        if galois_keys.parms_id() != self.context.key_parms_id() {
            panic!("[Invalid argument] Galois keys are not valid for encryption parameters.");
        }
        if steps == 0 {
            return;
        }
        let parms = context_data.parms();
        let coeff_count = parms.poly_modulus_degree();
        let galois_tool = context_data.galois_tool();
        if galois_keys.has_key(galois_tool.get_elt_from_step(steps)) {
            self.apply_galois_inplace(encrypted, galois_tool.get_elt_from_step(steps), galois_keys);
        } else {
            // Convert the steps to NAF: guarantees using smallest HW
            let naf_steps = util::naf(steps as i32);
            // println!("naf_steps: {:?}", naf_steps);
            // If naf_steps contains only one element, then this is a power-of-two
            // rotation and we would have expected not to get to this part of the
            // if-statement.
            if naf_steps.len() == 1 {
                panic!("[Logic error] Galois key not present.");
            }
            for naf_step in naf_steps {
                if (naf_step.unsigned_abs() as usize) != coeff_count >> 1 {
                    self.rotate_internal(encrypted, naf_step as isize, galois_keys);
                }
            }
        }
    }

    /// See [Evaluator::rotate_rows].
    #[inline]
    pub fn rotate_rows_inplace(&self, encrypted: &mut Ciphertext, steps: isize, galois_keys: &GaloisKeys) {
        let scheme = self.context.key_context_data().unwrap().parms().scheme();
        if scheme != SchemeType::BFV && scheme != SchemeType::BGV {
            panic!("[Invalid argument] Unsupported scheme.");
        }
        self.rotate_internal(encrypted, steps, galois_keys);
    }

    /// Rotates a BFV/BGV ciphertext by rows.
    /// 
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Evaluator};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let galois_keys = keygen.create_galois_keys(false);
    /// let message = vec![1, 2, 3, 4];
    /// let mut encrypted = encryptor.encrypt_new(&encoder.encode_new(&message));
    /// 
    /// let rotated = evaluator.rotate_rows_new(&encrypted, 1, &galois_keys);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&rotated));
    /// for i in 0..3 {assert_eq!(result[i], message[i + 1]);}
    /// assert_eq!(result[2047], message[0]);
    /// 
    /// let rotated = evaluator.rotate_rows_new(&encrypted, -1, &galois_keys);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&rotated));
    /// for i in 0..4 {assert_eq!(result[i + 1], message[i]);}
    /// ```
    #[inline]
    pub fn rotate_rows(&self, encrypted: &Ciphertext, steps: isize, galois_keys: &GaloisKeys, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.rotate_rows_inplace(destination, steps, galois_keys);
    }

    /// See [Evaluator::rotate_rows].
    #[inline]
    pub fn rotate_rows_new(&self, encrypted: &Ciphertext, steps: isize, galois_keys: &GaloisKeys) -> Ciphertext {
        let mut result = encrypted.clone();
        self.rotate_rows_inplace(&mut result, steps, galois_keys);
        result
    }

    fn conjugate_internal(&self, encrypted: &mut Ciphertext, galois_keys: &GaloisKeys) {
        let context_data = self.context.get_context_data(encrypted.parms_id());
        if context_data.is_none() {
            panic!("[Invalid argument] Ciphertext parms_id is not valid.");
        }
        let context_data = context_data.unwrap();
        if !context_data.qualifiers().using_batching {
            panic!("[Invalid argument] Encryption parameters does not support batching.");
        }
        let galois_tool = context_data.galois_tool();
        self.apply_galois_inplace(encrypted, galois_tool.get_elt_from_step(0), galois_keys);
    }

    /// See [Evaluator::rotate_columns].
    #[inline]
    pub fn rotate_columns_inplace(&self, encrypted: &mut Ciphertext, galois_keys: &GaloisKeys) {
        let scheme = self.context.key_context_data().unwrap().parms().scheme();
        if scheme != SchemeType::BFV && scheme != SchemeType::BGV {
            panic!("[Invalid argument] Unsupported scheme.");
        }
        self.conjugate_internal(encrypted, galois_keys);
    }

    /// Switch the two columns of a BFV/BGV ciphertext.
    /// 
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Evaluator};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let galois_keys = keygen.create_galois_keys(false);
    /// let message = vec![1, 2, 3, 4];
    /// let mut encrypted = encryptor.encrypt_new(&encoder.encode_new(&message));
    /// 
    /// let rotated = evaluator.rotate_columns_new(&encrypted, &galois_keys);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&rotated));
    /// for i in 0..4 {assert_eq!(result[i + 2048], message[i]);}
    /// ```
    #[inline]
    pub fn rotate_columns(&self, encrypted: &Ciphertext, galois_keys: &GaloisKeys, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.rotate_columns_inplace(destination, galois_keys);
    }

    /// See [Evaluator::rotate_columns].
    #[inline]
    pub fn rotate_columns_new(&self, encrypted: &Ciphertext, galois_keys: &GaloisKeys) -> Ciphertext {
        let mut result = encrypted.clone();
        self.rotate_columns_inplace(&mut result, galois_keys);
        result
    }

    /// See [Evaluator::rotate_vector].
    #[inline]
    pub fn rotate_vector_inplace(&self, encrypted: &mut Ciphertext, steps: isize, galois_keys: &GaloisKeys) {
        let scheme = self.context.key_context_data().unwrap().parms().scheme();
        if scheme != SchemeType::CKKS {
            panic!("[Invalid argument] Unsupported scheme.");
        }
        self.rotate_internal(encrypted, steps, galois_keys);
    }

    /// Rotates a CKKS ciphertext.
    /// 
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(4096, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let galois_keys = keygen.create_galois_keys(false);
    /// let message = vec![
    ///     Complex::new(1.0, 2.0), Complex::new(3.0, 4.0),
    ///     Complex::new(5.0, 6.0), Complex::new(7.0, 8.0),
    /// ];
    /// let mut encrypted = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message, None, (1u64<<40) as f64));
    /// 
    /// let rotated = evaluator.rotate_vector_new(&encrypted, 1, &galois_keys);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&rotated));
    /// for i in 0..3 {assert!((result[i] - message[i + 1]).norm() < 1e-3);}
    /// assert!((result[2047] - message[0]).norm() < 1e-3);
    /// 
    /// let rotated = evaluator.rotate_vector_new(&encrypted, -1, &galois_keys);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&rotated));
    /// for i in 0..4 {assert!((result[i + 1] - message[i]).norm() < 1e-3);}
    #[inline]
    pub fn rotate_vector(&self, encrypted: &Ciphertext, steps: isize, galois_keys: &GaloisKeys, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.rotate_vector_inplace(destination, steps, galois_keys);
    }

    /// See [Evaluator::rotate_vector].
    #[inline]
    pub fn rotate_vector_new(&self, encrypted: &Ciphertext, steps: isize, galois_keys: &GaloisKeys) -> Ciphertext {
        let mut result = encrypted.clone();
        self.rotate_vector_inplace(&mut result, steps, galois_keys);
        result
    }

    /// See [Evaluator::complex_conjugate].
    #[inline]
    pub fn complex_conjugate_inplace(&self, encrypted: &mut Ciphertext, galois_keys: &GaloisKeys) {
        let scheme = self.context.key_context_data().unwrap().parms().scheme();
        if scheme != SchemeType::CKKS {
            panic!("[Invalid argument] Unsupported scheme.");
        }
        self.conjugate_internal(encrypted, galois_keys);
    }

    /// Compute the complex conjugate on a CKKS ciphertext.
    /// 
    /// ```rust
    /// use heathcliff::{create_ckks_decryptor_suite, Evaluator};
    /// use num_complex::Complex;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_ckks_decryptor_suite(4096, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// let galois_keys = keygen.create_galois_keys(false);
    /// let message = vec![
    ///     Complex::new(1.0, 2.0), Complex::new(3.0, 4.0),
    ///     Complex::new(5.0, 6.0), Complex::new(7.0, 8.0),
    /// ];
    /// let mut encrypted = encryptor
    ///     .encrypt_new(&encoder.encode_c64_array_new(&message, None, (1u64<<40) as f64));
    /// 
    /// let conjugated = evaluator.complex_conjugate_new(&encrypted, &galois_keys);
    /// let result = encoder.decode_new(&decryptor.decrypt_new(&conjugated));
    /// for i in 0..4 {assert!((result[i] - message[i].conj()).norm() < 1e-3);}
    #[inline]
    pub fn complex_conjugate(&self, encrypted: &Ciphertext, galois_keys: &GaloisKeys, destination: &mut Ciphertext) {
        *destination = encrypted.clone();
        self.complex_conjugate_inplace(destination, galois_keys);
    }

    /// See [Evaluator::complex_conjugate].
    #[inline]
    pub fn complex_conjugate_new(&self, encrypted: &Ciphertext, galois_keys: &GaloisKeys) -> Ciphertext {
        let mut result = encrypted.clone();
        self.complex_conjugate_inplace(&mut result, galois_keys);
        result
    }

}

#[cfg(test)]
pub(crate) mod tests {

    use num_complex::Complex64;

    use crate::{
        SchemeType, CoeffModulus, SecurityLevel,
        Encryptor, Decryptor, KeyGenerator, BatchEncoder, CKKSEncoder,
        EncryptionParameters
    };

    use super::*;

    fn create_bfv_suite(poly_degree: usize, plain_bits: usize, q_bits: Vec<usize>, expand_keys: bool)
        -> (Arc<HeContext>, BatchEncoder, KeyGenerator, Encryptor, Decryptor, Evaluator)
    {
        let mut total_bits = q_bits.clone();
        total_bits.push(plain_bits);
        let all_modulus = CoeffModulus::create(poly_degree, total_bits);
        let params = EncryptionParameters::new(SchemeType::BFV)
            .set_poly_modulus_degree(poly_degree)
            .set_plain_modulus(&all_modulus[q_bits.len()])
            .set_coeff_modulus(&all_modulus[..q_bits.len()]);
        let context = HeContext::new(params, expand_keys, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false));
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let evaluator = Evaluator::new(context.clone());
        let encoder = BatchEncoder::new(context.clone());
        (context, encoder, keygen, encryptor, decryptor, evaluator)
    }

    pub fn random_u64_vector(context: &HeContext) -> Vec<u64> {
        let context_data = context.first_context_data().unwrap();
        let parms = context_data.parms();
        let mut vec = vec![0u64; parms.poly_modulus_degree()];
        let modulus = parms.plain_modulus().value();
        for i in 0..vec.len() {
            vec[i] = rand::random::<u64>() % modulus;
        }
        vec
    }

    pub fn random_c64_vector(context: &HeContext) -> Vec<Complex64> {
        let context_data = context.first_context_data().unwrap();
        let parms = context_data.parms();
        let mut vec = vec![Complex64::new(0.0, 0.0); parms.poly_modulus_degree() / 2];
        for i in 0..vec.len() {
            vec[i] = Complex64::new((rand::random::<f64>() - 0.5) * 32.0, (rand::random::<f64>() - 0.5) * 32.0);
        }
        vec
    }

    fn bfv_encrypt(message: &[u64], encoder: &BatchEncoder, encryptor: &Encryptor) -> Ciphertext {
        let plain = encoder.encode_new(message);
        
        encryptor.encrypt_new(&plain)
    }

    fn bfv_decrypt(ciphertext: &Ciphertext, encoder: &BatchEncoder, decryptor: &mut Decryptor) -> Vec<u64> {
        let plain = decryptor.decrypt_new(ciphertext);
        encoder.decode_new(&plain)
    }

    fn create_ckks_suite(poly_degree: usize, q_bits: Vec<usize>, expand_keys: bool)
        -> (Arc<HeContext>, CKKSEncoder, KeyGenerator, Encryptor, Decryptor, Evaluator)
    {
        let params = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(poly_degree)
            .set_coeff_modulus(&CoeffModulus::create(poly_degree, q_bits));
        let context = HeContext::new(params, expand_keys, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false));
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let evaluator = Evaluator::new(context.clone());
        let encoder = CKKSEncoder::new(context.clone());
        (context, encoder, keygen, encryptor, decryptor, evaluator)
    }

    fn ckks_encrypt(message: &[Complex64], encoder: &CKKSEncoder, encryptor: &Encryptor, scale: f64) -> Ciphertext {
        let plain = encoder.encode_c64_array_new(message, None, scale);
        
        encryptor.encrypt_new(&plain)
    }

    fn ckks_decrypt(ciphertext: &Ciphertext, encoder: &CKKSEncoder, decryptor: &mut Decryptor) -> Vec<Complex64> {
        let plain = decryptor.decrypt_new(ciphertext);
        encoder.decode_new(&plain)
    }
    
    fn create_bgv_suite(poly_degree: usize, plain_bits: usize, q_bits: Vec<usize>, expand_keys: bool)
        -> (Arc<HeContext>, BatchEncoder, KeyGenerator, Encryptor, Decryptor, Evaluator)
    {
        let mut total_bits = q_bits.clone();
        total_bits.push(plain_bits);
        let all_modulus = CoeffModulus::create(poly_degree, total_bits);
        let params = EncryptionParameters::new(SchemeType::BGV)
            .set_poly_modulus_degree(poly_degree)
            .set_plain_modulus(&all_modulus[q_bits.len()])
            .set_coeff_modulus(&all_modulus[..q_bits.len()]);
        let context = HeContext::new(params, expand_keys, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false));
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let evaluator = Evaluator::new(context.clone());
        let encoder = BatchEncoder::new(context.clone());
        (context, encoder, keygen, encryptor, decryptor, evaluator)
    }

    fn bgv_encrypt(message: &[u64], encoder: &BatchEncoder, encryptor: &Encryptor) -> Ciphertext {
        let plain = encoder.encode_new(message);
        
        encryptor.encrypt_new(&plain)
    }

    fn bgv_decrypt(ciphertext: &Ciphertext, encoder: &BatchEncoder, decryptor: &mut Decryptor) -> Vec<u64> {
        let plain = decryptor.decrypt_new(ciphertext);
        encoder.decode_new(&plain)
    }

    fn rotate_rows(m: Vec<u64>, s: isize) -> Vec<u64> {
        let s = if s>0 { s as usize } else { m.len() / 2 - (-s as usize) };
        let mut ret = vec![0; m.len()];
        let n = m.len() / 2;
        for i in 0..n {
            ret[i] = m[(i + s) % n];
            ret[i + n] = m[(i + n + s) % n + n];
        }
        ret
    }

    fn rotate_columns(m: Vec<u64>) -> Vec<u64> {
        let n = m.len() / 2;
        let mut ret = m[n..].to_vec();
        ret.extend_from_slice(&m[0..n]);
        ret
    }
    

    #[test]
    fn test_bfv_suite() {
        let (context, encoder, _keygen, encryptor, mut decryptor, evaluator) 
            = create_bfv_suite(32, 30, vec![40, 40, 40], false);
        let plain_modulus = encoder.get_plain_modulus();

        // Negate
        let message = random_u64_vector(&context);
        let mut cipher = bfv_encrypt(&message, &encoder, &encryptor);
        evaluator.negate_inplace(&mut cipher);
        let decrypted = bfv_decrypt(&cipher, &encoder, &mut decryptor);
        let negated_message = message.iter().map(|x| plain_modulus - x).collect::<Vec<_>>();
        assert_eq!(negated_message, decrypted);

        // Add
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let cipher1 = bfv_encrypt(&message1, &encoder, &encryptor);
        let cipher2 = bfv_encrypt(&message2, &encoder, &encryptor);
        let cipher3 = evaluator.add_new(&cipher1, &cipher2);
        let decrypted = bfv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter()).map(|(x, y)| (x + y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);

        // Add many
        let messages = (0..10).map(|_| random_u64_vector(&context)).collect::<Vec<_>>();
        let ciphertexts = messages.iter().map(|x| bfv_encrypt(x, &encoder, &encryptor)).collect::<Vec<_>>();
        let cipher_added = evaluator.add_many_new(&ciphertexts);
        let decrypted = bfv_decrypt(&cipher_added, &encoder, &mut decryptor);
        let added_message = messages.iter().fold(vec![0u64; messages[0].len()], |acc, x| {
            acc.iter().zip(x.iter()).map(|(a, b)| (a + b) % plain_modulus).collect::<Vec<_>>()
        });
        assert_eq!(added_message, decrypted);

        // Subtract
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let cipher1 = bfv_encrypt(&message1, &encoder, &encryptor);
        let cipher2 = bfv_encrypt(&message2, &encoder, &encryptor);
        let cipher3 = evaluator.sub_new(&cipher1, &cipher2);
        let decrypted = bfv_decrypt(&cipher3, &encoder, &mut decryptor);
        let subtracted_message = message1.iter().zip(message2.iter()).map(|(x, y)| (x + plain_modulus - y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(subtracted_message, decrypted);

        // Multiply
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let cipher1 = bfv_encrypt(&message1, &encoder, &encryptor);
        let cipher2 = bfv_encrypt(&message2, &encoder, &encryptor);
        let cipher3 = evaluator.multiply_new(&cipher1, &cipher2);
        let decrypted = bfv_decrypt(&cipher3, &encoder, &mut decryptor);
        let multiplied_message = message1.iter().zip(message2.iter()).map(|(x, y)| (x * y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(multiplied_message, decrypted);

        // Square
        let message = random_u64_vector(&context);
        let cipher1 = bfv_encrypt(&message, &encoder, &encryptor);
        let cipher2 = evaluator.square_new(&cipher1);
        let decrypted = bfv_decrypt(&cipher2, &encoder, &mut decryptor);
        let squared_message = message.iter()
            .map(|x| (x * x) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(squared_message, decrypted);

        // Add plain
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let cipher1 = bfv_encrypt(&message1, &encoder, &encryptor);
        let plain1 = encoder.encode_new(&message2);
        let cipher3 = evaluator.add_plain_new(&cipher1, &plain1);
        let decrypted = bfv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter()).map(|(x, y)| (x + y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);

        // Substract plain
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let cipher1 = bfv_encrypt(&message1, &encoder, &encryptor);
        let plain1 = encoder.encode_new(&message2);
        let cipher3 = evaluator.sub_plain_new(&cipher1, &plain1);
        let decrypted = bfv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter())
            .map(|(x, y)| (x + plain_modulus - y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);

        // Multiply plain
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let cipher1 = bgv_encrypt(&message1, &encoder, &encryptor);
        let plain1 = encoder.encode_new(&message2);
        let cipher3 = evaluator.multiply_plain_new(&cipher1, &plain1);
        let decrypted = bgv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter())
            .map(|(x, y)| (x * y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);
        
        // Multiply plain single
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let message2 = vec![message2[0]; message2.len()];
        let cipher1 = bgv_encrypt(&message1, &encoder, &encryptor);
        let plain1 = encoder.encode_new(&message2);
        let cipher3 = evaluator.multiply_plain_new(&cipher1, &plain1);
        let decrypted = bgv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter())
            .map(|(x, y)| (x * y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);

        // Add NTT
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let mut cipher1 = bfv_encrypt(&message1, &encoder, &encryptor);
        let mut cipher2 = bfv_encrypt(&message2, &encoder, &encryptor);
        evaluator.transform_to_ntt_inplace(&mut cipher1);
        evaluator.transform_to_ntt_inplace(&mut cipher2);
        let mut cipher3 = evaluator.add_new(&cipher1, &cipher2);
        evaluator.transform_from_ntt_inplace(&mut cipher3);
        let decrypted = bfv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter()).map(|(x, y)| (x + y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);

        // Mul NTT plain
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let mut cipher1 = bfv_encrypt(&message1, &encoder, &encryptor);
        let mut plain2 = encoder.encode_new(&message2);
        evaluator.transform_to_ntt_inplace(&mut cipher1);
        evaluator.transform_plain_to_ntt_inplace(&mut plain2, cipher1.parms_id());
        let mut cipher3 = evaluator.multiply_plain_new(&cipher1, &plain2);
        evaluator.transform_from_ntt_inplace(&mut cipher3);
        let decrypted = bfv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter()).map(|(x, y)| (x * y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);

        let (context, encoder, keygen, encryptor, mut decryptor, evaluator) 
            = create_bfv_suite(32, 30, vec![40, 40, 40], true);
        let plain_modulus = encoder.get_plain_modulus();

        // Square relin
        let relin_keys = keygen.create_relin_keys(false);
        let message1 = random_u64_vector(&context);
        let cipher1 = bfv_encrypt(&message1, &encoder, &encryptor);
        let mut cipher2 = evaluator.square_new(&cipher1);
        evaluator.relinearize_inplace(&mut cipher2, &relin_keys);
        let decrypted = bfv_decrypt(&cipher2, &encoder, &mut decryptor);
        let squared_message = message1.iter()
            .map(|x| (x * x) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(squared_message, decrypted);

        // Mod switch
        let message = random_u64_vector(&context);
        let mut cipher = bfv_encrypt(&message, &encoder, &encryptor);
        evaluator.mod_switch_to_next_inplace(&mut cipher);
        let decrypted = bfv_decrypt(&cipher, &encoder, &mut decryptor);
        assert_eq!(message, decrypted);

        // Rotate rows
        let galois_keys = keygen.create_galois_keys(false);
        let message = random_u64_vector(&context);
        let mut cipher = bfv_encrypt(&message, &encoder, &encryptor);
        evaluator.rotate_rows_inplace(&mut cipher, 1, &galois_keys);
        let decrypted = bfv_decrypt(&cipher, &encoder, &mut decryptor);
        let rotated_message = rotate_rows(message, 1);
        assert_eq!(rotated_message, decrypted);
        
        let message = random_u64_vector(&context);
        let mut cipher = bfv_encrypt(&message, &encoder, &encryptor);
        evaluator.rotate_rows_inplace(&mut cipher, 11, &galois_keys);
        let decrypted = bfv_decrypt(&cipher, &encoder, &mut decryptor);
        let rotated_message = rotate_rows(message, 11);
        assert_eq!(rotated_message, decrypted);
        
        let message = random_u64_vector(&context);
        let mut cipher = bfv_encrypt(&message, &encoder, &encryptor);
        evaluator.rotate_columns_inplace(&mut cipher, &galois_keys);
        let decrypted = bfv_decrypt(&cipher, &encoder, &mut decryptor);
        let rotated_message = rotate_columns(message);
        assert_eq!(rotated_message, decrypted);

    }


    #[test]
    fn test_ckks_suite() {
        let (context, encoder, _keygen, encryptor, mut decryptor, evaluator) 
            = create_ckks_suite(64, vec![30, 30, 30, 30], false);
        let scale = (1<<30) as f64;
        let are_close_f64 = |x: f64, y: f64| (x - y).abs() < 1e-1;
        let c64_vec_eq = |x: &Vec<Complex64>, y: &Vec<Complex64>| {
            x.iter().zip(y.iter()).for_each(|(a, b)| {
                assert!(are_close_f64(a.re, b.re), "{:?} != {:?}", a.re, b.re);
                assert!(are_close_f64(a.im, b.im), "{:?} != {:?}", a.im, b.im);
            });
        };

        // Negate
        let message = random_c64_vector(&context);
        let mut cipher = ckks_encrypt(&message, &encoder, &encryptor, scale);
        evaluator.negate_inplace(&mut cipher);
        let decrypted = ckks_decrypt(&cipher, &encoder, &mut decryptor);
        let negated_message = message.iter().map(|x| -x).collect::<Vec<_>>();
        c64_vec_eq(&negated_message, &decrypted);

        // Add
        let message1 = random_c64_vector(&context);
        let message2 = random_c64_vector(&context);
        let cipher1 = ckks_encrypt(&message1, &encoder, &encryptor, scale);
        let cipher2 = ckks_encrypt(&message2, &encoder, &encryptor, scale);
        let cipher3 = evaluator.add_new(&cipher1, &cipher2);
        let decrypted = ckks_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter()).map(|(x, y)| x + y).collect::<Vec<_>>();
        c64_vec_eq(&added_message, &decrypted);

        // Add many
        let messages = (0..10).map(|_| random_c64_vector(&context)).collect::<Vec<_>>();
        let ciphertexts = messages.iter().map(|x| 
            ckks_encrypt(x, &encoder, &encryptor, scale)).collect::<Vec<_>>();
        let cipher_added = evaluator.add_many_new(&ciphertexts);
        let decrypted = ckks_decrypt(&cipher_added, &encoder, &mut decryptor);
        let added_message = messages.iter().fold(vec![Complex64::default(); messages[0].len()], |acc, x| {
            acc.iter().zip(x.iter()).map(|(a, b)| a + b).collect::<Vec<_>>()
        });
        c64_vec_eq(&added_message, &decrypted);

        // Subtract
        let message1 = random_c64_vector(&context);
        let message2 = random_c64_vector(&context);
        let cipher1 = ckks_encrypt(&message1, &encoder, &encryptor, scale);
        let cipher2 = ckks_encrypt(&message2, &encoder, &encryptor, scale);
        let cipher3 = evaluator.sub_new(&cipher1, &cipher2);
        let decrypted = ckks_decrypt(&cipher3, &encoder, &mut decryptor);
        let subtracted_message = message1.iter().zip(message2.iter()).map(|(x, y)| x - y).collect::<Vec<_>>();
        c64_vec_eq(&subtracted_message, &decrypted);

        // Multiply
        let message1 = random_c64_vector(&context);
        let message2 = random_c64_vector(&context);
        let cipher1 = ckks_encrypt(&message1, &encoder, &encryptor, scale);
        let cipher2 = ckks_encrypt(&message2, &encoder, &encryptor, scale);
        let cipher3 = evaluator.multiply_new(&cipher1, &cipher2);
        let decrypted = ckks_decrypt(&cipher3, &encoder, &mut decryptor);
        let multiplied_message = message1.iter().zip(message2.iter()).map(|(x, y)| x * y).collect::<Vec<_>>();
        c64_vec_eq(&multiplied_message, &decrypted);

        // Square
        let message = random_c64_vector(&context);
        let cipher1 = ckks_encrypt(&message, &encoder, &encryptor, scale);
        let cipher2 = evaluator.square_new(&cipher1);
        let decrypted = ckks_decrypt(&cipher2, &encoder, &mut decryptor);
        let squared_message = message.iter()
            .map(|x| x * x).collect::<Vec<_>>();
        c64_vec_eq(&squared_message, &decrypted);

        // Add plain
        let message1 = random_c64_vector(&context);
        let message2 = random_c64_vector(&context);
        let cipher1 = ckks_encrypt(&message1, &encoder, &encryptor, scale);
        let plain1 = encoder.encode_c64_array_new(&message2, None, scale);
        let cipher3 = evaluator.add_plain_new(&cipher1, &plain1);
        let decrypted = ckks_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter())
            .map(|(x, y)| x + y).collect::<Vec<_>>();
        c64_vec_eq(&added_message, &decrypted);

        // Substract plain
        let message1 = random_c64_vector(&context);
        let message2 = random_c64_vector(&context);
        let cipher1 = ckks_encrypt(&message1, &encoder, &encryptor, scale);
        let plain1 = encoder.encode_c64_array_new(&message2, None, scale);
        let cipher3 = evaluator.sub_plain_new(&cipher1, &plain1);
        let decrypted = ckks_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter())
            .map(|(x, y)| x - y).collect::<Vec<_>>();
        c64_vec_eq(&added_message, &decrypted);

        // Multiply plain
        let message1 = random_c64_vector(&context);
        let message2 = random_c64_vector(&context);
        let cipher1 = ckks_encrypt(&message1, &encoder, &encryptor, scale);
        let plain1 = encoder.encode_c64_array_new(&message2, None, scale);
        let cipher3 = evaluator.multiply_plain_new(&cipher1, &plain1);
        let decrypted = ckks_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter())
            .map(|(x, y)| x * y).collect::<Vec<_>>();
        c64_vec_eq(&added_message, &decrypted);
        
        // Multiply plain single
        let message1 = random_c64_vector(&context);
        let message2 = random_c64_vector(&context);
        let message2 = vec![message2[0]; message2.len()];
        let cipher1 = ckks_encrypt(&message1, &encoder, &encryptor, scale);
        let plain1 = encoder.encode_c64_array_new(&message2, None, scale);
        let cipher3 = evaluator.multiply_plain_new(&cipher1, &plain1);
        let decrypted = ckks_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter())
            .map(|(x, y)| x * y).collect::<Vec<_>>();
        c64_vec_eq(&added_message, &decrypted);

        // Add INTT
        let message1 = random_c64_vector(&context);
        let message2 = random_c64_vector(&context);
        let mut cipher1 = ckks_encrypt(&message1, &encoder, &encryptor, scale);
        let mut cipher2 = ckks_encrypt(&message2, &encoder, &encryptor, scale);
        evaluator.transform_from_ntt_inplace(&mut cipher1);
        evaluator.transform_from_ntt_inplace(&mut cipher2);
        let mut cipher3 = evaluator.add_new(&cipher1, &cipher2);
        evaluator.transform_to_ntt_inplace(&mut cipher3);
        let decrypted = ckks_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter()).map(|(x, y)| x + y).collect::<Vec<_>>();
        c64_vec_eq(&added_message, &decrypted);

        let (context, encoder, keygen, encryptor, mut decryptor, evaluator) 
            = create_ckks_suite(64, vec![30, 30, 30, 30], true);
        let scale = (1<<30) as f64;

        let relin_keys = keygen.create_relin_keys(false);
        let message = random_c64_vector(&context);
        let cipher1 = ckks_encrypt(&message, &encoder, &encryptor, scale);
        let mut cipher2 = evaluator.square_new(&cipher1);
        evaluator.relinearize_inplace(&mut cipher2, &relin_keys);
        let decrypted = ckks_decrypt(&cipher2, &encoder, &mut decryptor);
        let squared_message = message.iter()
            .map(|x| x * x).collect::<Vec<_>>();
        c64_vec_eq(&squared_message, &decrypted);

        // Rescale
        let scale = (1u64<<60) as f64;
        let message = random_c64_vector(&context);
        let mut cipher = ckks_encrypt(&message, &encoder, &encryptor, scale);
        evaluator.rescale_to_next_inplace(&mut cipher);
        let decrypted = ckks_decrypt(&cipher, &encoder, &mut decryptor);
        c64_vec_eq(&message, &decrypted);

        // Rotate vector
        let galois_keys = keygen.create_galois_keys(false);
        let message = random_c64_vector(&context);
        let mut cipher = ckks_encrypt(&message, &encoder, &encryptor, scale);
        evaluator.rotate_vector_inplace(&mut cipher, 1, &galois_keys);
        let decrypted = ckks_decrypt(&cipher, &encoder, &mut decryptor);
        let rotated_message = message.iter().cycle().skip(1)
            .take(message.len()).copied().collect::<Vec<_>>();
        c64_vec_eq(&rotated_message, &decrypted);

        let message = random_c64_vector(&context);
        let mut cipher = ckks_encrypt(&message, &encoder, &encryptor, scale);
        evaluator.rotate_vector_inplace(&mut cipher, 11, &galois_keys);
        let decrypted = ckks_decrypt(&cipher, &encoder, &mut decryptor);
        let rotated_message = message.iter().cycle().skip(11)
            .take(message.len()).copied().collect::<Vec<_>>();
        c64_vec_eq(&rotated_message, &decrypted);

        let message = random_c64_vector(&context);
        let mut cipher = ckks_encrypt(&message, &encoder, &encryptor, scale);
        evaluator.complex_conjugate_inplace(&mut cipher, &galois_keys);
        let decrypted = ckks_decrypt(&cipher, &encoder, &mut decryptor);
        let rotated_message = message.iter()
            .map(|&x| x.conj()).collect::<Vec<_>>();
        c64_vec_eq(&rotated_message, &decrypted);

    }


    #[test]
    fn test_bgv_suite() {
        let (context, encoder, _keygen, encryptor, mut decryptor, evaluator) 
            = create_bgv_suite(32, 30, vec![40, 40, 40], false);
        let plain_modulus = encoder.get_plain_modulus();

        // Negate
        let message = random_u64_vector(&context);
        let mut cipher = bgv_encrypt(&message, &encoder, &encryptor);
        evaluator.negate_inplace(&mut cipher);
        let decrypted = bgv_decrypt(&cipher, &encoder, &mut decryptor);
        let negated_message = message.iter().map(|x| plain_modulus - x).collect::<Vec<_>>();
        assert_eq!(negated_message, decrypted);

        // Add
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let cipher1 = bgv_encrypt(&message1, &encoder, &encryptor);
        let cipher2 = bgv_encrypt(&message2, &encoder, &encryptor);
        let cipher3 = evaluator.add_new(&cipher1, &cipher2);
        let decrypted = bgv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter()).map(|(x, y)| (x + y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);

        // Add many
        let messages = (0..10).map(|_| random_u64_vector(&context)).collect::<Vec<_>>();
        let ciphertexts = messages.iter().map(|x| bgv_encrypt(x, &encoder, &encryptor)).collect::<Vec<_>>();
        let cipher_added = evaluator.add_many_new(&ciphertexts);
        let decrypted = bgv_decrypt(&cipher_added, &encoder, &mut decryptor);
        let added_message = messages.iter().fold(vec![0u64; messages[0].len()], |acc, x| {
            acc.iter().zip(x.iter()).map(|(a, b)| (a + b) % plain_modulus).collect::<Vec<_>>()
        });
        assert_eq!(added_message, decrypted);

        // Subtract
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let cipher1 = bgv_encrypt(&message1, &encoder, &encryptor);
        let cipher2 = bgv_encrypt(&message2, &encoder, &encryptor);
        let cipher3 = evaluator.sub_new(&cipher1, &cipher2);
        let decrypted = bgv_decrypt(&cipher3, &encoder, &mut decryptor);
        let subtracted_message = message1.iter().zip(message2.iter()).map(|(x, y)| (x + plain_modulus - y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(subtracted_message, decrypted);

        // Multiply
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let cipher1 = bgv_encrypt(&message1, &encoder, &encryptor);
        let cipher2 = bgv_encrypt(&message2, &encoder, &encryptor);
        let cipher3 = evaluator.multiply_new(&cipher1, &cipher2);
        let decrypted = bgv_decrypt(&cipher3, &encoder, &mut decryptor);
        let multiplied_message = message1.iter().zip(message2.iter()).map(|(x, y)| (x * y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(multiplied_message, decrypted);

        // Square
        let message = random_u64_vector(&context);
        let cipher1 = bgv_encrypt(&message, &encoder, &encryptor);
        let cipher2 = evaluator.square_new(&cipher1);
        let decrypted = bgv_decrypt(&cipher2, &encoder, &mut decryptor);
        let squared_message = message.iter()
            .map(|x| (x * x) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(squared_message, decrypted);

        // Add plain
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let cipher1 = bgv_encrypt(&message1, &encoder, &encryptor);
        let plain1 = encoder.encode_new(&message2);
        let cipher3 = evaluator.add_plain_new(&cipher1, &plain1);
        let decrypted = bgv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter()).map(|(x, y)| (x + y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);

        // Substract plain
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let cipher1 = bgv_encrypt(&message1, &encoder, &encryptor);
        let plain1 = encoder.encode_new(&message2);
        let cipher3 = evaluator.sub_plain_new(&cipher1, &plain1);
        let decrypted = bgv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter())
            .map(|(x, y)| (x + plain_modulus - y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);

        // Multiply plain
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let cipher1 = bgv_encrypt(&message1, &encoder, &encryptor);
        let plain1 = encoder.encode_new(&message2);
        let cipher3 = evaluator.multiply_plain_new(&cipher1, &plain1);
        let decrypted = bgv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter())
            .map(|(x, y)| (x * y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);
        
        // Multiply plain single
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let message2 = vec![message2[0]; message2.len()];
        let cipher1 = bgv_encrypt(&message1, &encoder, &encryptor);
        let plain1 = encoder.encode_new(&message2);
        let cipher3 = evaluator.multiply_plain_new(&cipher1, &plain1);
        let decrypted = bgv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter())
            .map(|(x, y)| (x * y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);

        // Add NTT
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let mut cipher1 = bfv_encrypt(&message1, &encoder, &encryptor);
        let mut cipher2 = bfv_encrypt(&message2, &encoder, &encryptor);
        evaluator.transform_to_ntt_inplace(&mut cipher1);
        evaluator.transform_to_ntt_inplace(&mut cipher2);
        let mut cipher3 = evaluator.add_new(&cipher1, &cipher2);
        evaluator.transform_from_ntt_inplace(&mut cipher3);
        let decrypted = bfv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter()).map(|(x, y)| (x + y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);

        // Mul NTT plain
        let message1 = random_u64_vector(&context);
        let message2 = random_u64_vector(&context);
        let mut cipher1 = bfv_encrypt(&message1, &encoder, &encryptor);
        let mut plain2 = encoder.encode_new(&message2);
        evaluator.transform_to_ntt_inplace(&mut cipher1);
        evaluator.transform_plain_to_ntt_inplace(&mut plain2, cipher1.parms_id());
        let mut cipher3 = evaluator.multiply_plain_new(&cipher1, &plain2);
        evaluator.transform_from_ntt_inplace(&mut cipher3);
        let decrypted = bfv_decrypt(&cipher3, &encoder, &mut decryptor);
        let added_message = message1.iter().zip(message2.iter()).map(|(x, y)| (x * y) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(added_message, decrypted);

        let (context, encoder, keygen, encryptor, mut decryptor, evaluator) 
            = create_bfv_suite(32, 30, vec![40, 40, 40], true);
        let plain_modulus = encoder.get_plain_modulus();

        // Square relin
        let relin_keys = keygen.create_relin_keys(false);
        let message1 = random_u64_vector(&context);
        let cipher1 = bgv_encrypt(&message1, &encoder, &encryptor);
        let mut cipher2 = evaluator.square_new(&cipher1);
        evaluator.relinearize_inplace(&mut cipher2, &relin_keys);
        let decrypted = bgv_decrypt(&cipher2, &encoder, &mut decryptor);
        let squared_message = message1.iter()
            .map(|x| (x * x) % plain_modulus).collect::<Vec<_>>();
        assert_eq!(squared_message, decrypted);

        // Mod switch
        let message = random_u64_vector(&context);
        let mut cipher = bgv_encrypt(&message, &encoder, &encryptor);
        evaluator.mod_switch_to_next_inplace(&mut cipher);
        let decrypted = bgv_decrypt(&cipher, &encoder, &mut decryptor);
        assert_eq!(message, decrypted);

        // Rotate rows
        let galois_keys = keygen.create_galois_keys(false);
        let message = random_u64_vector(&context);
        let mut cipher = bfv_encrypt(&message, &encoder, &encryptor);
        evaluator.rotate_rows_inplace(&mut cipher, 1, &galois_keys);
        let decrypted = bfv_decrypt(&cipher, &encoder, &mut decryptor);
        let rotated_message = rotate_rows(message, 1);
        assert_eq!(rotated_message, decrypted);
        
        let message = random_u64_vector(&context);
        let mut cipher = bfv_encrypt(&message, &encoder, &encryptor);
        evaluator.rotate_rows_inplace(&mut cipher, 11, &galois_keys);
        let decrypted = bfv_decrypt(&cipher, &encoder, &mut decryptor);
        let rotated_message = rotate_rows(message, 11);
        assert_eq!(rotated_message, decrypted);
        
        let message = random_u64_vector(&context);
        let mut cipher = bfv_encrypt(&message, &encoder, &encryptor);
        evaluator.rotate_columns_inplace(&mut cipher, &galois_keys);
        let decrypted = bfv_decrypt(&cipher, &encoder, &mut decryptor);
        let rotated_message = rotate_columns(message);
        assert_eq!(rotated_message, decrypted);

    }

}