use rand::SeedableRng;

use crate::{ParmsID, PARMS_ID_ZERO, context::HeContext, util::{self, PRNGSeed, BlakeRNG}};


/// Struct to store a plaintext element. 
/// 
/// The data for the plaintext is a polynomial
/// with coefficients modulo the plaintext modulus. The degree of the plaintext
/// polynomial must be one less than the degree of the polynomial modulus. The
/// backing array always allocates one 64-bit word per each coefficient of the
/// polynomial.
/// 
/// When the scheme is BFV each coefficient of a plaintext is a 64-bit
/// word, but when the scheme is CKKS the plaintext is by default
/// stored in an NTT transformed form with respect to each of the primes in the
/// coefficient modulus. Thus, the size of the allocation that is needed is the
/// size of the coefficient modulus (number of primes) times the degree of the
/// polynomial modulus. In addition, a valid CKKS plaintext also store the parms_id
/// for the corresponding encryption parameters.
/// 
/// See [Ciphertext] for the class that stores ciphertexts.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Plaintext {
    coeff_count: usize,
    data: Vec<u64>,
    parms_id: ParmsID,
    scale: f64,
}

impl Default for Plaintext {
    fn default() -> Self {
        Plaintext { coeff_count: 0, data: vec![], parms_id: PARMS_ID_ZERO, scale: 1.0 }
    }
}

impl Plaintext {

    /// Creates an empty plaintext.
    pub fn new() -> Self {
        Plaintext::default()
    }

    /// The [ParmsID] of the plaintext. If the plaintext is not in NTT form, the
    /// [ParmsID] is set to zero.
    pub fn parms_id(&self) -> &ParmsID {
        &self.parms_id
    }

    /// Sets the [ParmsID] of the plaintext.
    pub fn set_parms_id(&mut self, parms_id: ParmsID) {
        self.parms_id = parms_id;
    }

    /// The scale of the plaintext for the CKKS scheme.
    pub fn scale(&self) -> f64 {
        self.scale
    }

    /// Sets the scale of the plaintext for the CKKS scheme.
    pub fn set_scale(&mut self, new_scale: f64) {
        self.scale = new_scale;
    }

    /// The number of coefficients in the plaintext.
    pub fn coeff_count(&self) -> usize {
        self.coeff_count
    }

    /// The number of non-zero coefficients in the plaintext.
    pub fn nonzero_coeff_count(&self) -> usize {
        util::get_nonzero_uint64_count_uint(&self.data)
    }

    /// The number of significant coefficients in the plaintext.
    pub fn significant_coeff_count(&self) -> usize {
        util::get_significant_uint64_count_uint(&self.data)
    }

    /// Set the number of coefficients in the plaintext.
    pub fn set_coeff_count(&mut self, coeff_count: usize)  {
        self.coeff_count = coeff_count;
    }

    /// Resizes the plaintext to the given coefficient count.
    /// The plaintext cannot be resized if it is in NTT form.
    pub fn resize(&mut self, coeff_count: usize) {
        if self.is_ntt_form() {
            panic!("[Logic error] Cannot reserve for NTT form")
        }
        self.coeff_count = coeff_count;
        self.data.resize(coeff_count, 0);
    }

    /// Is the plaintext in NTT form?
    pub fn is_ntt_form(&self) -> bool {
        self.parms_id != PARMS_ID_ZERO
    }
    
    /// Reserves memory for the plaintext to hold the given number of coefficients.
    /// The plaintext cannot be reserved if it is in NTT form.
    pub fn reserve(&mut self, coeff_count: usize) {
        if self.is_ntt_form() {
            panic!("[Logic error] Cannot reserve for NTT form")
        }
        self.data.reserve(coeff_count);
    }

    /// Returns a reference to the underlying data.
    pub fn data(&self) -> &Vec<u64> {
        &self.data
    }

    /// Returns a mutable reference to the underlying data.
    pub fn data_mut(&mut self) -> &mut Vec<u64> {
        &mut self.data
    }

    /// Returns a reference to the underlying data at the given index.
    pub fn data_at(&self, id: usize) -> u64 {
        self.data[id]
    }

    /* 
    /// Return a reference to RNS component at the specified index in the plaintext polynomial.
    pub fn component(&self, index: usize) -> &[u64] {
        &self.data[index * self.coeff_count..(index + 1) * self.coeff_count]
    }

    /// Return a mutable reference to RNS component at the specified index in the plaintext polynomial.
    pub fn component_mut(&mut self, index: usize) -> &mut [u64] {
        let start = index * self.coeff_count;
        &mut self.data[start..start + self.coeff_count]
    }
    */

}



/// Struct to store a ciphertext element. 
/// 
/// The data for a ciphertext consists
/// of two or more polynomials, which are in Microsoft SEAL stored in a CRT
/// form with respect to the factors of the coefficient modulus. This data
/// itself is not meant to be modified directly by the user, but is instead
/// operated on by functions in the Evaluator class. The size of the backing
/// array of a ciphertext depends on the encryption parameters and the size
/// of the ciphertext (at least 2). If the size of the ciphertext is T,
/// the poly_modulus_degree encryption parameter is N, and the number of
/// primes in the coeff_modulus encryption parameter is K, then the
/// ciphertext backing array requires precisely 8*N*K*T bytes of memory.
/// A ciphertext also carries with it the parms_id of its associated
/// encryption parameters, which is used to check the validity of the
/// ciphertext for homomorphic operations and decryption.
/// 
/// See [Plaintext] for the class that stores plaintexts.
#[derive(Clone)]
pub struct Ciphertext {
    size: usize,
    coeff_modulus_size: usize,
    poly_modulus_degree: usize,
    data: Vec<u64>,
    parms_id: ParmsID,
    scale: f64,
    is_ntt_form: bool,
    correction_factor: u64
}

impl Default for Ciphertext {
    fn default() -> Self {
        Ciphertext {
            size: 0,
            coeff_modulus_size: 0,
            poly_modulus_degree: 0,
            data: vec![],
            parms_id: PARMS_ID_ZERO,
            scale: 1.0,
            correction_factor: 1,
            is_ntt_form: false
        }
    }
}

pub const CIPHERTEXT_SEED_FLAG: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Provide seed expansion utilities for symmetric encryption and public key generation.
/// 
/// Storing a seed instead of a complete sampled polynomial saves communication
/// costs when sending ciphertexts and public keys.
pub trait ExpandSeed {
    /// Does the object contain a seed?
    fn contains_seed(&self) -> bool;
    /// Expand the seed to the full form.
    fn expand_seed(self, context: &HeContext) -> Self;
}

impl Ciphertext {

    /// Creates an empty plaintext.
    pub fn new() -> Self {Self::default()}

    /// Create a ciphertext from raw members.
    pub fn from_members(
        size: usize,
        coeff_modulus_size: usize,
        poly_modulus_degree: usize,
        data: Vec<u64>,
        parms_id: ParmsID,
        scale: f64,
        correction_factor: u64,
        is_ntt_form: bool
    ) -> Ciphertext {
        Ciphertext {
            size,
            coeff_modulus_size,
            poly_modulus_degree,
            data,
            parms_id,
            scale,
            correction_factor,
            is_ntt_form
        }
    }

    /// The [ParmsID] of the ciphertext.
    pub fn parms_id(&self) -> &ParmsID {
        &self.parms_id
    }

    /// Set the [ParmsID] of the ciphertext.
    pub fn set_parms_id(&mut self, parms_id: ParmsID) {
        self.parms_id = parms_id;
    }

    /// The scale of the ciphertext for the CKKS scheme.
    pub fn scale(&self) -> f64 {
        self.scale
    }

    /// Set the scale of the ciphertext for the CKKS scheme.
    pub fn set_scale(&mut self, scale: f64) {
        self.scale = scale;
    }

    /// The number of coeff modulus in the polynomials.
    pub fn coeff_modulus_size(&self) -> usize {
        self.coeff_modulus_size
    }

    /// The number of polynomials in the ciphertext,
    /// not the total count of coefficients in the polynomials.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Is the ciphertext in NTT form?
    pub fn is_ntt_form(&self) -> bool {
        self.is_ntt_form
    }

    /// Set if the ciphertext is in the NTT form.
    pub fn set_is_ntt_form(&mut self, is_ntt_form: bool) {
        self.is_ntt_form = is_ntt_form;
    }

    /// The correction factor for the BGV scheme.
    pub fn correction_factor(&self) -> u64 {
        self.correction_factor
    }

    /// Set the correction factor for the BGV scheme.
    pub fn set_correction_factor(&mut self, correction_factor: u64) {
        self.correction_factor = correction_factor;
    }

    /// The degree of the polynomial modulus.
    pub fn poly_modulus_degree(&self) -> usize {
        self.poly_modulus_degree
    }

    /// Returns a reference to the underlying data.
    pub fn data(&self) -> &Vec<u64> {
        &self.data
    }

    /// Returns a mutable reference to the underlying data.
    pub fn data_mut(&mut self) -> &mut Vec<u64> {
        &mut self.data
    }
    
    /// Returns a reference to the underlying data at the given index.
    pub fn data_at(&self, id: usize) -> u64 {
        self.data[id]
    }

    fn resize_internal(&mut self, size: usize, poly_modulus_degree: usize, coeff_modulus_size: usize) {
        if (size < util::HE_CIPHERTEXT_SIZE_MIN && size != 0) || (size > util::HE_CIPHERTEXT_SIZE_MAX) {
            panic!("[Invalid argument] Size invalid.");
        }

        let data_size = size * poly_modulus_degree * coeff_modulus_size;
        self.data.resize(data_size, 0);

        self.size = size;
        self.poly_modulus_degree = poly_modulus_degree;
        self.coeff_modulus_size = coeff_modulus_size;
    }

    /// Resize the ciphertext to the given size (number of polynomials).
    pub fn resize(&mut self, context: &HeContext, parms_id: &ParmsID, size: usize) {
        if !context.parameters_set() {
            panic!("[Invalid argument] Context is not set correctly.");
        }
        let context_data = context.get_context_data(parms_id);
        if context_data.is_none() {
            panic!("[Invalid argument] Invalid parms id.");
        }
        let context_data = context_data.unwrap();
        let parms = context_data.parms();
        self.parms_id = *parms_id;
        self.resize_internal(size, parms.poly_modulus_degree(), parms.coeff_modulus().len());
    }
    
    /// Returns a reference to the polynomial at the given index.
    pub fn poly(&self, id: usize) -> &[u64] {
        let d = self.poly_modulus_degree * self.coeff_modulus_size;
        &self.data[id * d..(id + 1) * d]
    }

    /// Returns a mutable reference to the polynomial at the given index.
    pub fn poly_mut(&mut self, id: usize) -> &mut [u64] {
        let d = self.poly_modulus_degree * self.coeff_modulus_size;
        &mut self.data[id * d..(id + 1) * d]
    }

    /// Returns a reference to the polynomials in the range [id_lower, id_upper).
    pub fn polys(&self, id_lower: usize, id_upper: usize) -> &[u64] {
        let d = self.poly_modulus_degree * self.coeff_modulus_size;
        &self.data[id_lower * d..id_upper * d]
    }

    /// Returns a mutable reference to the polynomials in the range [id_lower, id_upper).
    pub fn polys_mut(&mut self, id_lower: usize, id_upper: usize) -> &mut [u64] {
        let d = self.poly_modulus_degree * self.coeff_modulus_size;
        &mut self.data[id_lower * d..id_upper * d]
    }
    
    /// Returns a reference to the component of the polynomial at the given index.
    pub fn poly_component(&self, poly_id: usize, component_id: usize) -> &[u64] {
        let offset = self.poly_modulus_degree * (poly_id * self.coeff_modulus_size + component_id);
        &self.data[offset .. offset + self.poly_modulus_degree]
    }

    /// Returns a mutable reference to the component of the polynomial at the given index.
    pub fn poly_component_mut(&mut self, poly_id: usize, component_id: usize) -> &mut [u64] {
        let offset = self.poly_modulus_degree * (poly_id * self.coeff_modulus_size + component_id);
        &mut self.data[offset .. offset + self.poly_modulus_degree]
    }

    /// Is the ciphertext zero?
    /// Transparent ciphertexts could leak information about the secret key.
    pub fn is_transparent(&self) -> bool {
        if self.data.is_empty() || self.size < util::HE_CIPHERTEXT_SIZE_MIN {
            true
        } else {
            self.data.iter().all(|&x| x==0)
        }
    }

}

impl ExpandSeed for Ciphertext {

    fn contains_seed(&self) -> bool {
        if self.size != util::HE_CIPHERTEXT_SIZE_MIN {
            false
        } else {
            self.poly(1)[0] == CIPHERTEXT_SEED_FLAG
        }
    }

    fn expand_seed(mut self, context: &HeContext) -> Self {
        if !self.contains_seed() {
            panic!("[Invalid argument] Ciphertext does not contain seed.");
        }
        if self.size() != 2 {
            panic!("[Invalid argument] Seeded ciphertext has more than 2 polynomials.");
        }
        unsafe {
            let prng_seed_byte_count = std::mem::size_of::<PRNGSeed>();
            let seed_ptr = self.poly_component_mut(1, 0).as_mut_ptr().offset(1) as *mut u8;
            let seed_slice = std::slice::from_raw_parts(seed_ptr, prng_seed_byte_count);
            let mut seed = [0_u8; util::HE_PRNG_SEED_BYTES];
            seed.copy_from_slice(&seed_slice[..util::HE_PRNG_SEED_BYTES]);
            let prng_seed: PRNGSeed = PRNGSeed(seed);
            let mut ciphertext_prng = BlakeRNG::from_seed(prng_seed);
            util::rlwe::sample::uniform(&mut ciphertext_prng, context.get_context_data(self.parms_id()).unwrap().parms(), self.poly_mut(1));
        }
        self
    }
}