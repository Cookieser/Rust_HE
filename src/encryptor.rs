use std::sync::{Arc, RwLock};

use crate::{
    util::{self, get_significant_uint64_count_uint, BlakeRNG}, polymod,
    Plaintext, Ciphertext,
    HeContext, PublicKey, SecretKey, ValCheck, ParmsID, SchemeType, PARMS_ID_ZERO, ExpandSeed
};

/// Encrypts [Plaintext] objects into [Ciphertext] objects.
/// 
/// Constructing an Encryptor
/// requires a [HeContext] with valid encryption parameters, the public key and/or
/// the secret key. If an Encrytor is given a secret key, it supports symmetric-key
/// encryption. If an Encryptor is given a public key, it supports asymmetric-key
/// encryption.
/// 
/// ## Inplace and new variants
/// For the encrypt function we provide two variants: one performs in place,
/// and the other creates a new object.
/// 
/// ## NTT form
/// When using the BFV/BGV scheme, all plaintext and ciphertexts should
/// remain by default in the usual coefficient representation, i.e. not in NTT form.
/// When using the CKKS scheme, all plaintexts and ciphertexts
/// should remain by default in NTT form. We call these scheme-specific NTT states
/// the "default NTT form". Decryption requires the input ciphertexts to be in
/// the default NTT form, and will throw an exception if this is not the case.
pub struct Encryptor {
    context: Arc<HeContext>,
    public_key: Option<PublicKey>,
    secret_key: Option<SecretKey>,
}

impl Encryptor {

    /// Get the secret key use by the encryptor.
    pub fn secret_key(&self) -> &SecretKey {
        self.secret_key.as_ref().unwrap()
    }

    /// Get the public key use by the encryptor.
    pub fn public_key(&self) -> &PublicKey {
        self.public_key.as_ref().unwrap()
    }

    /// Creates a new Encryptor object.
    /// Usually the user just set the encryption key ([PublicKey] and/or [SecretKey]) after creating an instance.
    /// ```rust
    /// use heathcliff::*;
    /// let poly_modulus_degree = 8192;
    /// let parms = EncryptionParameters::new(SchemeType::BFV)
    ///     .set_poly_modulus_degree(poly_modulus_degree)
    ///     .set_coeff_modulus(&CoeffModulus::create(poly_modulus_degree, vec![60, 40, 40, 60]))
    ///     .set_plain_modulus(&PlainModulus::batching(poly_modulus_degree, 20));
    /// let context = HeContext::new(parms, true, SecurityLevel::Tc128);
    /// let keygen = KeyGenerator::new(context.clone());
    /// let encryptor = Encryptor::new(context.clone())
    ///     .set_public_key(keygen.create_public_key(false));
    ///     // .. or you could use .set_secret_key(keygen.secret_key().clone())
    ///     // to enable symmetric encryption
    /// ```
    pub fn new(context: Arc<HeContext>) -> Self {
        if !context.parameters_set() {
            panic!("[Invalid argument] Encryption parameters not set correctly.");
        }
        Self {
            context,
            public_key: None,
            secret_key: None,
        }
    }

    /// Set the secret key use by the encryptor.
    /// See [Encryptor::new] for an example with public key. The usage of a secret key
    /// is similar.
    pub fn set_secret_key(mut self, secret_key: SecretKey) -> Self {
        if !secret_key.is_valid_for(&self.context) {
            panic!("[Invalid argument] Secret key not valid for HE context.");
        }
        self.secret_key = Some(secret_key);
        self
    }

    /// Set the public key use by the encryptor.
    /// See [Encryptor::new] for an example.
    pub fn set_public_key(mut self, public_key: PublicKey) -> Self {
        if public_key.contains_seed() {
            panic!("[Invalid argument] Seed should be expanded first.");
        }
        if !public_key.is_valid_for(&self.context) {
            panic!("[Invalid argument] Public key not valid for HE context.");
        }
        self.public_key = Some(public_key);
        self
    }

    fn encrypt_zero_internal(&self, parms_id: &ParmsID, is_asymmetric: bool, save_seed: bool, u_prng: Option<&mut BlakeRNG>, destination: &mut Ciphertext) {
        if is_asymmetric && self.public_key.is_none() {
            panic!("[Invalid argument] Public key is not set.");
        }
        if !is_asymmetric && self.secret_key.is_none() {
            panic!("[Invalid argument] Secret key is not set.");
        }
        if save_seed && is_asymmetric {
            panic!("[Invalid argument] Only symmetric encryption can save seed.");
        }
        // Verify params
        let context_data = self.context.get_context_data(parms_id);
        if context_data.is_none() {
            panic!("[Invalid argument] Parms id not valid for encryption params.");
        }
        let context_data = context_data.unwrap();
        let parms = context_data.parms();
        let coeff_modulus_size = parms.coeff_modulus().len();
        let coeff_count = parms.poly_modulus_degree();
        let poly_element_count = coeff_count * coeff_modulus_size;
        let mut is_ntt_form = false;
        if context_data.is_ckks() {
            is_ntt_form = true;
        } else if !context_data.is_bfv() && !context_data.is_bgv() {
            panic!("[Invalid argument] Unsupported scheme.");
        }

        // Resize destination and save results
        destination.resize(&self.context, parms_id, 2);

        if is_asymmetric {
            let prev_context_ptr = context_data.prev_context_data();
            if let Some(prev_context_data) = prev_context_ptr {
                // Requires modulus switching
                let prev_parms_id = prev_context_data.parms_id();
                let rns_tool = prev_context_data.rns_tool();

                // Zero encryption without modulus switching
                let mut temp = Ciphertext::new();
                if u_prng.is_none() {
                    util::rlwe::encrypt_zero::asymmetric(
                        self.public_key(), &self.context, prev_parms_id, is_ntt_form, &mut temp);
                } else {
                    util::rlwe::encrypt_zero::asymmetric_with_u_prng(
                        self.public_key(), &self.context, prev_parms_id, is_ntt_form, u_prng.unwrap(), &mut temp);
                }
                
                // Modulus switching
                for i in 0..temp.size() {
                    if context_data.is_ckks() {
                        rns_tool.divide_and_round_q_last_ntt_inplace(
                            temp.poly_mut(i), 
                            prev_context_data.small_ntt_tables())
                    } else if context_data.is_bfv() {
                        rns_tool.divide_and_round_q_last_inplace(
                            temp.poly_mut(i));
                    } else if context_data.is_bgv() {
                        rns_tool.mod_t_and_divide_q_last_inplace(
                            temp.poly_mut(i));
                    }
                    destination.poly_mut(i).copy_from_slice(&temp.poly(i)[..poly_element_count]);
                }
                destination.set_parms_id(*parms_id);
                destination.set_is_ntt_form(is_ntt_form);
                destination.set_scale(temp.scale());
                destination.set_correction_factor(temp.correction_factor());
            } else {
                // Does not require modulus switching
                if u_prng.is_none() {
                    util::rlwe::encrypt_zero::asymmetric(
                        self.public_key(), &self.context, parms_id, is_ntt_form, destination);
                } else {
                    util::rlwe::encrypt_zero::asymmetric_with_u_prng(
                        self.public_key(), &self.context, parms_id, is_ntt_form, u_prng.unwrap(), destination);
                }
            }
        } else {
            // Does not require modulus switching
            if u_prng.is_none() {
                util::rlwe::encrypt_zero::symmetric(
                    self.secret_key(), &self.context, parms_id, is_ntt_form, save_seed, destination);
            } else {
                util::rlwe::encrypt_zero::symmetric_with_c1_prng(
                    self.secret_key(), &self.context, parms_id, is_ntt_form, u_prng.unwrap(), save_seed, destination);
            }
        }

    }

    fn encrypt_internal(&self, plain: &Plaintext, is_asymmetric: bool, save_seed: bool, u_prng: Option<&mut BlakeRNG>, destination: &mut Ciphertext) {
        if is_asymmetric && self.public_key.is_none() {
            panic!("[Invalid argument] Public key is not set.");
        }
        if !is_asymmetric && self.secret_key.is_none() {
            panic!("[Invalid argument] Secret key is not set.");
        }
        if save_seed && is_asymmetric {
            panic!("[Invalid argument] Only symmetric encryption can save seed.");
        }
        // Verify params
        if !plain.is_valid_for(&self.context) {
            panic!("[Invalid argument] Plaintext not valid for HE context.");
        }
        let scheme = self.context.key_context_data().unwrap().parms().scheme();
        match scheme {
            SchemeType::BFV => {
                if plain.is_ntt_form() {
                    panic!("[Invalid argument] Plaintext is in NTT form.");
                }
                self.encrypt_zero_internal(self.context.first_parms_id(), is_asymmetric, save_seed, u_prng, destination);
                // Multiply plain by scalar coeff_div_plaintext and reposition if in upper-half.
                // Result gets added into the c_0 term of ciphertext (c_0,c_1).
                util::scaling_variant::multiply_add_plain(plain, self.context.first_context_data().unwrap().as_ref(), destination.poly_mut(0));
            },
            SchemeType::CKKS => {
                if !plain.is_ntt_form() {
                    panic!("[Invalid argument] Plaintext is not in NTT form.");
                }
                let context_data = self.context.get_context_data(plain.parms_id());
                if context_data.is_none() {
                    panic!("[Invalid argument] Plaintext not valid for encryption params.");
                }
                let context_data = context_data.unwrap();
                self.encrypt_zero_internal(plain.parms_id(), is_asymmetric, save_seed, u_prng, destination);
                let parms = context_data.parms();
                let coeff_modulus = parms.coeff_modulus();
                let coeff_count = parms.poly_modulus_degree();
                // The plaintext gets added into the c_0 term of ciphertext (c_0,c_1).
                polymod::add_inplace_p(
                    destination.poly_mut(0), 
                    plain.data(), 
                    coeff_count, 
                    coeff_modulus);
                destination.set_scale(plain.scale());
            },
            SchemeType::BGV => {
                if plain.is_ntt_form() {
                    panic!("[Invalid argument] Plaintext is in NTT form.");
                }
                self.encrypt_zero_internal(self.context.first_parms_id(), is_asymmetric, save_seed, u_prng, destination);
                // c_{0} = pk_{0}*u + p*e_{0} + M
                util::scaling_variant::add_plain(plain, self.context.first_context_data().unwrap().as_ref(), destination.poly_mut(0));
            }
            _ => {
                panic!("[Invalid argument] Unsupported scheme.");
            }
        }
    }

    /// Encrypt a plaintext at the first ciphertext level.
    /// 
    /// ```rust
    /// use heathcliff::create_bfv_decryptor_suite;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![30, 30, 30]);
    /// 
    /// let message = vec![1, 2, 3, 4];
    /// let encoded = encoder.encode_new(&message);
    /// let encrypted = encryptor.encrypt_new(&encoded);
    /// 
    /// let decrypted = decryptor.decrypt_new(&encrypted);
    /// let decoded = encoder.decode_new(&decrypted);
    /// assert_eq!(&decoded[..4], &message);
    /// assert_eq!(&decoded[4..], &vec![0; 4096 - 4]);
    /// ```
    pub fn encrypt(&self, plain: &Plaintext, destination: &mut Ciphertext) {
        self.encrypt_internal(plain, true, false, None, destination);
    }

    /// Same as [Self::encrypt] but with a BlakeRNG to sample u.
    pub fn encrypt_with_u_prng(&self, plain: &Plaintext, u_prng: &mut BlakeRNG, destination: &mut Ciphertext) {
        self.encrypt_internal(plain, true, false, Some(u_prng), destination);
    }

    /// Encrypt a plaintext at the first ciphertext level.
    /// See [Self::encrypt] for an example.
    pub fn encrypt_new(&self, plain: &Plaintext) -> Ciphertext {
        let mut destination = Ciphertext::new();
        self.encrypt_internal(plain, true, false, None, &mut destination);
        destination
    }

    /// Same as [Self::encrypt_new] but with a BlakeRNG to sample u.
    pub fn encrypt_new_with_u_prng(&self, plain: &Plaintext, u_prng: &mut BlakeRNG) -> Ciphertext {
        let mut destination = Ciphertext::new();
        self.encrypt_internal(plain, true, false, Some(u_prng), &mut destination);
        destination
    }

    /// Encrypt a plaintext consisting of zeros at the first ciphertext level.
    /// 
    /// ```rust
    /// use heathcliff::create_bfv_decryptor_suite;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![30, 30, 30]);
    /// let encrypted = encryptor.encrypt_zero_new();
    /// let decrypted = decryptor.decrypt_new(&encrypted);
    /// let decoded = encoder.decode_new(&decrypted);
    /// assert_eq!(decoded, vec![0; 4096]);
    /// ```
    pub fn encrypt_zero(&self, destination: &mut Ciphertext) {
        self.encrypt_zero_internal(self.context.first_parms_id(), true, false, None, destination);
    }

    /// Same as [Self::encrypt_zero] but with a BlakeRNG to sample u.
    pub fn encrypt_zero_with_u_prng(&self, u_prng: &mut BlakeRNG, destination: &mut Ciphertext) {
        self.encrypt_zero_internal(self.context.first_parms_id(), true, false, Some(u_prng), destination);
    }

    /// Encrypt a plaintext consisting of zeros at the first ciphertext level.
    /// See [Self::encrypt_zero] for an example.
    pub fn encrypt_zero_new(&self) -> Ciphertext {
        let mut destination = Ciphertext::new();
        self.encrypt_zero_internal(self.context.first_parms_id(), true, false, None, &mut destination);
        destination
    }

    /// Same as [Self::encrypt_zero_new] but with a BlakeRNG to sample u.
    pub fn encrypt_zero_new_with_u_prng(&self, u_prng: &mut BlakeRNG) -> Ciphertext {
        let mut destination = Ciphertext::new();
        self.encrypt_zero_internal(self.context.first_parms_id(), true, false, Some(u_prng), &mut destination);
        destination
    }

    /// Encrypt a plaintext consisting of zeros at the specified ciphertext level.
    /// 
    /// ```rust
    /// use heathcliff::create_bfv_decryptor_suite;
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![30, 30, 30]);
    /// let encrypted = encryptor.encrypt_zero_new_at(context.last_parms_id());
    /// let decrypted = decryptor.decrypt_new(&encrypted);
    /// let decoded = encoder.decode_new(&decrypted);
    /// assert_eq!(decoded, vec![0; 4096]);
    /// ```
    pub fn encrypt_zero_at(&self, parms_id: &ParmsID, destination: &mut Ciphertext) {
        self.encrypt_zero_internal(parms_id, true, false, None, destination);
    }

    /// Same as [Self::encrypt_zero_at] but with a BlakeRNG to sample u.
    pub fn encrypt_zero_at_with_u_prng(&self, parms_id: &ParmsID, u_prng: &mut BlakeRNG, destination: &mut Ciphertext) {
        self.encrypt_zero_internal(parms_id, true, false, Some(u_prng), destination);
    }

    /// Encrypt a plaintext consisting of zeros at the specified ciphertext level.
    /// See [Self::encrypt_zero_at] for an example.
    pub fn encrypt_zero_new_at(&self, parms_id: &ParmsID) -> Ciphertext {
        let mut destination = Ciphertext::new();
        self.encrypt_zero_internal(parms_id, true, false, None, &mut destination);
        destination
    }

    /// Same as [Self::encrypt_zero_new_at] but with a BlakeRNG to sample u.
    pub fn encrypt_zero_new_at_with_u_prng(&self, parms_id: &ParmsID, u_prng: &mut BlakeRNG) -> Ciphertext {
        let mut destination = Ciphertext::new();
        self.encrypt_zero_internal(parms_id, true, false, Some(u_prng), &mut destination);
        destination
    }

    /// Encrypt a plaintext at the first ciphertext level.
    /// Similar to [Self::encrypt], but this uses symmetric encryption.
    /// **Note: This does not save seed! To enable seed saving, use [Self::encrypt_symmetric_new].**
    /// 
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Ciphertext, ExpandSeed};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![30, 30, 30]);
    /// 
    /// let message = vec![1, 2, 3, 4];
    /// let encoded = encoder.encode_new(&message);
    /// let mut encrypted = Ciphertext::new();
    /// encryptor.encrypt_symmetric(&encoded, &mut encrypted);
    /// assert!(!encrypted.contains_seed());
    /// 
    /// let decrypted = decryptor.decrypt_new(&encrypted);
    /// let decoded = encoder.decode_new(&decrypted);
    /// assert_eq!(&decoded[..4], &message);
    /// assert_eq!(&decoded[4..], &vec![0; 4096 - 4]);
    /// ```
    pub fn encrypt_symmetric(&self, plain: &Plaintext, destination: &mut Ciphertext) {
        self.encrypt_internal(plain, false, false, None, destination);
    }

    /// Same as [Self::encrypt_symmetric] but with a BlakeRNG to sample u.
    pub fn encrypt_symmetric_with_u_prng(&self, plain: &Plaintext, u_prng: &mut BlakeRNG, destination: &mut Ciphertext) {
        self.encrypt_internal(plain, false, false, Some(u_prng), destination);
    }

    /// Encrypt a plaintext at the first ciphertext level.
    /// Similar to [Self::encrypt_new], but this uses symmetric encryption.
    /// **Note: This saves seed! Seeds will be expanded during deserialization, or they can be expanded manually ([Ciphertext::expand_seed]).**
    /// 
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, ExpandSeed};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![30, 30, 30]);
    /// 
    /// let message = vec![1, 2, 3, 4];
    /// let encoded = encoder.encode_new(&message);
    /// let encrypted = encryptor.encrypt_symmetric_new(&encoded);
    /// assert!(encrypted.contains_seed());
    /// let encrypted = encrypted.expand_seed(&context);
    /// assert!(!encrypted.contains_seed());
    /// 
    /// let decrypted = decryptor.decrypt_new(&encrypted);
    /// let decoded = encoder.decode_new(&decrypted);
    /// assert_eq!(&decoded[..4], &message);
    /// assert_eq!(&decoded[4..], &vec![0; 4096 - 4]);
    /// ```
    pub fn encrypt_symmetric_new(&self, plain: &Plaintext) -> Ciphertext {
        let mut destination = Ciphertext::new();
        self.encrypt_internal(plain, false, true, None, &mut destination);
        destination
    }

    /// Same as [Self::encrypt_symmetric_new] but with a BlakeRNG to sample u.
    pub fn encrypt_symmetric_new_with_u_prng(&self, plain: &Plaintext, u_prng: &mut BlakeRNG) -> Ciphertext {
        let mut destination = Ciphertext::new();
        self.encrypt_internal(plain, false, true, Some(u_prng), &mut destination);
        destination
    }

    /// Encrypt a plaintext consisting of zeros at the first ciphertext level.
    /// Similar to [Self::encrypt_zero], but this uses symmetric encryption.
    /// **Note: This does not save seed! To enable seed saving, use [Self::encrypt_symmetric_new].**
    /// 
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Ciphertext, ExpandSeed};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![30, 30, 30]);
    /// let mut encrypted = Ciphertext::new();
    /// encryptor.encrypt_zero_symmetric(&mut encrypted);
    /// assert!(!encrypted.contains_seed());
    /// let decrypted = decryptor.decrypt_new(&encrypted);
    /// let decoded = encoder.decode_new(&decrypted);
    /// assert_eq!(decoded, vec![0; 4096]);
    /// ```
    pub fn encrypt_zero_symmetric(&self, destination: &mut Ciphertext) {
        self.encrypt_zero_internal(self.context.first_parms_id(), false, false, None, destination);
    }

    /// Same as [Self::encrypt_zero_symmetric] but with a BlakeRNG to sample u.
    pub fn encrypt_zero_symmetric_with_u_prng(&self, u_prng: &mut BlakeRNG, destination: &mut Ciphertext) {
        self.encrypt_zero_internal(self.context.first_parms_id(), false, false, Some(u_prng), destination);
    }

    /// Encrypt a plaintext consisting of zeros at the first ciphertext level.
    /// Similar to [Self::encrypt_zero_new], but this uses symmetric encryption.
    /// **Note: This saves seed! Seeds will be expanded during deserialization, or they can be expanded manually ([Ciphertext::expand_seed]).**
    /// 
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, ExpandSeed};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![30, 30, 30]);
    /// let encrypted = encryptor.encrypt_zero_symmetric_new();
    /// assert!(encrypted.contains_seed());
    /// let encrypted = encrypted.expand_seed(&context);
    /// assert!(!encrypted.contains_seed());
    /// let decrypted = decryptor.decrypt_new(&encrypted);
    /// let decoded = encoder.decode_new(&decrypted);
    /// assert_eq!(decoded, vec![0; 4096]);
    /// ```
    pub fn encrypt_zero_symmetric_new(&self) -> Ciphertext {
        let mut destination = Ciphertext::new();
        self.encrypt_zero_internal(self.context.first_parms_id(), false, true, None, &mut destination);
        destination
    }

    /// Same as [Self::encrypt_zero_symmetric_new] but with a BlakeRNG to sample u.
    pub fn encrypt_zero_symmetric_new_with_u_prng(&self, u_prng: &mut BlakeRNG) -> Ciphertext {
        let mut destination = Ciphertext::new();
        self.encrypt_zero_internal(self.context.first_parms_id(), false, true, Some(u_prng), &mut destination);
        destination
    }

    /// Encrypt a plaintext consisting of zeros at the specified ciphertext level.
    /// Similar to [Self::encrypt_zero_at], but this uses symmetric encryption.
    /// **Note: This does not save seed! To enable seed saving, use [Self::encrypt_symmetric_new].**
    /// 
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Ciphertext, ExpandSeed};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![30, 30, 30]);
    /// let mut encrypted = Ciphertext::new();
    /// encryptor.encrypt_zero_symmetric_at(context.last_parms_id(), &mut encrypted);
    /// assert!(!encrypted.contains_seed());
    /// let decrypted = decryptor.decrypt_new(&encrypted);
    /// let decoded = encoder.decode_new(&decrypted);
    /// assert_eq!(decoded, vec![0; 4096]);
    /// ```
    pub fn encrypt_zero_symmetric_at(&self, parms_id: &ParmsID, destination: &mut Ciphertext) {
        self.encrypt_zero_internal(parms_id, false, false, None, destination);
    }

    /// Same as [Self::encrypt_zero_symmetric_at] but with a BlakeRNG to sample u.
    pub fn encrypt_zero_symmetric_at_with_u_prng(&self, parms_id: &ParmsID, u_prng: &mut BlakeRNG, destination: &mut Ciphertext) {
        self.encrypt_zero_internal(parms_id, false, false, Some(u_prng), destination);
    }

    /// Encrypt a plaintext consisting of zeros at the first ciphertext level.
    /// Similar to [Self::encrypt_zero_new], but this uses symmetric encryption.
    /// **Note: This saves seed! Seeds will be expanded during deserialization, or they can be expanded manually ([Ciphertext::expand_seed]).**
    /// 
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, ExpandSeed};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![30, 30, 30]);
    /// let encrypted = encryptor.encrypt_zero_symmetric_new_at(context.last_parms_id());
    /// assert!(encrypted.contains_seed());
    /// let encrypted = encrypted.expand_seed(&context);
    /// assert!(!encrypted.contains_seed());
    /// let decrypted = decryptor.decrypt_new(&encrypted);
    /// let decoded = encoder.decode_new(&decrypted);
    /// assert_eq!(decoded, vec![0; 4096]);
    /// ```
    pub fn encrypt_zero_symmetric_new_at(&self, parms_id: &ParmsID) -> Ciphertext {
        let mut destination = Ciphertext::new();
        self.encrypt_zero_internal(parms_id, false, true, None, &mut destination);
        destination
    }

    /// Same as [Self::encrypt_zero_symmetric_new_at] but with a BlakeRNG to sample u.
    pub fn encrypt_zero_symmetric_new_at_with_u_prng(&self, parms_id: &ParmsID, u_prng: &mut BlakeRNG) -> Ciphertext {
        let mut destination = Ciphertext::new();
        self.encrypt_zero_internal(parms_id, false, true, Some(u_prng), &mut destination);
        destination
    }

}

/// Decrypts [Ciphertext] objects into [Plaintext] objects. 
/// 
/// Constructing a Decryptor
/// requires an HeContext with valid encryption parameters, and the secret key.
/// The Decryptor is also used to compute the invariant noise budget in a given
/// ciphertext.
/// 
/// ## Overloads
/// For the decrypt function we provide two overloads concerning the memory pool
/// used in allocations needed during the operation. In one overload the global
/// memory pool is used for this purpose, and in another overload the user can
/// supply a MemoryPoolHandle to be used instead. This is to allow one single
/// Decryptor to be used concurrently by several threads without running into
/// thread contention in allocations taking place during operations. For example,
/// one can share one single Decryptor across any number of threads, but in each
/// thread call the decrypt function by giving it a thread-local MemoryPoolHandle
/// to use. It is important for a developer to understand how this works to avoid
/// unnecessary performance bottlenecks.
/// 
/// ## NTT form
/// When using the BFV scheme (scheme_type::bfv), all plaintext and ciphertexts
/// should remain by default in the usual coefficient representation, i.e. not in
/// NTT form. When using the CKKS scheme (scheme_type::ckks), all plaintexts and
/// ciphertexts should remain by default in NTT form. We call these scheme-specific
/// NTT states the "default NTT form". Decryption requires the input ciphertexts
/// to be in the default NTT form, and will throw an exception if this is not the
/// case.
pub struct Decryptor {
    context: Arc<HeContext>,
    
    secret_key_array: RwLock<Vec<u64>>,
}

impl Decryptor {

    /// Creates a new Decryptor object.
    /// ```rust
    /// use heathcliff::*;
    /// let poly_modulus_degree = 8192;
    /// let parms = EncryptionParameters::new(SchemeType::BFV)
    ///     .set_poly_modulus_degree(poly_modulus_degree)
    ///     .set_coeff_modulus(&CoeffModulus::create(poly_modulus_degree, vec![60, 60, 60]))
    ///     .set_plain_modulus(&PlainModulus::batching(poly_modulus_degree, 20));
    /// let context = HeContext::new(parms, true, SecurityLevel::Tc128);
    /// let keygen = KeyGenerator::new(context.clone());
    /// let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
    /// ```
    pub fn new(context: Arc<HeContext>, secret_key: SecretKey) -> Self {
        if !context.parameters_set() {
            panic!("[Invalid argument] Encryption parameters are not set properly.");
        }
        if !secret_key.is_valid_for(context.as_ref()) {
            panic!("[Invalid argument] Secret key is not valid for encryption parameters.");
        }
        let key_context_data = context.key_context_data().unwrap();
        let parms = key_context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_count = parms.poly_modulus_degree();
        let coeff_modulus_size = coeff_modulus.len();

        let secret_key_array = secret_key.data().to_vec();
        assert_eq!(secret_key_array.len(), coeff_modulus_size * coeff_count);
        Self {
            context,
            secret_key_array: RwLock::new(secret_key_array),
        }
    }

    fn compute_secret_key_array(&self, max_power: usize) {
        let context_data = self.context.key_context_data().unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();

        // Aquire read lock
        let read_lock = self.secret_key_array.read().unwrap();
        assert!(read_lock.len() % (coeff_count * coeff_modulus_size) == 0);
        let old_size = read_lock.len() / (coeff_count * coeff_modulus_size);
        let new_size = old_size.max(max_power);
        if old_size == new_size {
            return;
        }

        // Need to extend the array
        // Compute powers of secret key until max_power
        let mut secret_key_array = vec![0; new_size * coeff_count * coeff_modulus_size];
        let poly_size = coeff_count * coeff_modulus_size;
        
        // Copy the old secret_key_array to the new one
        secret_key_array[..old_size * poly_size].copy_from_slice(&read_lock[..old_size * poly_size]);
        // Drop lock
        drop(read_lock);
        
        // Since all of the key powers in secret_key_array_ are already NTT transformed, to get the next one we simply
        // need to compute a dyadic product of the last one with the first one [which is equal to NTT(secret_key_)].
        for i in 0..new_size - old_size {
            unsafe { // We need to get the last element of the array as immutable, but the next one as mutable
                let last = secret_key_array[(old_size + i - 1) * poly_size..(old_size + i) * poly_size].as_mut_ptr();
                let last = std::slice::from_raw_parts(last, poly_size);
                let next = secret_key_array[(old_size + i) * poly_size..(old_size + i + 1) * poly_size].as_mut_ptr();
                let next = std::slice::from_raw_parts_mut(next, poly_size);
                let first = secret_key_array[..poly_size].as_ptr();
                let first = std::slice::from_raw_parts(first, poly_size);
                polymod::dyadic_product_p(last, first, coeff_count, coeff_modulus, next);
            }
        }

        // Aquire write lock
        let mut write_lock = self.secret_key_array.write().unwrap();

        // Do we still need to update size?
        assert!(secret_key_array.len() % (coeff_count * coeff_modulus_size) == 0);
        let old_size = write_lock.len() / (coeff_count * coeff_modulus_size);
        let new_size = old_size.max(max_power);
        if old_size == new_size {
            return;
        }

        // Acquire new array
        *write_lock = secret_key_array;
        
        // Lock is dropped automatically
    }

    // Compute c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q.
    // Store result in destination in RNS form.
    fn dot_product_ct_sk_array(&self, encrypted: &Ciphertext, destination: &mut[u64]) {
        let context_data = self.context.get_context_data(encrypted.parms_id()).unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();
        let encrypted_size = encrypted.size();
        let key_coeff_modulus_size = self.context.key_context_data().unwrap().parms().coeff_modulus().len();
        let ntt_tables = context_data.small_ntt_tables();
        let is_ntt_form = encrypted.is_ntt_form();

        // Make sure we have enough secret key powers computed
        self.compute_secret_key_array(encrypted_size - 1);

        let secret_key_array_binding = self.secret_key_array.read().unwrap();
        let secret_key_array = secret_key_array_binding.as_ref();
        if encrypted_size == 2 {
            unsafe {
                let c0 = std::slice::from_raw_parts(encrypted.poly(0).as_ptr(), coeff_count * coeff_modulus_size);
                let c1 = std::slice::from_raw_parts(encrypted.poly(1).as_ptr(), coeff_count * coeff_modulus_size);
                if is_ntt_form {
                    // put < c_1 * s > mod q in destination
                    polymod::dyadic_product_p(c1, secret_key_array, coeff_count, coeff_modulus, destination);
                    // add c_0 to the result; note that destination should be in the same (NTT) form as encrypted
                    polymod::add_inplace_p(destination, c0, coeff_count, coeff_modulus);
                } else {
                    destination.copy_from_slice(c1);
                    polymod::ntt_p(destination, coeff_count, ntt_tables);
                    polymod::dyadic_product_inplace_p(destination, secret_key_array, coeff_count, coeff_modulus);
                    polymod::intt_p(destination, coeff_count, ntt_tables);
                    polymod::add_inplace_p(destination, c0, coeff_count, coeff_modulus);
                }
            }
        } else {
            let poly_coeff_count = coeff_count * coeff_modulus_size;
            let key_poly_coeff_count = coeff_count * key_coeff_modulus_size;
            let mut encrypted_copy = encrypted.data()[poly_coeff_count..].to_vec();
            assert_eq!(encrypted_copy.len(), (encrypted_size - 1) * coeff_count * coeff_modulus_size);
            if !is_ntt_form {
                polymod::ntt_ps(&mut encrypted_copy, encrypted_size - 1, coeff_count, ntt_tables);
            }
            for i in 0..encrypted_size - 1 {
                polymod::dyadic_product_inplace_p(
                    &mut encrypted_copy[i*poly_coeff_count..(i+1)*poly_coeff_count], 
                    &secret_key_array[i*key_poly_coeff_count..i*key_poly_coeff_count+poly_coeff_count], 
                    coeff_count, coeff_modulus);
            }
            destination.fill(0);
            for i in 0..encrypted_size - 1 {
                polymod::add_inplace_p(
                    destination, 
                    &encrypted_copy[i*poly_coeff_count..(i+1)*poly_coeff_count],
                    coeff_count, coeff_modulus);
            }
            if !is_ntt_form {
                polymod::intt_p(destination, coeff_count, ntt_tables);
            }
            polymod::add_inplace_p(destination, encrypted.poly(0), coeff_count, coeff_modulus);
        }

    }

    /// Get the remaining noise budget in bits in a ciphertext.
    /// If the remaining noise budget is less than 1 bit, the ciphertext
    /// cannot be decrypted correctly.
    /// 
    /// ```rust
    /// use heathcliff::{create_bfv_decryptor_suite, Evaluator};
    /// let (params, context, encoder, keygen, encryptor, decryptor)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![35, 30, 35]);
    /// let evaluator = Evaluator::new(context.clone());
    /// 
    /// let mut ciphertext = encryptor.encrypt_zero_new();
    /// let budget = decryptor.invariant_noise_budget(&ciphertext);
    /// assert!(budget >= 30 && budget <= 40);
    /// assert_eq!(encoder.decode_new(&decryptor.decrypt_new(&ciphertext)), vec![0; 4096]);
    /// 
    /// evaluator.square_inplace(&mut ciphertext);
    /// let budget = decryptor.invariant_noise_budget(&ciphertext);
    /// assert!(budget <= 10);
    /// assert_eq!(encoder.decode_new(&decryptor.decrypt_new(&ciphertext)), vec![0; 4096]);
    /// 
    /// evaluator.square_inplace(&mut ciphertext);
    /// let budget = decryptor.invariant_noise_budget(&ciphertext);
    /// assert!(budget == 0);
    /// let wrong = encoder.decode_new(&decryptor.decrypt_new(&ciphertext));
    /// let non_zero_count = wrong.iter().filter(|x| **x != 0).count();
    /// assert!(non_zero_count > 4000);
    /// ```
    pub fn invariant_noise_budget(&self, encrypted: &Ciphertext) -> usize {
        if !encrypted.is_valid_for(&self.context) {
            panic!("[Invalid argument] Ciphertext is not valid for encryption parameters");
        }
        if encrypted.size() < util::HE_CIPHERTEXT_SIZE_MIN {
            panic!("[Invalid argument] Ciphertext is empty.");
        }
        let scheme = self.context.key_context_data().unwrap().parms().scheme();
        if scheme != SchemeType::BFV && scheme != SchemeType::BGV {
            panic!("[Logic error] Unsupported scheme.");
        }
        if encrypted.is_ntt_form() {
            panic!("[Invalid argument] Ciphertext is in NTT form.");
        }
        let context_data = self.context.get_context_data(encrypted.parms_id()).unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();
        let plain_modulus = parms.plain_modulus();
        let mut norm = vec![0; coeff_modulus_size];
        let mut noise_poly = vec![0; coeff_count * coeff_modulus_size];
        // Now need to compute c(s) - Delta*m (mod q)
        // Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
        // This is equal to Delta m + v where ||v|| < Delta/2.
        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q
        // in destination_poly.
        // Now do the dot product of encrypted_copy and the secret key array using NTT.
        // The secret key powers are already NTT transformed.
        self.dot_product_ct_sk_array(encrypted, noise_poly.as_mut_slice());
        
        // Multiply by plain_modulus and reduce mod coeff_modulus to get
        // coeffModulus()*noise.
        if scheme == SchemeType::BFV {
            polymod::multiply_scalar_inplace_p(
                &mut noise_poly, plain_modulus.value(), coeff_count, coeff_modulus);
        }
        
        // CRT-compose the noise
        context_data.rns_tool().base_q().compose_array(&mut noise_poly);
        
        // Next we compute the infinity norm mod parms.coeffModulus()
        poly_infty_norm(&noise_poly, coeff_modulus_size, context_data.total_coeff_modulus(), &mut norm);
        
        // The -1 accounts for scaling the invariant noise by 2;
        // note that we already took plain_modulus into account in compose
        // so no need to subtract log(plain_modulus) from this
        let bit_count_diff = 
            context_data.total_coeff_modulus_bit_count() as isize 
            - util::get_significant_bit_count_uint(&norm) as isize - 1;
        bit_count_diff.max(0) as usize
    }

    fn bfv_decrypt(&self, encrypted: &Ciphertext, destination: &mut Plaintext) {
        assert!(!encrypted.is_ntt_form(), "[Invalid argument] Ciphertext is in NTT form.");
        let context_data = self.context.get_context_data(encrypted.parms_id()).unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_count = parms.poly_modulus_degree();
        let coeff_modulus_size = coeff_modulus.len();
        
        // Firstly find c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q
        // This is equal to Delta m + v where ||v|| < Delta/2.
        // Add Delta / 2 and now we have something which is Delta * (m + epsilon) where epsilon < 1
        // Therefore, we can (integer) divide by Delta and the answer will round down to m.

        // Make a temp destination for all the arithmetic mod qi before calling FastBConverse
        let mut tmp_dest_modq = vec![0; coeff_count * coeff_modulus_size];

        // put < (c_1 , c_2, ... , c_{count-1}) , (s,s^2,...,s^{count-1}) > mod q in destination
        // Now do the dot product of encrypted_copy and the secret key array using NTT.
        // The secret key powers are already NTT transformed.
        self.dot_product_ct_sk_array(encrypted, &mut tmp_dest_modq);

        // Allocate a full size destination to write to
        destination.set_parms_id(PARMS_ID_ZERO);
        destination.resize(coeff_count);

        // Divide scaling variant using BEHZ FullRNS techniques
        context_data.rns_tool()
            .decrypt_scale_and_round(&tmp_dest_modq, destination.data_mut());

        // How many non-zero coefficients do we really have in the result?
        let plain_coeff_count = get_significant_uint64_count_uint(destination.data());
        
        // Resize destination to appropriate size
        destination.resize(plain_coeff_count.max(1));
    }

    fn ckks_decrypt(&self, encrypted: &Ciphertext, destination: &mut Plaintext) {
        assert!(encrypted.is_ntt_form(), "[Invalid argument] Ciphertext is not in NTT form.");
        let context_data = self.context.get_context_data(encrypted.parms_id()).unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_count = parms.poly_modulus_degree();
        let coeff_modulus_size = coeff_modulus.len();
        let rns_poly_u64_count = coeff_count * coeff_modulus_size;

        // Decryption consists in finding
        // c_0 + c_1 *s + ... + c_{count-1} * s^{count-1} mod q_1 * q_2 * q_3
        // as long as ||m + v|| < q_1 * q_2 * q_3.
        // This is equal to m + v where ||v|| is small enough.

        // Since we overwrite destination, we zeroize destination parameters
        // This is necessary, otherwise resize will throw an exception.
        destination.set_parms_id(PARMS_ID_ZERO);
        // Resize destination to appropriate size
        destination.resize(rns_poly_u64_count);

        // Do the dot product of encrypted and the secret key array using NTT.
        self.dot_product_ct_sk_array(encrypted, destination.data_mut());

        // Set destination parameters as in encrypted
        destination.set_parms_id(*encrypted.parms_id());
        destination.set_scale(encrypted.scale());
    }

    fn bgv_decrypt(&self, encrypted: &Ciphertext, destination: &mut Plaintext) {
        assert!(!encrypted.is_ntt_form(), "[Invalid argument] Ciphertext is in NTT form.");
        let context_data = self.context.get_context_data(encrypted.parms_id()).unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_count = parms.poly_modulus_degree();
        let coeff_modulus_size = coeff_modulus.len();
        let plain_modulus = parms.plain_modulus();
        
        let mut tmp_dest_modq = vec![0; coeff_count * coeff_modulus_size];

        self.dot_product_ct_sk_array(encrypted, &mut tmp_dest_modq);

        destination.set_parms_id(PARMS_ID_ZERO);
        destination.resize(coeff_count);

        // Divide scaling variant using BEHZ FullRNS techniques
        context_data.rns_tool()
            .decrypt_mod_t(&tmp_dest_modq, destination.data_mut());

        if encrypted.correction_factor() != 1 {
            let mut fix = 1;
            if !util::try_invert_u64_mod(encrypted.correction_factor(), plain_modulus, &mut fix) {
                panic!("[Logic error] Correction factor is not invertible.");
            }
            polymod::multiply_scalar_inplace(destination.data_mut(), fix, plain_modulus);
        }

        // How many non-zero coefficients do we really have in the result?
        let plain_coeff_count = get_significant_uint64_count_uint(destination.data());
        
        // Resize destination to appropriate size
        destination.resize(plain_coeff_count.max(1));
    }

    /// Decrypt a ciphertext into a plaintext. The noise budget should be positive to
    /// obtain the correct decryption. See [Self::invariant_noise_budget] for details.
    /// See the [Encryptor]'s encryption methods for examples.
    pub fn decrypt(&self, encrypted: &Ciphertext, destination: &mut Plaintext) {
        if encrypted.contains_seed() {
            panic!("[Invalid argument] Seed should be expanded first.");
        }
        if !encrypted.is_valid_for(&self.context) {
            panic!("[Invalid argument] Ciphertext is not valid for encryption parameters.");
        }
        if encrypted.size() < util::HE_CIPHERTEXT_SIZE_MIN {
            panic!("[Invalid argument] Ciphertext is empty.");
        }
        let scheme = self.context.first_context_data().unwrap().parms().scheme();
        match scheme {
            SchemeType::BFV => self.bfv_decrypt(encrypted, destination),
            SchemeType::CKKS => self.ckks_decrypt(encrypted, destination),
            SchemeType::BGV => self.bgv_decrypt(encrypted, destination),
            _ => panic!("[Invalid argument] Unsupported scheme."),
        }
    }

    /// See [Self::decrypt].
    pub fn decrypt_new(&self, encrypted: &Ciphertext) -> Plaintext {
        let mut destination = Plaintext::new();
        self.decrypt(encrypted, &mut destination);
        destination
    }

}

fn poly_infty_norm(poly: &[u64], coeff_u64_count: usize, modulus: &[u64], result: &mut[u64]) {
    assert_eq!(modulus.len(), coeff_u64_count);
    // Construct negative threshold: (modulus + 1) / 2
    let mut modulus_neg_threshold = vec![0; coeff_u64_count];
    util::half_round_up_uint(modulus, &mut modulus_neg_threshold);
    // Mod out the poly coefficients and choose a symmetric representative from [-modulus,modulus)
    result.fill(0);
    let mut coeff_abs_value = vec![0; coeff_u64_count];
    let coeff_count = poly.len() / coeff_u64_count;
    for i in 0..coeff_count {
        let polyi = &poly[i*coeff_u64_count..(i+1)*coeff_u64_count];
        if util::is_greater_than_or_equal_uint(polyi, &modulus_neg_threshold) {
            util::sub_uint(modulus, polyi, &mut coeff_abs_value);
        } else {
            coeff_abs_value.copy_from_slice(polyi);
        }
        if util::is_greater_than_uint(&coeff_abs_value, result) {
            result.copy_from_slice(&coeff_abs_value);
        }
    }
}

#[cfg(test)]
mod tests {
    use num_complex::Complex;
    use rand::Rng;

    use crate::{EncryptionParameters, CoeffModulus, SecurityLevel, KeyGenerator, batch_encoder::BatchEncoder, PlainModulus, CKKSEncoder, ExpandSeed};

    use super::*;

    fn get_random_vector(size: usize, modulus: u64) -> Vec<u64> {
        let mut rng = rand::thread_rng();
        let mut v = vec![0; size];
        for i in 0..size {
            v[i] = rng.gen::<u64>() % modulus;
        }
        v
    }

    #[test]
    fn test_bfv() {

        let parms = EncryptionParameters::new(SchemeType::BFV)
            .set_plain_modulus(&PlainModulus::batching(64, 30))
            .set_poly_modulus_degree(64)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![40]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let pk = keygen.create_public_key(false);
        let encryptor = Encryptor::new(context.clone()).set_public_key(pk);
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let encoder = BatchEncoder::new(context.clone());

        let message = get_random_vector(10, 1<<30);
        let plain = encoder.encode_new(&message);
        let cipher = encryptor.encrypt_new(&plain);
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        assert_eq!(message, decoded[..message.len()]);
        assert_eq!(vec![0; 54], decoded[message.len()..]);

        let message = get_random_vector(encoder.slot_count(), 1<<30);
        let plain = encoder.encode_new(&message);
        let cipher = encryptor.encrypt_new(&plain);
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        assert_eq!(message, decoded);

        let parms = EncryptionParameters::new(SchemeType::BFV)
            .set_plain_modulus(&PlainModulus::batching(128, 30))
            .set_poly_modulus_degree(128)
            .set_coeff_modulus(&CoeffModulus::create(128, vec![40; 2]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let pk = keygen.create_public_key(false);
        let encryptor = Encryptor::new(context.clone()).set_public_key(pk);
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let encoder = BatchEncoder::new(context.clone());

        let message = get_random_vector(encoder.slot_count(), 1<<30);
        let plain = encoder.encode_new(&message);
        let cipher = encryptor.encrypt_new(&plain);
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        assert_eq!(message, decoded);

        let parms = EncryptionParameters::new(SchemeType::BFV)
            .set_plain_modulus(&PlainModulus::batching(256, 30))
            .set_poly_modulus_degree(256)
            .set_coeff_modulus(&CoeffModulus::create(256, vec![40; 3]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let pk = keygen.create_public_key(false);
        let encryptor = Encryptor::new(context.clone()).set_public_key(pk).set_secret_key(keygen.secret_key().clone());
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let encoder = BatchEncoder::new(context.clone());

        let message = get_random_vector(encoder.slot_count(), 1<<30);
        let plain = encoder.encode_new(&message);
        let cipher = encryptor.encrypt_new(&plain);
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        assert_eq!(message, decoded);

        let message = get_random_vector(encoder.slot_count(), 1<<30);
        let plain = encoder.encode_new(&message);
        let mut cipher = Ciphertext::new();
        encryptor.encrypt_symmetric(&plain, &mut cipher);
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        assert_eq!(message, decoded);

    }

    
    #[test]
    fn test_bgv() {
        let parms = EncryptionParameters::new(SchemeType::BGV)
            .set_plain_modulus(&PlainModulus::batching(64, 30))
            .set_poly_modulus_degree(64)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![40, 40, 40]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let pk = keygen.create_public_key(false);
        let encryptor = Encryptor::new(context.clone()).set_public_key(pk).set_secret_key(keygen.secret_key().clone());
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let encoder = BatchEncoder::new(context.clone());

        let message = vec![1,2,3,4,5,6,7,8,9,10];
        let plain = encoder.encode_new(&message);
        let cipher = encryptor.encrypt_new(&plain);
        let decrypted = decryptor.decrypt_new(&cipher);
        assert_eq!(plain.data(), decrypted.data());
        let decoded = encoder.decode_new(&decrypted);
        assert_eq!(message, decoded[..message.len()]);
        assert_eq!(vec![0; 54], decoded[message.len()..]);

        let message = get_random_vector(encoder.slot_count(), 1<<30);
        let plain = encoder.encode_new(&message);
        let mut cipher = Ciphertext::new();
        encryptor.encrypt_symmetric(&plain, &mut cipher);
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        assert_eq!(message, decoded);

    }

    #[test]
    fn test_ckks() {
        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(64)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![40, 40, 40]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let pk = keygen.create_public_key(false);
        let encryptor = Encryptor::new(context.clone()).set_public_key(pk).set_secret_key(keygen.secret_key().clone());
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let encoder = CKKSEncoder::new(context.clone());

        let message = (1..=10).map(|x| Complex::new(x as f64, 0.0)).collect::<Vec<_>>();
        let scale = (1<<16) as f64;
        let plain = encoder.encode_c64_array_new(&message, None, scale);
        let cipher = encryptor.encrypt_new(&plain);
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        for i in 0..message.len() {
            assert!((message[i].re - decoded[i].re).abs() < 0.5);
        }
        for i in message.len() .. decoded.len() {
            assert!((decoded[i].re).abs() < 0.5);
        }

        let message = get_random_vector(encoder.slots(), 1<<30)
            .into_iter().map(|x| Complex::new(x as f64, 0.0)).collect::<Vec<_>>();
        let plain = encoder.encode_c64_array_new(&message, None, scale);
        let mut cipher = Ciphertext::new();
        encryptor.encrypt_symmetric(&plain, &mut cipher);
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        for i in 0..message.len() {
            assert!((message[i].re - decoded[i].re).abs() < 0.5);
        }
    }

    #[test]
    fn test_seed_expand() {
        let parms = EncryptionParameters::new(SchemeType::BFV)
            .set_plain_modulus(&PlainModulus::batching(64, 30))
            .set_poly_modulus_degree(64)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![40]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_secret_key(keygen.secret_key().clone());
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let encoder = BatchEncoder::new(context.clone());

        let message = get_random_vector(encoder.slot_count(), 1<<30);
        let plain = encoder.encode_new(&message);
        let cipher = encryptor.encrypt_symmetric_new(&plain);
        assert!(cipher.contains_seed());
        let cipher = cipher.expand_seed(&context);
        assert!(!cipher.contains_seed());
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        assert_eq!(message, decoded);

        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(64)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![40, 40, 40]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let pk = keygen.create_public_key(false);
        let encryptor = Encryptor::new(context.clone()).set_public_key(pk).set_secret_key(keygen.secret_key().clone());
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let encoder = CKKSEncoder::new(context.clone());

        let scale = (1<<16) as f64;
        let message = get_random_vector(encoder.slots(), 1<<30)
            .into_iter().map(|x| Complex::new(x as f64, 0.0)).collect::<Vec<_>>();
        let plain = encoder.encode_c64_array_new(&message, None, scale);
        let cipher = encryptor.encrypt_symmetric_new(&plain);
        assert!(cipher.contains_seed());
        let cipher = cipher.expand_seed(&context);
        assert!(!cipher.contains_seed());
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        for i in 0..message.len() {
            assert!((message[i].re - decoded[i].re).abs() < 0.5);
        }
    }

}