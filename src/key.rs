use std::{ops::{Index, IndexMut}, sync::{Arc, RwLock}};

use crate::{
    Plaintext, 
    ParmsID, 
    Ciphertext, 
    util::{self, rlwe, BlakeRNG}, 
    context::HeContext,
    polymod, ExpandSeed,
};


/// Struct to store a secret key.
/// 
/// Internally and mathematically the secret key is a [Plaintext] object.
/// 
/// - See [KeyGenerator] for the class that generates the secret key.
/// - See [PublicKey] for the class that stores the public key.
/// - See [RelinKeys] for the class that stores the relinearization keys.
/// - See [GaloisKeys] for the class that stores the Galois keys.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SecretKey {
    sk: Plaintext
}

impl SecretKey {
    
    /// Create a new secret key from a [Plaintext] object.
    pub fn new(sk: Plaintext) -> Self {
        Self {sk}
    }

    /// The [ParmsID] of the secret key.
    pub fn parms_id(&self) -> &ParmsID {
        self.sk.parms_id()
    }

    /// Set the [ParmsID] of the secret key.
    pub fn set_parms_id(&mut self, parms_id: ParmsID) {
        self.sk.set_parms_id(parms_id);
    }

    /// The inner [Plaintext] object.
    pub fn as_plaintext(&self) -> &Plaintext {
        &self.sk
    }

    /// The inner [Plaintext] object.
    pub fn as_plaintext_mut(&mut self) -> &mut Plaintext {
        &mut self.sk
    }

    /// The data of the secret key.
    pub fn data(&self) -> &Vec<u64> {
        self.sk.data()
    }

    /// The data of the secret key.
    pub fn data_mut(&mut self) -> &mut Vec<u64> {
        self.sk.data_mut()
    }

    /// The data of the secret key, at a given index.
    pub fn data_at(&self, index: usize) -> u64 {
        self.sk.data_at(index)
    }

}


/// Struct to store a public key.
/// 
/// Internally and mathematically the secret key is a [Ciphertext] object,
/// symmetrically encrypted with the secret key.
/// 
/// - See [KeyGenerator] for the class that generates the public key.
/// - See [SecretKey] for the class that stores the secret key.
/// - See [RelinKeys] for the class that stores the relinearization keys.
/// - See [GaloisKeys] for the class that stores the Galois keys.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PublicKey {
    pk: Ciphertext
}

impl PublicKey {
    
    /// Create a new secret key from a [Ciphertext] object.
    pub fn new(pk: Ciphertext) -> Self {
        Self {pk}
    }

    /// The [ParmsID] of the public key.
    pub fn parms_id(&self) -> &ParmsID {
        self.pk.parms_id()
    }

    /// Set the [ParmsID] of the public key.
    pub fn set_parms_id(&mut self, parms_id: ParmsID) {
        self.pk.set_parms_id(parms_id);
    }

    /// The inner [Ciphertext] object.
    pub fn as_ciphertext(&self) -> &Ciphertext {
        &self.pk
    }

    /// The inner [Ciphertext] object.
    pub fn as_ciphertext_mut(&mut self) -> &mut Ciphertext {
        &mut self.pk
    }

    /// The data of the public key.
    pub fn data(&self) -> &Vec<u64> {
        self.pk.data()
    }

    /// The data of the public key.
    pub fn data_mut(&mut self) -> &mut Vec<u64> {
        self.pk.data_mut()
    }

    /// The data of the public key, at a given index.
    pub fn data_at(&self, index: usize) -> u64 {
        self.pk.data_at(index)
    }

}

impl From<Ciphertext> for PublicKey {
    fn from(pk: Ciphertext) -> Self {
        Self::new(pk)
    }
}

impl ExpandSeed for PublicKey {
    fn contains_seed(&self) -> bool {
        self.pk.contains_seed()
    }
    fn expand_seed(mut self, context: &HeContext) -> Self {
        self.pk = self.pk.expand_seed(context);
        self
    }
}

/// Struct to store keyswitching keys. 
/// 
/// It should never be necessary for normal
/// users to create an instance of KSwitchKeys. This class is used strictly as
/// a base class for RelinKeys and GaloisKeys classes.
/// 
/// # Keyswitching
/// Concretely, keyswitching is used to change a ciphertext encrypted with one
/// key to be encrypted with another key. It is a general technique and is used
/// in relinearization and Galois rotations. A keyswitching key contains a sequence
/// (vector) of keys. In RelinKeys, each key is an encryption of a power of the
/// secret key. In GaloisKeys, each key corresponds to a type of rotation.
/// 
/// - See [RelinKeys] for the class that stores the relinearization keys.
/// - See [GaloisKeys] for the class that stores the Galois keys.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[allow(clippy::len_without_is_empty)]
pub struct KSwitchKeys {
    parms_id: ParmsID,
    keys: Vec<Vec<PublicKey>>
}
impl KSwitchKeys {
    /// Create a new KSwitchKeys object.
    pub fn from_members(parms_id: ParmsID, keys: Vec<Vec<PublicKey>>) -> Self {
        Self {parms_id, keys}
    }

    /// The [ParmsID] of the keyswitching keys.
    pub fn parms_id(&self) -> &ParmsID {&self.parms_id}

    /// The data of the keyswitching keys.
    pub fn data(&self) -> &[Vec<PublicKey>] {&self.keys}

    /// The data of the keyswitching keys.
    pub fn data_mut(&mut self) -> &mut Vec<Vec<PublicKey>> {&mut self.keys}

    /// The number of non-empty keys in the keyswitching keys.
    pub fn len(&self) -> usize {
        let mut k = 0;
        for key in &self.keys {
            if !key.is_empty() {
                k += 1;
            }
        }
        k
    }

    /// Set the params id
    pub fn set_parms_id(&mut self, parms_id: ParmsID) {
        self.parms_id = parms_id;
    }

    /// The inner public-key data in the keyswitching keys.
    pub fn keys(&self) -> &Vec<Vec<PublicKey>> {&self.keys}
}
impl Index<usize> for KSwitchKeys {
    type Output = Vec<PublicKey>;
    fn index(&self, index: usize) -> &Self::Output {
        &self.keys[index]
    }
}
impl IndexMut<usize> for KSwitchKeys {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.keys[index]
    }
}

impl ExpandSeed for KSwitchKeys {
    fn contains_seed(&self) -> bool {
        if self.keys.is_empty() {return false;}
        for each in &self.keys {
            if !each.is_empty() {return each[0].contains_seed();}
        }
        false
    }
    fn expand_seed(mut self, context: &HeContext) -> Self {
        self.keys = self.keys.into_iter().map(|vec| {
            vec.into_iter().map(|x| {x.expand_seed(context)}).collect::<Vec<_>>()
        }).collect::<Vec<_>>();
        self
    }
}

/// Struct to store relinearization keys.
/// 
/// # Relinearization
/// Freshly encrypted ciphertexts have a size of 2, and multiplying ciphertexts
/// of sizes K and L results in a ciphertext of size K+L-1. Unfortunately, this
/// growth in size slows down further multiplications and increases noise growth.
/// Relinearization is an operation that has no semantic meaning, but it reduces
/// the size of ciphertexts back to 2. Microsoft SEAL can only relinearize size 3
/// ciphertexts back to size 2, so if the ciphertexts grow larger than size 3,
/// there is no way to reduce their size. Relinearization requires an instance of
/// RelinKeys to be created by the secret key owner and to be shared with the
/// evaluator. Note that plain multiplication is fundamentally different from
/// normal multiplication and does not result in ciphertext size growth.
/// 
/// # When to Relinearize
/// Typically, one should always relinearize after each multiplications. However,
/// in some cases relinearization should be postponed as late as possible due to
/// its computational cost. For example, suppose the computation involves several
/// homomorphic multiplications followed by a sum of the results. In this case it
/// makes sense to not relinearize each product, but instead add them first and
/// only then relinearize the sum. This is particularly important when using the
/// CKKS scheme, where relinearization is much more computationally costly than
/// multiplications and additions.
/// 
/// - See [GaloisKeys] for the class that stores the Galois keys.
/// - See [KeyGenerator] for the class that generates the relinearization keys.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RelinKeys {
    keys: KSwitchKeys
}
impl RelinKeys {
    /// Create a new RelinKeys object.
    pub fn new(keys: KSwitchKeys) -> Self {
        Self {keys}
    }

    /// Get the inner keyswitching key index corresponding to the given power.
    pub fn get_index(key_power: usize) -> usize {
        assert!(key_power >= 2, "[Invalid argument] Key_power must be at least 2.");
        key_power - 2
    }

    /// Does the relinearization key have a key for the given power?
    pub fn has_key(&self, key_power: usize) -> bool {
        let index = Self::get_index(key_power);
        index < self.keys.data().len() && !self.keys[index].is_empty()
    }

    /// Get the key for the given power.
    pub fn key(&self, key_power: usize) -> &Vec<PublicKey> {
        let index = Self::get_index(key_power);
        &self.keys[index]
    }

    /// The [ParmsID] of the relinearization keys.
    pub fn parms_id(&self) -> &ParmsID {
        &self.keys.parms_id
    }

    /// Set the [ParmsID] of the relinearization keys.
    pub fn set_parms_id(&mut self, parms_id: ParmsID) {
        self.keys.parms_id = parms_id;
    }

    /// As a reference to the inner keyswitching keys.
    pub fn as_kswitch_keys(&self) -> &KSwitchKeys {
        &self.keys
    }
}
impl ExpandSeed for RelinKeys {
    fn contains_seed(&self) -> bool {
        self.keys.contains_seed()
    }
    fn expand_seed(mut self, context: &HeContext) -> Self {
        self.keys = self.keys.expand_seed(context);
        self
    }
}
/// Struct to store Galois keys.
/// 
/// # Slot Rotations
/// Galois keys are certain types of public keys that are needed to perform encrypted
/// vector rotation operations on batched ciphertexts. Batched ciphertexts encrypt
/// a 2-by-(N/2) matrix of modular integers in the BFV scheme, or an N/2-dimensional
/// vector of complex numbers in the CKKS scheme, where N denotes the degree of the
/// polynomial modulus. In the BFV scheme Galois keys can enable both cyclic rotations
/// of the encrypted matrix rows, as well as row swaps (column rotations). In the CKKS
/// scheme Galois keys can enable cyclic vector rotations, as well as a complex
/// conjugation operation.
/// 
/// - See [RelinKeys] for the class that stores the relinearization keys.
/// - See [KeyGenerator] for the class that generates the Galois keys.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct GaloisKeys {
    keys: KSwitchKeys
}
impl GaloisKeys {
    /// Create a new RelinKeys object.
    pub fn new(keys: KSwitchKeys) -> Self {
        Self {keys}
    }
    /// Get the inner keyswitching key index corresponding to the given Galois element.
    pub fn get_index(galois_elt: usize) -> usize {
        util::GaloisTool::get_index_from_elt(galois_elt)
    }
    /// Does the relinearization key have a key for the given Galois element?
    pub fn has_key(&self, galois_elt: usize) -> bool {
        let index = Self::get_index(galois_elt);
        index < self.keys.data().len() && !self.keys[index].is_empty()
    }
    /// Get the key for the given Galois element.
    pub fn key(&self, galois_elt: usize) -> &Vec<PublicKey> {
        let index = Self::get_index(galois_elt);
        &self.keys[index]
    }
    /// The [ParmsID] of the Galois keys.
    pub fn parms_id(&self) -> &ParmsID {
        self.keys.parms_id()
    }
    /// Set the [ParmsID] of the Galois keys.
    pub fn set_parms_id(&mut self, parms_id: ParmsID) {
        self.keys.parms_id = parms_id;
    }
    /// As a reference to the inner keyswitching keys.
    pub fn as_kswitch_keys(&self) -> &KSwitchKeys {
        &self.keys
    }
}
impl ExpandSeed for GaloisKeys {
    fn contains_seed(&self) -> bool {
        self.keys.contains_seed()
    }
    fn expand_seed(mut self, context: &HeContext) -> Self {
        self.keys = self.keys.expand_seed(context);
        self
    }
}

/// Provides key generation utilities.
/// 
/// Generates matching secret key and public key. An existing KeyGenerator can
/// also at any time be used to generate relinearization keys and Galois keys.
/// Constructing a KeyGenerator requires only a [HeContext].
/// 
/// - [EncryptionParameters](crate::EncryptionParameters) for more details on encryption parameters.
/// - [SecretKey] for more details on secret key.
/// - [PublicKey] for more details on public key.
/// - [RelinKeys] for more details on relinearization keys.
/// - [GaloisKeys] for more details on Galois keys.
pub struct KeyGenerator {
    context: Arc<HeContext>,
    secret_key: SecretKey,

    secret_key_array: RwLock<Vec<u64>>,

    sk_generated: bool,
    // random_generator: Arc<Mutex<BlakeRNG>>,
}

impl KeyGenerator {

    /// Create a new KeyGenerator.
    pub fn new(context: Arc<HeContext>) -> Self {
        assert!(context.parameters_set(), "[Invalid argument] Encryption parameters are not set correctly.");
        let secret_key_array = vec![];
        let mut ret = Self {
            context: context.clone(),
            secret_key: SecretKey::default(),
            secret_key_array: RwLock::new(secret_key_array),
            sk_generated: false,
            // random_generator: context.create_random_generator(),
        };
        ret.generate_sk(false);
        ret
    }

    /// The [HeContext] used by the KeyGenerator.
    pub fn context(&self) -> &Arc<HeContext> {
        &self.context
    }

    /// Create a new KeyGenerator with a given secret key.
    pub fn from_sk(context: Arc<HeContext>, sk: SecretKey) -> Self {
        assert!(context.parameters_set(), "[Invalid argument] Encryption parameters are not set correctly.");
        let secret_key_array = vec![];
        let mut ret = Self {
            context: context.clone(),
            secret_key: sk,
            secret_key_array: RwLock::new(secret_key_array),
            sk_generated: true,
            // random_generator: context.create_random_generator(),
        };
        ret.generate_sk(true);
        ret
    }

    // pub fn set_random_generator(&mut self, random_generator: Arc<Mutex<BlakeRNG>>) {
    //     self.random_generator = random_generator;
    // }

    fn generate_sk(&mut self, is_initialized: bool) {
        let context_data = self.context.key_context_data().unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();

        if !is_initialized {
            self.secret_key.data_mut().resize(coeff_count * coeff_modulus_size, 0);
            let mut rng = self.context.create_random_generator();
            rlwe::sample::ternary(&mut rng, parms, self.secret_key.data_mut());

            let ntt_tables = context_data.small_ntt_tables();
            polymod::ntt_p(self.secret_key.data_mut(), coeff_count, ntt_tables);

            self.secret_key.set_parms_id(*context_data.parms_id());
            self.secret_key.as_plaintext_mut().set_coeff_count(coeff_count * coeff_modulus_size);
        }

        let mut secret_key_array = self.secret_key_array.write().unwrap();
        secret_key_array.resize(coeff_count * coeff_modulus_size, 0);
        secret_key_array.copy_from_slice(self.secret_key.data());
        self.sk_generated = true;
    }

    fn generate_pk(&self, save_seed: bool, u_prng: Option<&mut BlakeRNG>) -> PublicKey {
        assert!(self.sk_generated, "[Logic error] Cannot generate public key for unspecified secret key.");
        let context_data = self.context.key_context_data().unwrap();

        let mut public_key = PublicKey::default();
        if u_prng.is_none() {
            rlwe::encrypt_zero::symmetric(
                &self.secret_key, &self.context, 
                context_data.parms_id(), true, 
                save_seed, 
                public_key.as_ciphertext_mut()
            );
        } else {
            rlwe::encrypt_zero::symmetric_with_c1_prng(
                &self.secret_key, &self.context, 
                context_data.parms_id(), true, 
                u_prng.unwrap(), save_seed, 
                public_key.as_ciphertext_mut()
            );
        }

        public_key.set_parms_id(*context_data.parms_id());
        public_key
    }

    /// Generates a new [PublicKey] corresponding to the secret key.
    pub fn create_public_key(&self, save_seed: bool) -> PublicKey {
        self.generate_pk(save_seed, None)
    }

    /// Create a pk with the polynomial u sampled from a specified PRNG.
    pub fn create_public_key_with_u_prng(&self, save_seed: bool, rng: &mut BlakeRNG) -> PublicKey {
        self.generate_pk(save_seed, Some(rng))
    }

    /// Obtain a reference to the secret key.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
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


    fn generate_one_kswitch_key(&self, new_key: &[u64], destination: &mut Vec<PublicKey>, save_seed: bool) {
        if !self.context.using_keyswitching() {
            panic!("[Logic error] Key switching is not supported by the current encryption parameters.");
        }
        let key_context_data = self.context.key_context_data().unwrap();
        let coeff_count = key_context_data.parms().poly_modulus_degree();
        let key_parms = key_context_data.parms();
        let key_modulus = key_parms.coeff_modulus();
        let decomp_mod_count = self.context.first_context_data().unwrap().parms().coeff_modulus().len();
        let key_parms_id = key_context_data.parms_id();

        let mut temp = vec![0; coeff_count];
        destination.resize(decomp_mod_count, PublicKey::default());
        for i in 0..decomp_mod_count {
            rlwe::encrypt_zero::symmetric(&self.secret_key, &self.context, key_parms_id, true, save_seed, destination[i].as_ciphertext_mut());
            let factor = util::barrett_reduce_u64(key_modulus[key_modulus.len() - 1].value(), &key_modulus[i]);
            polymod::multiply_scalar(&new_key[i * coeff_count..(i + 1) * coeff_count], factor, &key_modulus[i], &mut temp);
            let destination_component = destination[i].as_ciphertext_mut().poly_component_mut(0, i);
            polymod::add_inplace(destination_component, &temp, &key_modulus[i]);
        }
    }

    fn generate_kswitch_keys(&self, new_keys: &[u64], num_keys: usize, destination: &mut KSwitchKeys, save_seed: bool) {
        let key_context_data = self.context.key_context_data().unwrap();
        let coeff_count = key_context_data.parms().poly_modulus_degree();
        let key_parms = key_context_data.parms();
        let coeff_modulus_size = key_parms.coeff_modulus().len();
        destination.data_mut().resize(num_keys, vec![]);
        let d = coeff_count * coeff_modulus_size;
        for i in 0..num_keys {
            self.generate_one_kswitch_key(&new_keys[i * d .. (i+1) * d], &mut destination.data_mut()[i], save_seed);
        }
    }

    /// Create a keyswitching key to support switching a ciphertext from another secret key.
    /// Use with [Evaluator::apply_keyswitching].
    pub fn create_keyswitching_key(&self, new_key: &SecretKey, save_seed: bool) -> KSwitchKeys {
        let mut ret = KSwitchKeys::default();
        ret.data_mut().resize(1, Vec::new());
        self.generate_one_kswitch_key(new_key.data(), &mut ret.data_mut()[0], save_seed);
        let context_data = self.context.key_context_data().unwrap();
        ret.set_parms_id(*context_data.parms_id());
        ret
    }

    fn generate_rlk(&self, count: usize, save_seed: bool) -> RelinKeys {
        assert!(self.sk_generated, "[Logic error] Cannot generate relin key for unspecified secret key.");
        if count == 0 || count > util::HE_CIPHERTEXT_SIZE_MAX - 2 {
            panic!("[Invalid argument] Invalid count.");
        }

        let context_data = self.context.key_context_data().unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();

        // Make sure we have enough secret keys computed
        self.compute_secret_key_array(count + 1);

        // Create the RelinKeys object to return
        let mut relin_keys = RelinKeys::default();

        // Assume the secret key is already transformed into NTT form.
        let d = coeff_count * coeff_modulus_size;
        // Acquire read lock
        let read_lock = self.secret_key_array.read().unwrap();
        self.generate_kswitch_keys(&read_lock[d..], count, &mut relin_keys.keys, save_seed);

        // Set the parms_id
        relin_keys.set_parms_id(*context_data.parms_id());
        relin_keys
    }

    /// Creates a [RelinKeys] object that can be used to relinearize ciphertexts.
    pub fn create_relin_keys(&self, save_seed: bool) -> RelinKeys {
        self.generate_rlk(1, save_seed)
    }

    fn generate_galois_keys(&self, galois_elts: &[usize], save_seed: bool) -> GaloisKeys {
        assert!(self.sk_generated, "[Logic error] Cannot generate galois key for unspecified secret key.");
        let context_data = self.context.key_context_data().unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let galois_tool = context_data.galois_tool();
        let coeff_count = parms.poly_modulus_degree();
        let coeff_modulus_size = coeff_modulus.len();

        // Create the GaloisKeys object to return
        let mut galois_keys = GaloisKeys::default();
        galois_keys.keys.data_mut().resize(coeff_count, vec![]);
        for &galois_elt in galois_elts {
            if galois_elt % 2 == 0 || galois_elt >= (coeff_count << 1) {
                panic!("[Invalid argument] Invalid Galois element.");
            }
            if galois_keys.has_key(galois_elt) {
                continue;
            }
            let mut rotated_secret_key = vec![0; coeff_count * coeff_modulus_size];
            galois_tool.apply_ntt_p(self.secret_key.data(), coeff_modulus_size, galois_elt, &mut rotated_secret_key);
            let index = GaloisKeys::get_index(galois_elt);
            self.generate_one_kswitch_key(&rotated_secret_key, &mut galois_keys.keys.data_mut()[index], save_seed);
        }

        // Set the parms_id
        galois_keys.set_parms_id(*context_data.parms_id());
        galois_keys
    }

    /// Creates a [GaloisKeys] object that can be used to apply Galois automorphisms to ciphertexts,
    /// using the specified Galois elements.
    pub fn create_galois_keys_from_elts(&self, galois_elts: &[usize], save_seed: bool) -> GaloisKeys {
        self.generate_galois_keys(galois_elts, save_seed)
    }

    /// Creates a [GaloisKeys] object that can be used to apply Galois automorphisms to ciphertexts,
    /// using the specified rotation steps.
    pub fn create_galois_keys_from_steps(&self, steps: &[isize], save_seed: bool) -> GaloisKeys {
        if !self.context.key_context_data().unwrap().qualifiers().using_batching {
            panic!("[Logic error] Galois keys are not supported by the current encryption parameters.");
        }
        let elts = self.context.key_context_data().unwrap().galois_tool().get_elts_from_steps(steps);
        self.create_galois_keys_from_elts(&elts, save_seed)
    }

    /// Creates a [GaloisKeys] object that can be used to apply Galois automorphisms to ciphertexts,
    /// using steps of ±2^i.
    pub fn create_galois_keys(&self, save_seed: bool) -> GaloisKeys {
        let elts = self.context.key_context_data().unwrap().galois_tool().get_elts_all();
        self.create_galois_keys_from_elts(&elts, save_seed)
    }

}



#[cfg(test)]
mod tests {

    use crate::{
        SchemeType,
        EncryptionParameters,
        CoeffModulus,
        SecurityLevel, ValCheck, PlainModulus,
    };

    use super::*;

    #[test]
    fn test_keygen() {

        // BFV

        let parms = EncryptionParameters::new(SchemeType::BFV)
            .set_poly_modulus_degree(64)
            .set_plain_modulus_u64(65537)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![60, 60]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let evk = keygen.create_relin_keys(false);
        assert_eq!(evk.parms_id(), context.key_parms_id());
        assert_eq!(evk.key(2).len(), 1);
        evk.as_kswitch_keys().data().iter().for_each(|x| {
            x.iter().for_each(|x| assert!(!x.as_ciphertext().is_transparent()))
        });
        assert!(evk.is_valid_for(context.as_ref()));
        let galks = keygen.create_galois_keys(false);
        galks.as_kswitch_keys().data().iter().for_each(|x| {
            x.iter().for_each(|x| assert!(!x.as_ciphertext().is_transparent()))
        });
        assert!(galks.is_valid_for(context.as_ref()));
        assert_eq!(galks.key(3).len(), 1);
        assert_eq!(galks.as_kswitch_keys().len(), 10);
        let galks = keygen.create_galois_keys_from_elts(&[1, 3, 5, 7], false);
        assert!(galks.has_key(1));
        assert!(galks.has_key(3));
        assert!(galks.has_key(5));
        assert!(galks.has_key(7));
        assert!(!galks.has_key(9));
        assert!(!galks.has_key(127));
        assert_eq!(galks.key(1).len(), 1);
        assert!(galks.as_kswitch_keys().len() == 4);
        let galks = keygen.create_galois_keys_from_elts(&[1], false);
        assert!(galks.has_key(1));
        assert!(!galks.has_key(3));
        assert!(!galks.has_key(127));
        assert_eq!(galks.key(1).len(), 1);
        assert_eq!(galks.as_kswitch_keys().len(), 1);

        let parms = EncryptionParameters::new(SchemeType::BFV)
            .set_poly_modulus_degree(256)
            .set_plain_modulus_u64(65537)
            .set_coeff_modulus(&CoeffModulus::create(256, vec![60, 30, 30]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let evk = keygen.create_relin_keys(false);
        assert_eq!(evk.parms_id(), context.key_parms_id());
        evk.as_kswitch_keys().data().iter().for_each(|x| {
            x.iter().for_each(|x| assert!(!x.as_ciphertext().is_transparent()))
        });
        assert!(evk.is_valid_for(context.as_ref()));
        let galks = keygen.create_galois_keys(false);
        galks.as_kswitch_keys().data().iter().for_each(|x| {
            x.iter().for_each(|x| assert!(!x.as_ciphertext().is_transparent()))
        });
        assert!(galks.is_valid_for(context.as_ref()));
        assert_eq!(galks.key(3).len(), 2);
        assert_eq!(galks.as_kswitch_keys().len(), 14);


        // BGV

        let parms = EncryptionParameters::new(SchemeType::BGV)
            .set_poly_modulus_degree(64)
            .set_plain_modulus_u64(65537)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![60, 60]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let evk = keygen.create_relin_keys(false);
        assert_eq!(evk.parms_id(), context.key_parms_id());
        assert_eq!(evk.key(2).len(), 1);
        evk.as_kswitch_keys().data().iter().for_each(|x| {
            x.iter().for_each(|x| assert!(!x.as_ciphertext().is_transparent()))
        });
        assert!(evk.is_valid_for(context.as_ref()));
        let galks = keygen.create_galois_keys(false);
        galks.as_kswitch_keys().data().iter().for_each(|x| {
            x.iter().for_each(|x| assert!(!x.as_ciphertext().is_transparent()))
        });
        assert!(galks.is_valid_for(context.as_ref()));
        assert_eq!(galks.key(3).len(), 1);
        assert_eq!(galks.as_kswitch_keys().len(), 10);
        let galks = keygen.create_galois_keys_from_elts(&[1, 3, 5, 7], false);
        assert!(galks.has_key(1));
        assert!(galks.has_key(3));
        assert!(galks.has_key(5));
        assert!(galks.has_key(7));
        assert!(!galks.has_key(9));
        assert!(!galks.has_key(127));
        assert_eq!(galks.key(1).len(), 1);
        assert!(galks.as_kswitch_keys().len() == 4);
        let galks = keygen.create_galois_keys_from_elts(&[1], false);
        assert!(galks.has_key(1));
        assert!(!galks.has_key(3));
        assert!(!galks.has_key(127));
        assert_eq!(galks.key(1).len(), 1);
        assert_eq!(galks.as_kswitch_keys().len(), 1);

        let parms = EncryptionParameters::new(SchemeType::BGV)
            .set_poly_modulus_degree(256)
            .set_plain_modulus_u64(65537)
            .set_coeff_modulus(&CoeffModulus::create(256, vec![60, 30, 30]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let evk = keygen.create_relin_keys(false);
        assert_eq!(evk.parms_id(), context.key_parms_id());
        evk.as_kswitch_keys().data().iter().for_each(|x| {
            x.iter().for_each(|x| assert!(!x.as_ciphertext().is_transparent()))
        });
        assert!(evk.is_valid_for(context.as_ref()));
        let galks = keygen.create_galois_keys(false);
        galks.as_kswitch_keys().data().iter().for_each(|x| {
            x.iter().for_each(|x| assert!(!x.as_ciphertext().is_transparent()))
        });
        assert!(galks.is_valid_for(context.as_ref()));
        assert_eq!(galks.key(3).len(), 2);
        assert_eq!(galks.as_kswitch_keys().len(), 14);

        // CKKS

        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(64)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![60, 60]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let evk = keygen.create_relin_keys(false);
        assert_eq!(evk.parms_id(), context.key_parms_id());
        assert_eq!(evk.key(2).len(), 1);
        evk.as_kswitch_keys().data().iter().for_each(|x| {
            x.iter().for_each(|x| assert!(!x.as_ciphertext().is_transparent()))
        });
        assert!(evk.is_valid_for(context.as_ref()));
        let galks = keygen.create_galois_keys(false);
        galks.as_kswitch_keys().data().iter().for_each(|x| {
            x.iter().for_each(|x| assert!(!x.as_ciphertext().is_transparent()))
        });
        assert!(galks.is_valid_for(context.as_ref()));
        assert_eq!(galks.key(3).len(), 1);
        assert_eq!(galks.as_kswitch_keys().len(), 10);
        let galks = keygen.create_galois_keys_from_elts(&[1, 3, 5, 7], false);
        assert!(galks.has_key(1));
        assert!(galks.has_key(3));
        assert!(galks.has_key(5));
        assert!(galks.has_key(7));
        assert!(!galks.has_key(9));
        assert!(!galks.has_key(127));
        assert_eq!(galks.key(1).len(), 1);
        assert!(galks.as_kswitch_keys().len() == 4);
        let galks = keygen.create_galois_keys_from_elts(&[1], false);
        assert!(galks.has_key(1));
        assert!(!galks.has_key(3));
        assert!(!galks.has_key(127));
        assert_eq!(galks.key(1).len(), 1);
        assert_eq!(galks.as_kswitch_keys().len(), 1);

        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(256)
            .set_coeff_modulus(&CoeffModulus::create(256, vec![60, 30, 30]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let evk = keygen.create_relin_keys(false);
        assert_eq!(evk.parms_id(), context.key_parms_id());
        evk.as_kswitch_keys().data().iter().for_each(|x| {
            x.iter().for_each(|x| assert!(!x.as_ciphertext().is_transparent()))
        });
        assert!(evk.is_valid_for(context.as_ref()));
        let galks = keygen.create_galois_keys(false);
        galks.as_kswitch_keys().data().iter().for_each(|x| {
            x.iter().for_each(|x| assert!(!x.as_ciphertext().is_transparent()))
        });
        assert!(galks.is_valid_for(context.as_ref()));
        assert_eq!(galks.key(3).len(), 2);
        assert_eq!(galks.as_kswitch_keys().len(), 14);
    }

    #[test]
    fn test_multithread() {
        
        let parms = EncryptionParameters::new(SchemeType::BFV)
            .set_poly_modulus_degree(8192)
            .set_plain_modulus(&PlainModulus::batching(8192, 20))
            .set_coeff_modulus(&CoeffModulus::create(8192, vec![60, 60, 60]));
        let context = HeContext::new(parms.clone(), true, SecurityLevel::None);
        let keygen = Arc::new(KeyGenerator::new(context.clone()));

        let thread_count = 4;
        let mut threads = vec![];
        for _i in 0..thread_count {
            let keygen = keygen.clone();
            let handle = std::thread::spawn(move || {
                keygen.create_relin_keys(false)
            });
            threads.push(handle);
        }
        let mut rlks = vec![];
        for handle in threads {
            rlks.push(handle.join().unwrap());
        }

        use crate::{Encryptor, Evaluator, Decryptor, BatchEncoder};
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false));
        let evaluator = Evaluator::new(context.clone());
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let encoder = BatchEncoder::new(context.clone());

        fn random_u64_vector(context: &HeContext) -> Vec<u64> {
            let context_data = context.first_context_data().unwrap();
            let parms = context_data.parms();
            let mut vec = vec![0u64; parms.poly_modulus_degree()];
            let modulus = parms.plain_modulus().value();
            for i in 0..vec.len() {
                vec[i] = rand::random::<u64>() % modulus;
            }
            vec
        }

        let message = random_u64_vector(context.as_ref());
        let plain = encoder.encode_new(&message);

        let ciphertext = encryptor.encrypt_new(&plain);
        let squared = (0..thread_count).map(|i| {
            let c = evaluator.square_new(&ciphertext);
            
            evaluator.relinearize_new(&c, &rlks[i])
        }).collect::<Vec<_>>();

        let squared_message = message.iter().map(|x| {
            (x * x) % parms.plain_modulus().value()
        }).collect::<Vec<_>>();
        for i in 0..thread_count {
            let decrypted = encoder.decode_new(&decryptor.decrypt_new(&squared[i]));
            assert_eq!(decrypted, squared_message);
        }

        let squared = (0..thread_count).map(|_i| {
            
            evaluator.square_new(&ciphertext)
        }).collect::<Vec<_>>();

        let mut threads = vec![];
        let decryptor = Arc::new(decryptor);
        for squared in squared.into_iter() {
            let decryptor = decryptor.clone();
            let handle = std::thread::spawn(move || {
                decryptor.decrypt_new(&squared)
            });
            threads.push(handle);
        }
        let mut decs = vec![];
        for handle in threads {
            decs.push(handle.join().unwrap());
        }

        for i in 0..thread_count {
            let decrypted = encoder.decode_new(&decs[i]);
            assert_eq!(decrypted, squared_message);
        }
    }

}