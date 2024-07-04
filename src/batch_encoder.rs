use std::sync::Arc;

use crate::{
    context::HeContext, 
    SchemeType,
    util::{self, GALOIS_GENERATOR}, 
    Plaintext, 
    PARMS_ID_ZERO, 
    ValCheck
};


/// Provides SIMD encoding and decoding functionality for the [BFV](SchemeType::BFV) and [BGV](SchemeType::BGV) schemes.
/// 
/// Provides functionality for CRT batching. If the polynomial modulus degree is N, and
/// the plaintext modulus is a prime number T such that T is congruent to 1 modulo 2N,
/// then BatchEncoder allows the plaintext elements to be viewed as 2-by-(N/2)
/// matrices of integers modulo T. Homomorphic operations performed on such encrypted
/// matrices are applied coefficient (slot) wise, enabling powerful SIMD functionality
/// for computations that are vectorizable. This functionality is often called "batching"
/// in the homomorphic encryption literature.
/// 
/// ## Mathematical Background
/// Mathematically speaking, if the polynomial modulus is X^N+1, N is a power of two, and
/// plain_modulus is a prime number T such that 2N divides T-1, then integers modulo T
/// contain a primitive 2N-th root of unity and the polynomial X^N+1 splits into n distinct
/// linear factors as X^N+1 = (X-a_1)*...*(X-a_N) mod T, where the constants a_1, ..., a_n
/// are all the distinct primitive 2N-th roots of unity in integers modulo T. The Chinese
/// Remainder Theorem (CRT) states that the plaintext space Z_T\[X\]/(X^N+1) in this case is
/// isomorphic (as an algebra) to the N-fold direct product of fields Z_T. The isomorphism
/// is easy to compute explicitly in both directions, which is what this class does.
/// Furthermore, the Galois group of the extension is (Z/2NZ)* ~= Z/2Z x Z/(N/2) whose
/// action on the primitive roots of unity is easy to describe. Since the batching slots
/// correspond 1-to-1 to the primitive roots of unity, applying Galois automorphisms on the
/// plaintext act by permuting the slots. By applying generators of the two cyclic
/// subgroups of the Galois group, we can effectively view the plaintext as a 2-by-(N/2)
/// matrix, and enable cyclic row rotations, and column rotations (row swaps).
/// 
/// ## Valid Parameters
/// Whether batching can be used depends on whether the plaintext modulus has been chosen
/// appropriately. Thus, to construct a BatchEncoder the user must provide an instance
/// of SEALContext such that its associated EncryptionParameterQualifiers object has the
/// flags parameters_set and enable_batching set to true.
/// 
/// - See [EncryptionParameters](crate::EncryptionParameters) for more information about encryption parameters.
/// - See [EncryptionParameterQualifiers](crate::EncryptionParameterQualifiers) for more information about parameter qualifiers.
/// - See [Evaluator](crate::Evaluator) for rotating rows and columns of encrypted matrices.

pub struct BatchEncoder {
    context: Arc<HeContext>,
    slots: usize,
    // roots_of_unity: Vec<u64>,
    matrix_reps_index_map: Vec<usize>,
}

impl BatchEncoder {

    /// Creates a BatchEncoder initialized with the specified [HeContext].
    pub fn new(context: Arc<HeContext>) -> Self {

        if !context.parameters_set() {
            panic!("[Invalid argument] Encryption parameters are not set correctly");
        }

        let context_data = context.first_context_data().unwrap();
        let parms = context_data.parms();
        match parms.scheme() {
            SchemeType::BFV | SchemeType::BGV => {}
            _ => {
                panic!("[Invalid argument] Unsupported scheme.");
            }
        }

        let slots = parms.poly_modulus_degree();
        let mut roots_of_unity;
        let mut matrix_reps_index_map: Vec<usize>;
        match context_data.qualifiers().using_batching {
            true => {
                roots_of_unity = vec![0; slots];
                let root = context_data.plain_ntt_tables().root();
                let modulus = parms.plain_modulus();
                let generator_sq = util::multiply_u64_mod(root, root, modulus);
                roots_of_unity[0] = root;
                for i in 1..slots {
                    roots_of_unity[i] = util::multiply_u64_mod(roots_of_unity[i - 1], generator_sq, modulus);
                }
                let logn = util::get_power_of_two(slots as u64);
                assert!(logn > 0, "[Invalid argument] n must be power of 2");
                let logn = logn as usize;
                matrix_reps_index_map = vec![0; slots];
                let row_size = slots >> 1;
                let m = slots << 1;
                let gen = GALOIS_GENERATOR; let mut pos = 1;
                for i in 0..row_size {
                    let index1 = (pos - 1) >> 1;
                    let index2 = (m - pos - 1) >> 1;
                    matrix_reps_index_map[i] = util::reverse_bits_u64(index1 as u64, logn) as usize;
                    matrix_reps_index_map[i + row_size] = util::reverse_bits_u64(index2 as u64, logn) as usize;
                    pos = (pos * gen) & (m - 1);
                }
            }
            false => {
                matrix_reps_index_map = vec![];
                // panic!("[Invalid argument] Batching is not supported under this parameters set.")
            }
        }

        BatchEncoder {
            context,
            slots,
            matrix_reps_index_map,
        }
    }

    /// Return the numb`er of slots (coefficients) that are available for batching.
    pub fn slot_count(&self) -> usize {
        self.slots
    }

    /// Return the number of rows in the matrix that is encoded in a plaintext.
    /// Equals to 2.
    pub fn row_count(&self) -> usize {
        2
    }

    /// Return the number of columns in the matrix that is encoded in a plaintext.
    /// Equals to [Self::slot_count()] / 2.
    pub fn column_count(&self) -> usize {
        self.slots / 2
    }

    /// Permutes a vector with index bitwise reversed.
    /// The length of the vector must be a power of 2.
    pub fn reverse_bits(&self, input: &mut [u64]) {
        let logn = util::get_power_of_two(self.slots as u64);
        assert!(logn > 0, "[Invalid argument] n must be power of 2");
        let logn = logn as usize;
        let n = self.slots;
        for i in 0..n {
            let j = util::reverse_bits_u64(i as u64, logn) as usize;
            if j > i {
                input.swap(i, j);
            }
        }
    }

    /// Encodes a vector of integers as a plaintext polynomial.
    /// The length of the vector must be at most [Self::slot_count()].
    /// ```rust
    /// use heathcliff::create_bfv_decryptor_suite;
    /// let (params, context, encoder, _, _, _)
    ///     = create_bfv_decryptor_suite(4096, 20, vec![30, 30, 30]);
    /// let values = vec![1, 2, 3, 4];
    /// let plain = encoder.encode_new(&values);
    /// let decoded = encoder.decode_new(&plain);
    /// assert_eq!(&values, &decoded[..4]);
    /// assert_eq!(&vec![0; 4096 - 4], &decoded[4..]);
    /// ```
    pub fn encode(&self, values: &[u64], destination: &mut Plaintext) {
        assert!(!self.matrix_reps_index_map.is_empty(), "[Invalid argument] The parameters does not support vector batching.");
        let context_data = self.context.first_context_data().unwrap();
        let value_size = values.len();
        // Validate input parameters
        if value_size > self.slots {
            panic!("[Invalid argument] Values has size larger than the number of slots");
        }
        // Set destination to full size
        destination.resize(self.slots);
        destination.set_parms_id(PARMS_ID_ZERO);
        // First write the values to destination coefficients.
        // Read in top row, then bottom row.
        for i in 0..value_size {
            destination.data_mut()[self.matrix_reps_index_map[i]] = values[i];
        }
        for i in value_size..self.slots {
            destination.data_mut()[self.matrix_reps_index_map[i]] = 0;
        }
        // Transform destination using inverse of negacyclic NTT
        // Note: We already performed bit-reversal when reading in the matrix
        let plain_ntt_tables = context_data.plain_ntt_tables();
        plain_ntt_tables.inverse_ntt_negacyclic_harvey(destination.data_mut());
    }

    /// Encode a plaintext polynomial, given polynomial coefficients.
    pub fn encode_polynomial(&self, values: &[u64], destination: &mut Plaintext) {
        let context_data = self.context.first_context_data().unwrap();
        let value_size = values.len();
        // Validate input parameters
        if value_size > self.slots {
            panic!("[Invalid argument] Values has size larger than the number of slots");
        }
        // Set destination to full size
        destination.resize(values.len());
        destination.set_parms_id(PARMS_ID_ZERO);
        let modulus = context_data.parms().plain_modulus();
        for i in 0..value_size {
            destination.data_mut()[i] = modulus.reduce(values[i]);
        }
    }

    /// See [Self::encode].
    pub fn encode_new(&self, values: &[u64]) -> Plaintext {
        let mut destination = Plaintext::default();
        self.encode(values, &mut destination);
        destination
    }

    /// See [Self::encode_polynomial].
    pub fn encode_polynomial_new(&self, values: &[u64]) -> Plaintext {
        let mut destination = Plaintext::default();
        self.encode_polynomial(values, &mut destination);
        destination
    }

    /// Decodes a plaintext polynomial into a vector of integers.
    /// The length of the vector will be [Self::slot_count()].
    /// See [Self::encode] for an example.
    pub fn decode(&self, plain: &Plaintext, destination: &mut Vec<u64>) {
        assert!(!self.matrix_reps_index_map.is_empty(), "[Invalid argument] The parameters does not support vector batching.");
        if !plain.is_valid_for(&self.context) {
            panic!("[Invalid argument] Plaintext is not valid for encryption parameters.");
        }
        if plain.is_ntt_form() {
            panic!("[Invalid argument] Plaintext is in NTT form.");
        }
        let context_data = self.context.first_context_data().unwrap();
        destination.resize(self.slots, 0);
        let plain_coeff_count = std::cmp::min(plain.coeff_count(), self.slots);
        let mut temp_dest = vec![0; self.slots];
        util::set_uint(plain.data(), plain_coeff_count, &mut temp_dest);
        // Transform destination using negacyclic NTT
        let plain_ntt_tables = context_data.plain_ntt_tables();
        plain_ntt_tables.ntt_negacyclic_harvey(&mut temp_dest);
        // Read in top row, then bottom row.
        for i in 0..self.slots {
            destination[i] = temp_dest[self.matrix_reps_index_map[i]];
        }
    }

    /// Decodes a plaintext polynomial into as their coefficients.
    pub fn decode_polynomial(&self, plain: &Plaintext, destination: &mut Vec<u64>) {
        destination.resize(plain.data().len(), 0);
        destination.copy_from_slice(plain.data());
    }

    /// See [Self::decode_polynomial]
    pub fn decode_polynomial_new(&self, plain: &Plaintext) -> Vec<u64> {
        plain.data().clone()
    }

    /// See [Self::decode].
    pub fn decode_new(&self, plain: &Plaintext) -> Vec<u64> {
        let mut destination = Vec::new();
        self.decode(plain, &mut destination);
        destination
    }

    /// Do as the name says.
    pub fn get_plain_modulus(&self) -> u64 {
        let context_data = self.context.first_context_data().unwrap();
        let plain_modulus = context_data.parms().plain_modulus();
        plain_modulus.value()
    }

    /// Does the parameter set support SIMD vector encoding?
    pub fn simd_encoding_supported(&self) -> bool {
        !self.matrix_reps_index_map.is_empty()
    }

}

#[cfg(test)]
mod tests {
    use crate::{EncryptionParameters, CoeffModulus, KeyGenerator, Encryptor, Decryptor};
    use super::*;

    #[test]
    fn test_unbatch_uint_vector() {
        let parms = EncryptionParameters::new(SchemeType::BFV)
            .set_poly_modulus_degree(64)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![60]))
            .set_plain_modulus_u64(257);
        let context = HeContext::new(parms, false, crate::SecurityLevel::None);
        assert!(context.first_context_data().unwrap().qualifiers().using_batching);
        let encoder = BatchEncoder::new(context.clone());
        assert_eq!(encoder.slot_count(), 64);

        let plain_vec = (0..encoder.slot_count() as u64).collect::<Vec<_>>();
        let plain = encoder.encode_new(&plain_vec);
        let decoded_vec = encoder.decode_new(&plain);
        assert_eq!(plain_vec, decoded_vec);

        let plain_vec = (0..encoder.slot_count()).map(|_| 5).collect::<Vec<_>>();
        let plain = encoder.encode_new(&plain_vec);
        let mut coeffs = vec![0; encoder.slot_count()];
        coeffs[0] = 5;
        assert_eq!(plain.data(), &coeffs);
        let decoded_vec = encoder.decode_new(&plain);
        assert_eq!(plain_vec, decoded_vec);

        let plain_vec = (0..20).collect::<Vec<_>>();
        let plain = encoder.encode_new(&plain_vec);
        let decoded_vec = encoder.decode_new(&plain);
        assert_eq!(decoded_vec.len(), 64);
        assert_eq!(decoded_vec[0..20], plain_vec[..]);
        assert_eq!(decoded_vec[20..], vec![0; 44]);
    }

    #[test]
    fn test_polynomial() {
        use crate::{create_bfv_decryptor_suite, Evaluator};
        let (_params, context, encoder, _keygen, encryptor, decryptor)
            = create_bfv_decryptor_suite(8192, 30, vec![60, 60, 60]);
        let evaluator = Evaluator::new(context.clone());
        let x = vec![1, 2, 3];
        let y = vec![4, 5, 6];
        let x_encoded = encoder.encode_polynomial_new(&x);
        let y_encoded = encoder.encode_polynomial_new(&y);
        let x_decoded = encoder.decode_polynomial_new(&x_encoded);
        x.iter().zip(x_decoded.iter()).for_each(|(a, b)| {
            assert_eq!(a, b);
        });
        let x_encrypted = encryptor.encrypt_new(&x_encoded);
        let y_encrypted = encryptor.encrypt_new(&y_encoded);
        let result = evaluator.multiply_new(&x_encrypted, &y_encrypted);
        let result_decrypted = decryptor.decrypt_new(&result);
        let result = encoder.decode_polynomial_new(&result_decrypted);
        let expected = [4, 13, 28, 27, 18];
        result.into_iter().zip(expected.iter()).for_each(|(a, &b)| {
            assert_eq!(a, b);
        });

        let result = evaluator.multiply_plain_new(&x_encrypted, &y_encoded);
        let result_decrypted = decryptor.decrypt_new(&result);
        let result = encoder.decode_polynomial_new(&result_decrypted);
        result.into_iter().zip(expected.iter()).for_each(|(a, &b)| {
            assert_eq!(a, b);
        });
        
        let params = EncryptionParameters::new(SchemeType::BFV)
            .set_poly_modulus_degree(8192)
            .set_plain_modulus_u64(1<<30)
            .set_coeff_modulus(&CoeffModulus::create(8192, vec![60, 60, 60]));
        let context = HeContext::new(params, true, crate::SecurityLevel::Tc128);
        let encoder = BatchEncoder::new(context.clone());
        let keygen = KeyGenerator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false));
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());

        let evaluator = Evaluator::new(context.clone());
        let x = vec![1, 2, 3];
        let y = vec![4, 5, 6];
        let x_encoded = encoder.encode_polynomial_new(&x);
        let y_encoded = encoder.encode_polynomial_new(&y);
        let x_decoded = encoder.decode_polynomial_new(&x_encoded);
        x.iter().zip(x_decoded.iter()).for_each(|(a, b)| {
            assert_eq!(a, b);
        });
        let x_encrypted = encryptor.encrypt_new(&x_encoded);
        let y_encrypted = encryptor.encrypt_new(&y_encoded);
        let result = evaluator.multiply_new(&x_encrypted, &y_encrypted);
        let result_decrypted = decryptor.decrypt_new(&result);
        let result = encoder.decode_polynomial_new(&result_decrypted);
        let expected = [4, 13, 28, 27, 18];
        result.into_iter().zip(expected.iter()).for_each(|(a, &b)| {
            assert_eq!(a, b);
        });

        let result = evaluator.multiply_plain_new(&x_encrypted, &y_encoded);
        let result_decrypted = decryptor.decrypt_new(&result);
        let result = encoder.decode_polynomial_new(&result_decrypted);
        result.into_iter().zip(expected.iter()).for_each(|(a, &b)| {
            assert_eq!(a, b);
        });

    }

}