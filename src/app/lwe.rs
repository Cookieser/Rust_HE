//! Provide PackLWEs utility.
//! 
//! Chen et al., 2020. Efficient Homomorphic Conversion Between (Ring) LWE Ciphertexts
//! <https://eprint.iacr.org/2020/015>

use crate::util::MultiplyU64ModOperand;
#[allow(unused_imports)]
use crate::{
    HeContext, Encryptor, KeyGenerator, Plaintext, Ciphertext,
    EncryptionParameters, BatchEncoder, Evaluator, ParmsID,
    Decryptor, GaloisKeys, CKKSEncoder,
    polymod,
};

/// A LWE Ciphertext, created by extracting from an RLWE ciphertext.
/// 
/// Usually represents one term in the RLWE polynomial.
#[derive(Clone, Debug)]
pub struct LWECiphertext {
    coeff_modulus_size: usize,
    poly_modulus_degree: usize,
    c1: Vec<u64>, // c1.len() == coeff_modulus_size * poly_modulus_degree
    c0: Vec<u64>, // c2.len() == coeff_modulus_size
    parms_id: ParmsID,
    scale: f64,
    correction_factor: u64,
    // term_offset: usize,
}

#[allow(missing_docs)]
impl LWECiphertext {
    pub fn coeff_modulus_size(&self) -> usize {self.coeff_modulus_size}
    pub fn poly_modulus_degree(&self) -> usize {self.poly_modulus_degree}
    pub fn c1(&self) -> &[u64] {&self.c1}
    pub fn c0(&self) -> &[u64] {&self.c0}
    pub fn parms_id(&self) -> &ParmsID {&self.parms_id}
    pub fn scale(&self) -> f64 {self.scale}
    pub fn correction_factor(&self) -> u64 {self.correction_factor}
    // pub fn term_offset(&self) -> usize {self.term_offset}

    /// Convert one LWE ciphertext into a RLWE ciphertext.
    /// The term is placed as the constant term in the polynomial.
    pub fn assemble_lwe(&self) -> Ciphertext {
        let poly_len = self.coeff_modulus_size() * self.poly_modulus_degree();
        let mut data = vec![0; poly_len * 2];
        data[poly_len..].copy_from_slice(&self.c1);
        for (i, c0i) in self.c0.iter().enumerate() {
            data[i * self.poly_modulus_degree()] = *c0i;
        }
        let encrypted = Ciphertext::from_members(
            2,
            self.coeff_modulus_size(),
            self.poly_modulus_degree(),
            data,
            *self.parms_id(),
            self.scale(),
            self.correction_factor(),
            false
        );
        encrypted
    }
}

impl Evaluator {

    /// Extract one term LWE-ciphertext from an RLWE ciphertext.
    pub fn extract_lwe(&self, encrypted: &Ciphertext, term: usize) -> LWECiphertext {
        assert_eq!(encrypted.size(), 2, "Ciphertext size must be 2.");
        if encrypted.is_ntt_form() {
            let encrypted = self.transform_from_ntt_new(encrypted);
            self.extract_lwe(&encrypted, term)
        } else {
            self.check_ciphertext(encrypted);
            // gather c1
            let mut c1 = vec![0; encrypted.poly(1).len()];
            let context_data = self.get_context_data(encrypted.parms_id());
            let poly_modulus_degree = encrypted.poly_modulus_degree();
            let coeff_modulus_size = encrypted.coeff_modulus_size();
            let coeff_modulus = context_data.parms().coeff_modulus();
            let shift = if term == 0 {0} else {poly_modulus_degree * 2 - term};
            polymod::negacyclic_shift_p(encrypted.poly(1), shift, poly_modulus_degree, coeff_modulus, &mut c1);
            // gather c0
            let mut c0 = vec![0u64; coeff_modulus_size];
            for (i, c0i) in c0.iter_mut().enumerate() {
                *c0i = encrypted.poly_component(0, i)[term];
            }
            // additional info
            let parms_id = *encrypted.parms_id();
            let scale = encrypted.scale();
            let correction_factor = encrypted.correction_factor();
            LWECiphertext {
                coeff_modulus_size,
                poly_modulus_degree,
                c1,
                c0,
                parms_id,
                scale,
                correction_factor,
            }
        }
    }

    /// Convert one LWE ciphertext into a RLWE ciphertext.
    /// The term is placed as the constant term in the polynomial.
    pub fn assemble_lwe(&self, encrypted: &LWECiphertext) -> Ciphertext {
        encrypted.assemble_lwe()
    }

    /// Apply field trace. `logn` specifies how many coefficients will be left non-zero after the operation.
    /// For example, if set logn = 0, then there will only be the constant term left.
    pub fn field_trace_inplace(&self, encrypted: &mut Ciphertext, automorphism_keys: &GaloisKeys, logn: usize) {
        let mut poly_degree = self.context().key_context_data().unwrap().parms().poly_modulus_degree();
        let mut temp = Ciphertext::new();
        while poly_degree > (1<<logn) {
            let galois_element = poly_degree + 1;
            self.apply_galois(encrypted, galois_element, automorphism_keys, &mut temp);
            self.add_inplace(encrypted, &temp);
            poly_degree >>= 1;
        }
    }

    /// Divide a ciphertext's polynomial coefficients by N.
    pub fn divide_by_poly_modulus_degree_inplace(&self, encrypted: &mut Ciphertext, mul: Option<u64>) {
        self.check_ciphertext(encrypted);
        let context_data = self.get_context_data(encrypted.parms_id());
        let size = encrypted.size();
        let ntt_tables = context_data.small_ntt_tables();
        let modulus = context_data.parms().coeff_modulus();
        let mut operands = ntt_tables.iter().map(|table| table.inv_degree_modulo()).collect::<Vec<_>>();
        if let Some(mul) = mul {
            for (operand, modulus) in operands.iter_mut().zip(modulus.iter()) {
                let new_operand = modulus.reduce_u128(mul as u128 * operand.operand as u128);
                *operand = MultiplyU64ModOperand::new(new_operand, modulus);
            }
        }
        for poly_id in 0..size {
            for (component_id, (operand, modulus)) in operands.iter().zip(modulus).enumerate() {
                let component = encrypted.poly_component_mut(poly_id, component_id);
                polymod::multiply_operand_inplace(component, operand, modulus);
            }
        }
    }

    /// Pack multiple LWE ciphertexts into a single RLWE ciphertext. Note that the terms are placed so
    /// as to fit the polynomial degree. For example, if you have N=8, and pack 5 LWEs, you will get \[1,2,3,4,5,0,0,0\];
    /// but if you pack only 3 LWEs, you will get \[1,0,2,0,3,0,0,0\].
    pub fn pack_lwe_ciphertexts(&self, lwes: &[LWECiphertext], automorphism_keys: &GaloisKeys) -> Ciphertext {
        let lwes_count = lwes.len();
        if lwes_count == 0 {
            panic!("LWE ciphertexts count must be at least 1.");
        }
        let context_data = self.get_context_data(lwes[0].parms_id());
        let poly_modulus_degree = lwes[0].poly_modulus_degree();
        let parms_id = *lwes[0].parms_id();
        // check all have same parms_id
        for lwe in lwes.iter() {
            assert_eq!(lwe.parms_id(), &parms_id, "All LWE ciphertexts must have the same parms_id.");
        }
        assert!(lwes_count <= poly_modulus_degree, "LWE ciphertexts count must be at most poly_modulus_degree.");
        use crate::util;
        // l as minimum 2^l >= lwes_count
        let mut l = 0; 
        while (1<<l) < lwes_count {
            l += 1;
        }
        let mut rlwes = vec![Ciphertext::new(); 1<<l];
        let mut zero_rlwe = self.assemble_lwe(&lwes[0]);
        zero_rlwe.data_mut().fill(0);
        for i in 0..(1<<l) {
            let index = util::reverse_bits_u64(i as u64, l) as usize;
            if index < lwes_count {
                rlwes[i] = self.assemble_lwe(&lwes[index]);
                self.divide_by_poly_modulus_degree_inplace(&mut rlwes[i], None);
            } else {
                rlwes[i] = zero_rlwe.clone();
            }
        }
        let modulus = context_data.parms().coeff_modulus();
        let mut temp = zero_rlwe.clone(); // buffer
        for layer in 0..l {
            let gap = 1 << layer;
            let mut offset = 0;
            let shift = poly_modulus_degree >> (layer + 1);
            while offset < (1<<l) {
                let even = unsafe {rlwes.as_mut_ptr().add(offset).as_mut().unwrap()};
                let odd = unsafe {rlwes.as_mut_ptr().add(offset + gap).as_mut().unwrap()};
                polymod::negacyclic_shift_ps(odd.data(), shift, odd.size(), poly_modulus_degree, modulus, temp.data_mut());
                // add
                self.sub(even, &temp, odd);
                self.add_inplace(even, &temp);
                // if ckks we need to convert to ntt before doing apply galois
                if context_data.is_ckks() {
                    self.transform_to_ntt_inplace(odd);
                }
                self.apply_galois_inplace(odd, (1<<(layer+1))+1, automorphism_keys);
                // if ckks we need to convert back to normal form
                if context_data.is_ckks() {
                    self.transform_from_ntt_inplace(odd);
                }
                self.add_inplace(even, odd);
                offset += gap * 2;
            }
        }
        // take the first element
        let mut ret = rlwes[0].clone();
        // if ckks we need to convert to ntt
        if context_data.is_ckks() {
            self.transform_to_ntt_inplace(&mut ret);
        }
        // field trace
        self.field_trace_inplace(&mut ret, automorphism_keys, l);
        ret
    }

}

impl KeyGenerator {

    /// Create a GaloisKeys object for PackLWEs.
    pub fn create_automorphism_keys(&self, save_seed: bool) -> GaloisKeys {
        let mut poly_degree = self.context().key_context_data().unwrap().parms().poly_modulus_degree();
        let mut galois_elements = vec![];
        while poly_degree >= 2 {
            galois_elements.push(poly_degree + 1);
            poly_degree >>= 1;
        }
        self.create_galois_keys_from_elts(&galois_elements, save_seed)
    }

}

#[cfg(test)]
mod tests {

    use crate::CoeffModulus;

    use super::*;

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

    #[allow(dead_code)]
    pub fn random_f64_vector(context: &HeContext) -> Vec<f64> {
        let context_data = context.first_context_data().unwrap();
        let parms = context_data.parms();
        let mut vec = vec![0.0; parms.poly_modulus_degree()];
        for i in 0..vec.len() {
            vec[i] = (rand::random::<f64>() - 0.5) * 32.0;
        }
        vec
    }

    #[test]
    fn test_extract_assemble() {
        // setup 
        let params = EncryptionParameters::new(crate::SchemeType::BFV)
            .set_plain_modulus_u64(17)
            .set_coeff_modulus(&CoeffModulus::create(32, vec![30, 30, 30]))
            .set_poly_modulus_degree(32);
        let context = HeContext::new(params, true, crate::SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let encoder = BatchEncoder::new(context.clone());
        let evaluator = Evaluator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false));
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        // plaintext
        let coefficients = random_u64_vector(&context);
        let plaintext = encoder.encode_polynomial_new(&coefficients);
        let ciphertext = encryptor.encrypt_new(&plaintext);
        // extract
        let term = 5;
        let lwe = evaluator.extract_lwe(&ciphertext, term);
        // assemble
        let ciphertext = evaluator.assemble_lwe(&lwe);
        // decrypt
        let plaintext = decryptor.decrypt_new(&ciphertext);
        let decoded = encoder.decode_polynomial_new(&plaintext);
        assert_eq!(coefficients[term], decoded[0]);
    }

    #[test]
    fn test_field_trace_bfv() {
        // setup 
        let params = EncryptionParameters::new(crate::SchemeType::BFV)
            .set_plain_modulus_u64(17)
            .set_coeff_modulus(&CoeffModulus::create(32, vec![30, 30, 30]))
            .set_poly_modulus_degree(32);
        let context = HeContext::new(params.clone(), true, crate::SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let encoder = BatchEncoder::new(context.clone());
        let evaluator = Evaluator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false));
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        
        // he
        let coefficients = random_u64_vector(&context);
        let plaintext = encoder.encode_polynomial_new(&coefficients);
        let mut ciphertext = encryptor.encrypt_new(&plaintext);
        let auto_key = keygen.create_automorphism_keys(false);
        evaluator.field_trace_inplace(&mut ciphertext, &auto_key, 0);
        let plaintext = decryptor.decrypt_new(&ciphertext);
        let decoded = encoder.decode_polynomial_new(&plaintext);

        assert_eq!(params.plain_modulus().reduce(coefficients[0] * params.poly_modulus_degree() as u64), decoded[0]);
        // other places are 0
        for i in 1..decoded.len() {
            assert_eq!(0, decoded[i]);
        }
    }

    #[allow(dead_code)]
    fn print_vec(vec: &[u64]) {
        for i in 0..vec.len() {
            print!("{:2} ", vec[i]);
        }
        println!();
    }

    #[test]
    fn test_pack_lwe_bfv() {
        // setup 
        let params = EncryptionParameters::new(crate::SchemeType::BFV)
            .set_plain_modulus_u64(17)
            .set_coeff_modulus(&CoeffModulus::create(32, vec![30, 30, 30]))
            .set_poly_modulus_degree(32);
        let context = HeContext::new(params.clone(), true, crate::SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let encoder = BatchEncoder::new(context.clone());
        let evaluator = Evaluator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false));
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());

        let lwe_count = 18;
        let coefficients = (0..lwe_count).map(|_| random_u64_vector(&context)).collect::<Vec<_>>();
        let plaintexts = coefficients.iter().map(|coeff| encoder.encode_polynomial_new(coeff)).collect::<Vec<_>>();
        let ciphertexts = plaintexts.iter().map(|plain| encryptor.encrypt_new(plain)).collect::<Vec<_>>();
        let lwes = ciphertexts.iter().enumerate().map(|(i, ciphertext)| evaluator.extract_lwe(ciphertext, i)).collect::<Vec<_>>();
        let auto_key = keygen.create_automorphism_keys(false);
        let packed_cipher = evaluator.pack_lwe_ciphertexts(&lwes, &auto_key);
        let plaintext = decryptor.decrypt_new(&packed_cipher);
        let decoded = encoder.decode_polynomial_new(&plaintext);
        // decoded[i] == coefficients[i][i] for i in lwe_count
        for i in 0..lwe_count.min(decoded.len()) {
            assert_eq!(coefficients[i][i], decoded[i], "i = {}", i);
        }

    }

    fn assert_f64_equal(value1: f64, value2: f64) {
        assert!((value1 - value2).abs() < 1e-3, "{} != {}", value1, value2);
    }
    
    #[test]
    fn test_field_trace_ckks() {
        // setup 
        let scale = 1e7;
        let params = EncryptionParameters::new(crate::SchemeType::CKKS)
            .set_coeff_modulus(&CoeffModulus::create(32, vec![30, 30, 30]))
            .set_poly_modulus_degree(32);
        let context = HeContext::new(params.clone(), true, crate::SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let encoder = CKKSEncoder::new(context.clone());
        let evaluator = Evaluator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false));
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        
        // he
        let coefficients = random_f64_vector(&context);
        let plaintext = encoder.encode_f64_polynomial_new(&coefficients, None, scale);
        let mut ciphertext = encryptor.encrypt_new(&plaintext);
        let auto_key = keygen.create_automorphism_keys(false);
        evaluator.field_trace_inplace(&mut ciphertext, &auto_key, 0);
        let plaintext = decryptor.decrypt_new(&ciphertext);
        let decoded = encoder.decode_polynomial_new(&plaintext);

        assert_f64_equal(coefficients[0] * params.poly_modulus_degree() as f64, decoded[0]);
        // other places are 0
        for i in 1..decoded.len() {
            assert_f64_equal(0.0, decoded[i]);
        }
    }

    
    #[test]
    fn test_pack_lwe_ckks() {
        // setup 
        let scale = 1e7;
        let params = EncryptionParameters::new(crate::SchemeType::CKKS)
            .set_coeff_modulus(&CoeffModulus::create(32, vec![30, 30, 30]))
            .set_poly_modulus_degree(32);
        let context = HeContext::new(params.clone(), true, crate::SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let encoder = CKKSEncoder::new(context.clone());
        let evaluator = Evaluator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false));
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());

        let lwe_count = 18;
        let coefficients = (0..lwe_count).map(|_| random_f64_vector(&context)).collect::<Vec<_>>();
        let plaintexts = coefficients.iter().map(|coeff| encoder.encode_f64_polynomial_new(coeff, None, scale)).collect::<Vec<_>>();
        let ciphertexts = plaintexts.iter().map(|plain| encryptor.encrypt_new(plain)).collect::<Vec<_>>();
        let lwes = ciphertexts.iter().enumerate().map(|(i, ciphertext)| evaluator.extract_lwe(ciphertext, i)).collect::<Vec<_>>();
        let auto_key = keygen.create_automorphism_keys(false);
        let packed_cipher = evaluator.pack_lwe_ciphertexts(&lwes, &auto_key);
        let plaintext = decryptor.decrypt_new(&packed_cipher);
        let decoded = encoder.decode_polynomial_new(&plaintext);
        // decoded[i] == coefficients[i][i] for i in lwe_count
        for i in 0..lwe_count {
            assert_f64_equal(coefficients[i][i], decoded[i]);
        }

    }

    fn pack_lwe_bfv_performance(plain_modulus: u64, poly_modulus_degree: usize, coeff_modulus_bits: Vec<usize>, lwe_count: usize) {
        println!("N = {}, t = {}, log q = {:?}, pack count = {}", poly_modulus_degree, plain_modulus, coeff_modulus_bits, lwe_count);
        // setup 
        let params = EncryptionParameters::new(crate::SchemeType::BFV)
            .set_plain_modulus_u64(plain_modulus)
            .set_coeff_modulus(&CoeffModulus::create(poly_modulus_degree, coeff_modulus_bits))
            .set_poly_modulus_degree(poly_modulus_degree);
        let context = HeContext::new(params.clone(), true, crate::SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let encoder = BatchEncoder::new(context.clone());
        let evaluator = Evaluator::new(context.clone());
        let encryptor = Encryptor::new(context.clone()).set_public_key(keygen.create_public_key(false));
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());

        let coefficients = (0..lwe_count).map(|_| random_u64_vector(&context)).collect::<Vec<_>>();
        let plaintexts = coefficients.iter().map(|coeff| encoder.encode_polynomial_new(coeff)).collect::<Vec<_>>();
        let ciphertexts = plaintexts.iter().map(|plain| encryptor.encrypt_new(plain)).collect::<Vec<_>>();
        let lwes = ciphertexts.iter().enumerate().map(|(i, ciphertext)| evaluator.extract_lwe(ciphertext, i)).collect::<Vec<_>>();
        let auto_key = keygen.create_automorphism_keys(false);
        let time = std::time::Instant::now();
        let packed_cipher = evaluator.pack_lwe_ciphertexts(&lwes, &auto_key);
        println!("pack time: {:?}", time.elapsed());
        let plaintext = decryptor.decrypt_new(&packed_cipher);
        let decoded = encoder.decode_polynomial_new(&plaintext);
        let mut interval = 1;
        // interval -> floor 2^l
        while interval * 2 <= poly_modulus_degree / lwe_count {
            interval *= 2;
        }
        for i in 0..lwe_count {
            assert_eq!(coefficients[i][i], decoded[i * interval], "i = {}", i);
        }

    }

    
    #[test] // cargo test --lib -r test_pack_lwe_bfv_performance -- --ignored --nocapture
    #[ignore] // Don't run by default. Long time...
    fn test_pack_lwe_bfv_performance() {
        pack_lwe_bfv_performance(1<<20, 4096, vec![60, 49], 128);
        pack_lwe_bfv_performance(1<<20, 4096, vec![60, 49], 512);
        pack_lwe_bfv_performance(1<<30, 8192, vec![60, 60, 60], 128);
        pack_lwe_bfv_performance(1<<30, 8192, vec![60, 60, 60], 512);
    }


}