use std::sync::Arc;

use crate::{
    KeyGenerator, 
    BatchEncoder, 
    Encryptor, 
    Decryptor, 
    HeContext, 
    EncryptionParameters, 
    SchemeType, 
    CoeffModulus, 
    SecurityLevel, Evaluator, PublicKey, RelinKeys, GaloisKeys, CKKSEncoder
};

/// Create BFV utilities suite for the encrypting/decrypting party.
pub fn create_bfv_decryptor_suite(poly_modulus_degree: usize, plain_modulus_bits: usize, coeff_modulus_bits: Vec<usize>) 
    -> (EncryptionParameters, Arc<HeContext>, BatchEncoder, KeyGenerator, Encryptor, Decryptor) 
{
    let mut total_bits = coeff_modulus_bits.clone();
    total_bits.push(plain_modulus_bits);
    let all_modulus = CoeffModulus::create(poly_modulus_degree, total_bits);
    let params = EncryptionParameters::new(SchemeType::BFV)
        .set_poly_modulus_degree(poly_modulus_degree)
        .set_plain_modulus(&all_modulus[coeff_modulus_bits.len()])
        .set_coeff_modulus(&all_modulus[..coeff_modulus_bits.len()]);
    let context = HeContext::new(params.clone(), true, SecurityLevel::Tc128);
    let keygen = KeyGenerator::new(context.clone());
    let encryptor = Encryptor::new(context.clone())
        .set_public_key(keygen.create_public_key(false))
        .set_secret_key(keygen.secret_key().clone());
    let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
    let encoder = BatchEncoder::new(context.clone());
    (params, context, encoder, keygen, encryptor, decryptor)
}

/// Create BFV utilities suite for the HE evaluation party.
pub fn create_bfv_evaluator_suite(poly_modulus_degree: usize, plain_modulus_bits: usize, coeff_modulus_bits: Vec<usize>, public_key: PublicKey)
    -> (EncryptionParameters, Arc<HeContext>, BatchEncoder, Encryptor, Evaluator)
{
    let mut total_bits = coeff_modulus_bits.clone();
    total_bits.push(plain_modulus_bits);
    let all_modulus = CoeffModulus::create(poly_modulus_degree, total_bits);
    let params = EncryptionParameters::new(SchemeType::BFV)
        .set_poly_modulus_degree(poly_modulus_degree)
        .set_plain_modulus(&all_modulus[coeff_modulus_bits.len()])
        .set_coeff_modulus(&all_modulus[..coeff_modulus_bits.len()]);
    let context = HeContext::new(params.clone(), true, SecurityLevel::Tc128);
    let encryptor = Encryptor::new(context.clone())
        .set_public_key(public_key);
    let evaluator = Evaluator::new(context.clone());
    let encoder = BatchEncoder::new(context.clone());
    (params, context, encoder, encryptor, evaluator)
}

/// Create BFV utilities suite for the HE evaluation party.
pub fn create_bfv_evaluator_suite_from_params(params: EncryptionParameters) 
    -> (Arc<HeContext>, BatchEncoder, Evaluator)
{
    let context = HeContext::new(params.clone(), true, SecurityLevel::Tc128);
    let evaluator = Evaluator::new(context.clone());
    let encoder = BatchEncoder::new(context.clone());
    (context, encoder, evaluator)
}

/// Create BGV utilities suite for the encrypting/decrypting party.
pub fn create_bgv_decryptor_suite(poly_modulus_degree: usize, plain_modulus_bits: usize, coeff_modulus_bits: Vec<usize>) 
    -> (EncryptionParameters, Arc<HeContext>, BatchEncoder, KeyGenerator, Encryptor, Decryptor) 
{
    let mut total_bits = coeff_modulus_bits.clone();
    total_bits.push(plain_modulus_bits);
    let all_modulus = CoeffModulus::create(poly_modulus_degree, total_bits);
    let params = EncryptionParameters::new(SchemeType::BGV)
        .set_poly_modulus_degree(poly_modulus_degree)
        .set_plain_modulus(&all_modulus[coeff_modulus_bits.len()])
        .set_coeff_modulus(&all_modulus[..coeff_modulus_bits.len()]);
    let context = HeContext::new(params.clone(), true, SecurityLevel::Tc128);
    let keygen = KeyGenerator::new(context.clone());
    let encryptor = Encryptor::new(context.clone())
        .set_public_key(keygen.create_public_key(false))
        .set_secret_key(keygen.secret_key().clone());
    let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
    let encoder = BatchEncoder::new(context.clone());
    (params, context, encoder, keygen, encryptor, decryptor)
}

/// Create BGV utilities suite for the HE evaluation party.
pub fn create_bgv_evaluator_suite(poly_modulus_degree: usize, plain_modulus_bits: usize, coeff_modulus_bits: Vec<usize>, public_key: PublicKey)
    -> (EncryptionParameters, Arc<HeContext>, BatchEncoder, Encryptor, Evaluator)
{
    let mut total_bits = coeff_modulus_bits.clone();
    total_bits.push(plain_modulus_bits);
    let all_modulus = CoeffModulus::create(poly_modulus_degree, total_bits);
    let params = EncryptionParameters::new(SchemeType::BGV)
        .set_poly_modulus_degree(poly_modulus_degree)
        .set_plain_modulus(&all_modulus[coeff_modulus_bits.len()])
        .set_coeff_modulus(&all_modulus[..coeff_modulus_bits.len()]);
    let context = HeContext::new(params.clone(), true, SecurityLevel::Tc128);
    let encryptor = Encryptor::new(context.clone())
        .set_public_key(public_key);
    let evaluator = Evaluator::new(context.clone());
    let encoder = BatchEncoder::new(context.clone());
    (params, context, encoder, encryptor, evaluator)
}

/// Create BGV utilities suite for the HE evaluation party.
pub fn create_bgv_evaluator_suite_from_params(params: EncryptionParameters) 
    -> (Arc<HeContext>, BatchEncoder, Evaluator)
{
    let context = HeContext::new(params.clone(), true, SecurityLevel::Tc128);
    let evaluator = Evaluator::new(context.clone());
    let encoder = BatchEncoder::new(context.clone());
    (context, encoder, evaluator)
}

/// Create CKKS utilities suite for the encrypting/decrypting party.
pub fn create_ckks_decryptor_suite(poly_modulus_degree: usize, coeff_modulus_bits: Vec<usize>) 
    -> (EncryptionParameters, Arc<HeContext>, CKKSEncoder, KeyGenerator, Encryptor, Decryptor) 
{
    let params = EncryptionParameters::new(SchemeType::CKKS)
        .set_poly_modulus_degree(poly_modulus_degree)
        .set_coeff_modulus(&CoeffModulus::create(poly_modulus_degree, coeff_modulus_bits));
    let context = HeContext::new(params.clone(), true, SecurityLevel::Tc128);
    let keygen = KeyGenerator::new(context.clone());
    let encryptor = Encryptor::new(context.clone())
        .set_public_key(keygen.create_public_key(false))
        .set_secret_key(keygen.secret_key().clone());
    let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
    let encoder = CKKSEncoder::new(context.clone());
    (params, context, encoder, keygen, encryptor, decryptor)
}

/// Create CKKS utilities suite for the HE evaluation party.
pub fn create_ckks_evaluator_suite(poly_modulus_degree: usize, coeff_modulus_bits: Vec<usize>, public_key: PublicKey)
    -> (EncryptionParameters, Arc<HeContext>, CKKSEncoder, Encryptor, Evaluator)
{
    let params = EncryptionParameters::new(SchemeType::CKKS)
        .set_poly_modulus_degree(poly_modulus_degree)
        .set_coeff_modulus(&CoeffModulus::create(poly_modulus_degree, coeff_modulus_bits));
    let context = HeContext::new(params.clone(), true, SecurityLevel::Tc128);
    let encryptor = Encryptor::new(context.clone())
        .set_public_key(public_key);
    let evaluator = Evaluator::new(context.clone());
    let encoder = CKKSEncoder::new(context.clone());
    (params, context, encoder, encryptor, evaluator)
}

/// Create CKKS utilities suite for the HE evaluation party.
pub fn create_ckks_evaluator_suite_from_params(params: EncryptionParameters) 
    -> (Arc<HeContext>, CKKSEncoder, Evaluator)
{
    let context = HeContext::new(params.clone(), true, SecurityLevel::Tc128);
    let evaluator = Evaluator::new(context.clone());
    let encoder = CKKSEncoder::new(context.clone());
    (context, encoder, evaluator)
}

impl KeyGenerator {
    /// Create public key, relinearization keys and galois keys.
    pub fn create_public_keys(&self, save_seed: bool) -> (PublicKey, RelinKeys, GaloisKeys) {
        let public_key = self.create_public_key(save_seed);
        let relin_keys = self.create_relin_keys(save_seed);
        let galois_keys = self.create_galois_keys(save_seed);
        (public_key, relin_keys, galois_keys)
    }

}

