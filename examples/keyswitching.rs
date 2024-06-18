use heathcliff::{
    EncryptionParameters, Evaluator, KeyGenerator, HeContext, CoeffModulus,
    BatchEncoder, Encryptor, Decryptor, ExpandSeed,
};

fn main() {

    let log_t = 20;
    let log_q = vec![60, 40, 40, 60];
    let n = 8192;

    let params = EncryptionParameters::new(heathcliff::SchemeType::BFV)
        .set_poly_modulus_degree(n)
        .set_plain_modulus_u64(1<<log_t)
        .set_coeff_modulus(&CoeffModulus::create(n, log_q));

    let context = HeContext::new(params, true, heathcliff::SecurityLevel::Tc128);
    let encoder = BatchEncoder::new(context.clone());
    let keygen = KeyGenerator::new(context.clone());
    let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
    let evaluator = Evaluator::new(context.clone());

    // create another secret key
    let keygen_other = KeyGenerator::new(context.clone());
    let secret_key_other = keygen_other.secret_key().clone();
    let encryptor_other = Encryptor::new(context.clone()).set_secret_key(secret_key_other.clone());
    let decryptor_other = Decryptor::new(context.clone(), secret_key_other.clone());

    // create ksk from sk' to sk
    let kswitch_key = keygen.create_keyswitching_key(keygen_other.secret_key(), true);
    let kswitch_key = kswitch_key.expand_seed(&context);

    // encrypt something with sk'
    let message = vec![1, 2, 3, 4];
    let plaintext = encoder.encode_polynomial_new(&message);
    let ciphertext = encryptor_other.encrypt_symmetric_new(&plaintext).expand_seed(&context);

    // decrypt and see correct
    let decoded = encoder.decode_polynomial_new(&decryptor_other.decrypt_new(&ciphertext));
    assert_eq!(decoded[..message.len()], message);

    // switch to sk
    let ciphertext = evaluator.apply_keyswitching_new(&ciphertext, &kswitch_key);

    // decrypt and see correct
    let decoded = encoder.decode_polynomial_new(&decryptor.decrypt_new(&ciphertext));
    assert_eq!(decoded[..message.len()], message);



}