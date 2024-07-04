use criterion::{black_box, criterion_group, criterion_main, Criterion};
use heathcliff::{
    EncryptionParameters,
    HeContext,
    Plaintext,
    Ciphertext,
    BatchEncoder,
    KeyGenerator, SchemeType, PlainModulus, CoeffModulus, SecurityLevel, Encryptor, Decryptor, Evaluator, CKKSEncoder
};
use num_complex::Complex64;

#[allow(clippy::too_many_arguments)]
fn test_suite<F: Fn(String) -> String>(
    c: &mut Criterion, get_name: F,
    plain: Plaintext, 
    keygen: KeyGenerator, 
    encryptor: Encryptor, decryptor: Decryptor, 
    evaluator: Evaluator, 
    test_mod_switch: bool, test_rescale: bool,
    is_ckks: bool,
) {

    let mut cipher = Ciphertext::new();

    c.bench_function(get_name("Encrypt".to_string()).as_str(), |b| b.iter(|| encryptor.encrypt(black_box(&plain), &mut cipher)));
    c.bench_function(get_name("EncryptSym".to_string()).as_str(), |b| b.iter(|| encryptor.encrypt_symmetric(black_box(&plain), &mut cipher)));

    let mut cipher: Ciphertext = encryptor.encrypt_new(&plain);
    let mut decrypted: Plaintext = Plaintext::new();
    c.bench_function(get_name("Decrypt".to_string()).as_str(), |b| b.iter(|| decryptor.decrypt(black_box(&cipher), &mut decrypted)));

    let cipher1 = encryptor.encrypt_new(&plain);
    let cipher2 = encryptor.encrypt_new(&plain);
    
    c.bench_function(get_name("Add".to_string()).as_str(), |b| b.iter(|| evaluator.add(&cipher1, &cipher2, &mut cipher)));
    c.bench_function(get_name("Sub".to_string()).as_str(), |b| b.iter(|| evaluator.sub(&cipher1, &cipher2, &mut cipher)));

    c.bench_function(get_name("AddPlain".to_string()).as_str(), |b| b.iter(|| evaluator.add_plain(&cipher1, &plain, &mut cipher)));
    c.bench_function(get_name("SubPlain".to_string()).as_str(), |b| b.iter(|| evaluator.sub_plain(&cipher1, &plain, &mut cipher)));

    c.bench_function(get_name("Mul".to_string()).as_str(), |b| b.iter(|| evaluator.multiply(&cipher1, &cipher2, &mut cipher)));
    c.bench_function(get_name("MulPlain".to_string()).as_str(), |b| b.iter(|| evaluator.multiply_plain(&cipher1, &plain, &mut cipher)));
    
    c.bench_function(get_name("Square".to_string()).as_str(), |b| b.iter(|| evaluator.square(&cipher1, &mut cipher)));

    let cipher3 = evaluator.multiply_new(&cipher1, &cipher2);
    let relin_keys = keygen.create_relin_keys(false);

    c.bench_function(get_name("Relinear".to_string()).as_str(), |b| b.iter(|| evaluator.relinearize(&cipher3, &relin_keys, &mut cipher)));

    if test_mod_switch {
        c.bench_function(get_name("Modswitch".to_string()).as_str(), |b| b.iter(|| evaluator.mod_switch_to_next(&cipher1, &mut cipher)));
    }
    if test_rescale {
        c.bench_function(get_name("Rescale".to_string()).as_str(), |b| b.iter(|| evaluator.rescale_to_next(&cipher1, &mut cipher)));
    }

    let galois_keys = keygen.create_galois_keys(false);
    if !is_ckks {
        let mut plain_ntt = Plaintext::new();
        c.bench_function(get_name("ToNTT".to_string()).as_str(), |b| b.iter(|| evaluator.transform_to_ntt(&cipher1, &mut cipher)));
        c.bench_function(get_name("PlainToNTT".to_string()).as_str(), |b| b.iter(|| evaluator.transform_plain_to_ntt(&plain, cipher1.parms_id(), &mut plain_ntt)));
        let cipher_ntt = evaluator.transform_to_ntt_new(&cipher1);
        c.bench_function(get_name("FromNTT".to_string()).as_str(), |b| b.iter(|| evaluator.transform_from_ntt(&cipher_ntt, &mut cipher)));
        c.bench_function(get_name("RotRows(1)".to_string()).as_str(), |b| b.iter(|| evaluator.rotate_rows(&cipher1, 1, &galois_keys, &mut cipher)));
        c.bench_function(get_name("RotRows(7)".to_string()).as_str(), |b| b.iter(|| evaluator.rotate_rows(&cipher1, 7, &galois_keys, &mut cipher)));
        c.bench_function(get_name("RotCols".to_string()).as_str(), |b| b.iter(|| evaluator.rotate_columns(&cipher1, &galois_keys, &mut cipher)));
    } else {
        c.bench_function(get_name("FromNTT".to_string()).as_str(), |b| b.iter(|| evaluator.transform_from_ntt(&cipher1, &mut cipher)));
        let cipher_intt = evaluator.transform_from_ntt_new(&cipher1);
        c.bench_function(get_name("ToNTT".to_string()).as_str(), |b| b.iter(|| evaluator.transform_to_ntt(&cipher_intt, &mut cipher)));
        c.bench_function(get_name("RotVec(1)".to_string()).as_str(), |b| b.iter(|| evaluator.rotate_vector(&cipher1, 1, &galois_keys, &mut cipher)));
        c.bench_function(get_name("RotVec(7)".to_string()).as_str(), |b| b.iter(|| evaluator.rotate_vector(&cipher1, 7, &galois_keys, &mut cipher)));
        c.bench_function(get_name("Conjugate".to_string()).as_str(), |b| b.iter(|| evaluator.complex_conjugate(&cipher1, &galois_keys, &mut cipher)));
    }

} 

fn bfvbgv_benchmark(c: &mut Criterion, name: String, poly_modulus_degree: usize, plain_modulus_bits: usize, coeff_modulus_bits: Vec<usize>, is_bgv: bool) {
    
    let parms = EncryptionParameters::new(if !is_bgv {SchemeType::BFV} else {SchemeType::BGV})
        .set_poly_modulus_degree(poly_modulus_degree)
        .set_plain_modulus(&PlainModulus::batching(poly_modulus_degree, plain_modulus_bits))
        .set_coeff_modulus(&CoeffModulus::create(poly_modulus_degree, coeff_modulus_bits.clone()));
    let context = HeContext::new(parms, true, SecurityLevel::Tc128);

    let get_name = |func: String| -> String {format!("{}({}) {}", if !is_bgv {"BFV"} else {"BGV"}, name, func)};
    
    let encoder = BatchEncoder::new(context.clone());
    let message = (0..poly_modulus_degree).map(|x| x as u64).collect::<Vec<_>>();
    let mut plain = encoder.encode_new(&message);
    c.bench_function(get_name("Encode".to_string()).as_str(), |b| b.iter(|| encoder.encode(black_box(&message), &mut plain)));
    let mut decoded_message: Vec<u64> = vec![];
    c.bench_function(get_name("Decode".to_string()).as_str(), |b| b.iter(|| encoder.decode(black_box(&plain), &mut decoded_message)));
    
    let keygen = KeyGenerator::new(context.clone());
    let public_key = keygen.create_public_key(false);
    let encryptor = Encryptor::new(context.clone()).set_public_key(public_key.clone()).set_secret_key(keygen.secret_key().clone());
    let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
    let evaluator = Evaluator::new(context.clone());

    test_suite(c, get_name, plain, keygen, encryptor, decryptor, evaluator, coeff_modulus_bits.len() > 2, false, false);

}

fn ckks_benchmark(c: &mut Criterion, name: String, poly_modulus_degree: usize, coeff_modulus_bits: Vec<usize>, scale: f64) {
    
    let parms = EncryptionParameters::new(SchemeType::CKKS)
        .set_poly_modulus_degree(poly_modulus_degree)
        .set_coeff_modulus(&CoeffModulus::create(poly_modulus_degree, coeff_modulus_bits.clone()));
    let context = HeContext::new(parms, true, SecurityLevel::Tc128);

    let get_name = |func: String| -> String {format!("{}({}) {}", "CKKS", name, func)};
    
    let encoder = CKKSEncoder::new(context.clone());
    let message = (0..poly_modulus_degree/2).map(|x| Complex64::new(x as f64, 0.0)).collect::<Vec<_>>();
    c.bench_function(get_name("Encode".to_string()).as_str(), |b| b.iter(|| encoder.encode_c64_array_new(black_box(&message), None, scale)));
    let plain = encoder.encode_c64_array_new(&message, None, scale);
    c.bench_function(get_name("Decode".to_string()).as_str(), |b| b.iter(|| encoder.decode_new(black_box(&plain))));
    
    let keygen = KeyGenerator::new(context.clone());
    let public_key = keygen.create_public_key(false);
    let encryptor = Encryptor::new(context.clone()).set_public_key(public_key.clone()).set_secret_key(keygen.secret_key().clone());
    let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
    let evaluator = Evaluator::new(context.clone());

    test_suite(c, get_name, plain, keygen, encryptor, decryptor, evaluator, false, coeff_modulus_bits.len() > 2, true);

}



fn criterion_bfv_benchmark(c: &mut Criterion) {

    let poly_modulus_degree = 4096;
    let plain_modulus_bits = 20;
    let coeff_modulus_bits = vec![40, 40];
    bfvbgv_benchmark(c, "s".to_string(), poly_modulus_degree, plain_modulus_bits, coeff_modulus_bits, false);

    let poly_modulus_degree = 8192;
    let plain_modulus_bits = 30;
    let coeff_modulus_bits = vec![60, 60, 60];
    bfvbgv_benchmark(c, "m".to_string(), poly_modulus_degree, plain_modulus_bits, coeff_modulus_bits, false);

    let poly_modulus_degree = 16384;
    let plain_modulus_bits = 30;
    let coeff_modulus_bits = vec![60, 40, 40, 40, 40, 60];
    bfvbgv_benchmark(c, "l".to_string(), poly_modulus_degree, plain_modulus_bits, coeff_modulus_bits, false);

}

fn criterion_bgv_benchmark(c: &mut Criterion) {

    let poly_modulus_degree = 4096;
    let plain_modulus_bits = 20;
    let coeff_modulus_bits = vec![40, 40];
    bfvbgv_benchmark(c, "s".to_string(), poly_modulus_degree, plain_modulus_bits, coeff_modulus_bits, true);

    let poly_modulus_degree = 8192;
    let plain_modulus_bits = 30;
    let coeff_modulus_bits = vec![60, 60, 60];
    bfvbgv_benchmark(c, "m".to_string(), poly_modulus_degree, plain_modulus_bits, coeff_modulus_bits, true);

    let poly_modulus_degree = 16384;
    let plain_modulus_bits = 30;
    let coeff_modulus_bits = vec![60, 40, 40, 40, 40, 60];
    bfvbgv_benchmark(c, "l".to_string(), poly_modulus_degree, plain_modulus_bits, coeff_modulus_bits, true);

}

fn criterion_ckks_benchmark(c: &mut Criterion) {

    let poly_modulus_degree = 4096;
    let scale = (1<<20) as f64;
    let coeff_modulus_bits = vec![60, 40];
    ckks_benchmark(c, "s".to_string(), poly_modulus_degree, coeff_modulus_bits, scale);

    let poly_modulus_degree = 8192;
    let scale = (1_u64<<40) as f64;
    let coeff_modulus_bits = vec![60, 60, 60];
    ckks_benchmark(c, "m".to_string(), poly_modulus_degree, coeff_modulus_bits, scale);
    
    let poly_modulus_degree = 16384;
    let scale = (1_u64<<40) as f64;
    let coeff_modulus_bits = vec![60, 40, 40, 40, 40, 60];
    ckks_benchmark(c, "l".to_string(), poly_modulus_degree, coeff_modulus_bits, scale);

}

criterion_group!(bench_bfv, criterion_bfv_benchmark);
criterion_group!(bench_bgv, criterion_bgv_benchmark);
criterion_group!(bench_ckks, criterion_ckks_benchmark);
criterion_main!(bench_bfv, bench_bgv, bench_ckks);