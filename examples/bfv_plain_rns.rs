use heathcliff::{
    CoeffModulus, SchemeType, SecurityLevel,
    app::rns_plain::renamed::{
        HeContext, BatchEncoder, Encryptor, EncryptionParameters, 
        Decryptor, Evaluator, KeyGenerator, ExpandSeed,
    },
};
use rand::{Rng, SeedableRng};

fn generate_vector<R: Rng>(max: u64, count: usize, rng: &mut R) -> Vec<u64> {
    let uniform = rand::distributions::Uniform::new(0, max);
    (0..count).map(|_| rng.sample(uniform)).collect()
}

fn main() {

    let plain_modulus_lengths = vec![45, 45, 45, 45];
    let coeff_modulus_lengths = vec![60, 60, 60];
    let poly_modulus_degree = 8192;
    let operand_bitlength = 61;
    let plain_rns_count = plain_modulus_lengths.len();

    // generate moduli
    let mut total_modulus_lengths = plain_modulus_lengths.clone();
    total_modulus_lengths.extend(coeff_modulus_lengths.clone());
    let total_moduli = CoeffModulus::create(poly_modulus_degree, total_modulus_lengths);
    let plain_moduli = total_moduli[..plain_modulus_lengths.len()].to_vec();
    let coeff_moduli = total_moduli[plain_modulus_lengths.len()..].to_vec();
    println!("plain_moduli = {:?}", plain_moduli.iter().map(|x| x.value()).collect::<Vec<_>>());
    println!("coeff_moduli = {:?}", coeff_moduli.iter().map(|x| x.value()).collect::<Vec<_>>());

    // generate contexts
    let params = EncryptionParameters::new(SchemeType::BFV)
            .set_coeff_modulus(coeff_moduli)
            .set_plain_modulus(plain_moduli)
            .set_poly_modulus_degree(poly_modulus_degree);
    let context = HeContext::new(params, true, SecurityLevel::None);
    let encoder = BatchEncoder::new(&context);
    let keygen = KeyGenerator::new(&context);
    let secret_key = keygen.get_secret_key();
    let encryptor = Encryptor::new(&context).set_secret_key(secret_key.clone());
    let decryptor = Decryptor::new(&context, secret_key);
    let evaluator = Evaluator::new(&context);

    // generate operand
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0; 32]);
    let a = generate_vector(1 << operand_bitlength, poly_modulus_degree, &mut rng);
    let b = generate_vector(1 << operand_bitlength, poly_modulus_degree, &mut rng);
    let operand_mask = (1 << operand_bitlength) - 1;
    let c_truth = a.iter().zip(b.iter()).map(|(a, b)| a.wrapping_mul(*b) & operand_mask).collect::<Vec<_>>();
    println!("a = {}, b = {}, c_truth = {}", a[0], b[0], c_truth[0]);

    #[allow(unused_variables)]
    let print_rns = |x: &[u64]| -> String {
        let mut s = String::new();
        for i in 0..plain_rns_count {
            s.push_str(&format!("{}", x[i * poly_modulus_degree]));
            if i != plain_rns_count - 1 { s.push_str(", "); }
        }
        s
    };

    // rns decompose
    let mut a_rns = vec![0; poly_modulus_degree * plain_rns_count];
    for i in 0..poly_modulus_degree { a_rns[i * plain_rns_count] = a[i]; }
    let mut b_rns = vec![0; poly_modulus_degree * plain_rns_count];
    for i in 0..poly_modulus_degree { b_rns[i * plain_rns_count] = b[i]; }
    
    let mut a_debug = a_rns.clone();
    encoder.rns_decompose(&mut a_debug);
    println!("a_rns = [{}]", print_rns(&a_debug));
    let mut b_debug = b_rns.clone();
    encoder.rns_decompose(&mut b_debug);
    println!("b_rns = [{}]", print_rns(&b_debug));

    // encode and encrypt
    let a_encoded = encoder.encode_new(&a_rns);
    let a_encrypted = encryptor.encrypt_symmetric_new(&a_encoded).expand_seed(&context);
    let b_encoded = encoder.encode_new(&b_rns);

    // multiply
    let c_encrypted = evaluator.multiply_plain_new(&a_encrypted, &b_encoded);
    
    // decrypt and decode and modulo
    let c_decrypted = decryptor.decrypt_new(&c_encrypted);
    let c_result = encoder.decode_new(&c_decrypted);
    
    let mut c_debug = c_result.clone();
    encoder.rns_decompose(&mut c_debug);
    println!("c_rns = [{}]", print_rns(&c_debug));

    let mut c = vec![0; poly_modulus_degree];
    for (i, c_rns) in c_result.chunks(plain_rns_count).enumerate() {
        c[i] = c_rns[0] & operand_mask;
    }

    println!("c = {}", c[0]);

    // assert equal
    assert_eq!(c, c_truth);

}