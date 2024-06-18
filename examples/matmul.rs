use heathcliff::{
    app::matmul::{
        cheetah::MatmulHelper as MatmulCheetah, Cipher2d, MatmulHelperObjective,
        bolt_cp::MatmulBoltCp,
    }, 
    perf_utils::{
        print_communication, TimerOnce as Timer
    }, 
    BatchEncoder, CKKSEncoder, CoeffModulus, Decryptor, 
    EncryptionParameters, Encryptor, Evaluator, GaloisKeys, 
    HeContext, KeyGenerator, Modulus, SchemeType, 
    SerializableWithHeContext
};
use clap::Parser;
use rand::Rng;

pub enum Encoder {
    BatchEncoder(BatchEncoder),
    CKKSEncoder(CKKSEncoder),
}

impl Encoder {
    fn as_bfv(&self) -> &BatchEncoder {
        if let Self::BatchEncoder(x) = self {x}
        else {panic!("Unavailable");}
    }
    fn as_ckks(&self) -> &CKKSEncoder {
        if let Self::CKKSEncoder(x) = self {x}
        else {panic!("Unavailable");}
    }
}

pub enum MessageVector {
    U(Vec<u64>),
    F(Vec<f64>)
}

impl MessageVector {
    fn as_bfv(&self) -> &[u64] {
        if let Self::U(x) = self {x}
        else {panic!("Unavailable");}
    }
    fn as_ckks(&self) -> &[f64] {
        if let Self::F(x) = self {x}
        else {panic!("Unavailable");}
    }
}

#[derive(Parser)]
struct Arguments {

    #[arg(short='i', default_value="cheetah")]
    implementation: String,

    #[arg(short='M', default_value_t = 16)]
    batch_size: usize,

    #[arg(short='R', default_value_t = 512)]
    input_dims: usize,

    #[arg(short='N', default_value_t = 10)]
    output_dims: usize,

    #[arg(short='p', default_value_t = 0)]
    poly_modulus_degree: usize,

    #[arg(short='t', default_value_t = 41)]
    log_t: usize,

    #[arg(short='q', default_value="default")]
    log_q: String,

    #[arg(short='s', default_value_t = 2.0f64.powf(40.0))]
    scale: f64,

    #[arg(long="ckks", action=clap::ArgAction::SetTrue)]
    ckks: bool,

    #[arg(short='P', long="no-pack-lwe", action=clap::ArgAction::SetTrue)]
    no_pack_lwe: bool,

}

fn main() {

    let args = Arguments::parse();
    if args.implementation != "cheetah" && args.implementation != "bolt" {
        panic!("Invalid implementation. Must be 'cheetah' or 'bolt'.");
    }
    if args.implementation == "bolt" && args.ckks {
        panic!("BOLT does not support CKKS.");
    }
    let log_q = if args.log_q.as_str() == "default" {
        if args.ckks {
            vec![60, 40, 40, 60]
        } else {
            vec![60, 60, 60]
        }
    } else {
        args.log_q.split(',').map(|x| x.parse::<usize>().unwrap()).collect::<Vec<_>>()
    };
    let mut poly_degree = args.poly_modulus_degree;
    if poly_degree == 0 {
        poly_degree = 8192;
    }
    println!("[Arguments]");
    println!("  Implementation  = {}", args.implementation);
    if args.ckks {
        println!("  Scheme          = CKKS");
    } else {
        println!("  Scheme          = BFV");
    }
    println!("  M = batch size  = {}", args.batch_size);
    println!("  R = input dims  = {}", args.input_dims);
    println!("  N = output dims = {}", args.output_dims);
    println!("  poly degree     = {}", poly_degree);
    if !args.ckks {
        println!("  log t           = {}", args.log_t);
    }
    if args.ckks {
        println!("  scale           = {}", args.scale);
    }
    println!("  log q           = {:?}", log_q);
    if args.implementation == "cheetah" {
        println!("  pack LWE        = {}", !args.no_pack_lwe);
    }

    let scale = args.scale;
    let (plain_modulus, params, context) = match args.implementation.as_str() {
        "cheetah" => {
            let plain_modulus = Modulus::new(1 << args.log_t);
            let params = match args.ckks {
                false => EncryptionParameters::new(SchemeType::BFV)
                    .set_plain_modulus(&plain_modulus)
                    .set_coeff_modulus(&CoeffModulus::create(poly_degree, log_q))
                    .set_poly_modulus_degree(poly_degree),
                true => EncryptionParameters::new(SchemeType::CKKS)
                    .set_coeff_modulus(&CoeffModulus::create(poly_degree, log_q))
                    .set_poly_modulus_degree(poly_degree),
            };
            let context = HeContext::new(params.clone(), true, heathcliff::SecurityLevel::None);
            (plain_modulus, params, context)
        },
        "bolt" => {
            let mut total_bits = vec![args.log_t];
            total_bits.extend(log_q.iter().cloned());
            let mut moduli = CoeffModulus::create(poly_degree, total_bits);
            let plain_modulus = moduli.remove(0);
            let params = EncryptionParameters::new(SchemeType::BFV)
                .set_plain_modulus(&plain_modulus)
                .set_coeff_modulus(&moduli)
                .set_poly_modulus_degree(poly_degree);
            let context = HeContext::new(params.clone(), true, heathcliff::SecurityLevel::None);
            (plain_modulus, params, context)
        },
        _ => unreachable!(),
    };

    println!("[Running]");
    let encoder = match args.ckks {
        false => Encoder::BatchEncoder(BatchEncoder::new(context.clone())),
        true => Encoder::CKKSEncoder(CKKSEncoder::new(context.clone())),
    };
    let keygen = KeyGenerator::new(context.clone());
    let encryptor = Encryptor::new(context.clone()).set_secret_key(keygen.secret_key().clone());
    let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
    let evaluator = Evaluator::new(context.clone());
    let automorphism_key = keygen.create_automorphism_keys(true);
    let galois_key = keygen.create_galois_keys(true);
    let mut stream = vec![];
    let automorphism_key_serialized_bytes = automorphism_key.serialize(&context, &mut stream).unwrap();
    let mut read_stream = stream.as_slice();
    let automorphism_key = GaloisKeys::deserialize(&context, &mut read_stream).unwrap();
    let mut stream = vec![];
    let galois_key_serialized_bytes = galois_key.serialize(&context, &mut stream).unwrap();
    let mut read_stream = stream.as_slice();
    let galois_key = GaloisKeys::deserialize(&context, &mut read_stream).unwrap();

    let batch_size = args.batch_size;
    let input_dims = args.input_dims;
    let output_dims = args.output_dims;
    
    let mut rng = rand::thread_rng();
    let rand_array = 
    |k: usize, rng: &mut rand::rngs::ThreadRng, modulus: &Modulus| -> MessageVector {
        match args.ckks {
            false => MessageVector::U((0..k).map(|_| modulus.reduce(rng.gen())).collect::<Vec<_>>()),
            true => MessageVector::F((0..k).map(|_| rng.gen_range(-2.0..2.0)).collect::<Vec<_>>())
        }
    };

    let inputs = rand_array(batch_size * input_dims, &mut rng, &plain_modulus);
    let weights = rand_array(input_dims * output_dims, &mut rng, &plain_modulus);
    let biases = rand_array(batch_size * output_dims, &mut rng, &plain_modulus);

    if args.implementation == "cheetah" {

        let helper = MatmulCheetah::new(
            batch_size, input_dims, output_dims, poly_degree,
            MatmulHelperObjective::CipherPlain, !args.no_pack_lwe,
        );

        let inputs_encoded = match args.ckks {
            false => helper.encode_inputs_bfv(encoder.as_bfv(), inputs.as_bfv()),
            true => helper.encode_inputs_ckks(encoder.as_ckks(), inputs.as_ckks(), None, args.scale),
        };
        let weights_encoded = match args.ckks { 
            false => helper.encode_weights_bfv(encoder.as_bfv(), weights.as_bfv()),
            true => helper.encode_weights_ckks(encoder.as_ckks(), weights.as_ckks(), None, args.scale),
        };
        let inputs_encrypted = inputs_encoded.encrypt_symmetric(&encryptor);
        let mut stream = vec![];
        let inputs_serialized_bytes = inputs_encrypted.serialize(&context, &mut stream).unwrap();
        let mut read_stream = stream.as_slice();
        let inputs_encrypted = Cipher2d::deserialize(&context, &mut read_stream).unwrap();
        
        let timer = Timer::new().tabs(1);
        let mut outputs_encrypted = helper.matmul(&evaluator, &inputs_encrypted, &weights_encoded);
        timer.finish("matmul");
        
        if !args.no_pack_lwe {
            let timer = Timer::new().tabs(1);
            outputs_encrypted = helper.pack_outputs(&evaluator, &automorphism_key, &outputs_encrypted);
            timer.finish("pack");
        }

        let biases_encoded = match args.ckks { 
            false => helper.encode_outputs_bfv(encoder.as_bfv(), biases.as_bfv()),
            true => helper.encode_outputs_ckks(encoder.as_ckks(), biases.as_ckks(), None, scale * scale / params.coeff_modulus()[params.coeff_modulus().len() - 2].value() as f64),
        };
        // println!("biases len = {}", biases_encoded.data.len() * biases_encoded.data[0].len());
        if args.ckks {
            outputs_encrypted.rescale_to_next_inplace(&evaluator);
        }
        outputs_encrypted.add_plain_inplace(&evaluator, &biases_encoded);

        let outputs_serialized_bytes = if args.no_pack_lwe {
            let output_terms = helper.output_terms();
            let mut stream = vec![];
            let outputs_serialized_bytes = outputs_encrypted.serialize_terms(&context, &output_terms, &mut stream).unwrap();
            let mut read_stream = stream.as_slice();
            outputs_encrypted = Cipher2d::deserialize_terms(&context, &output_terms, &mut read_stream).unwrap();
            outputs_serialized_bytes
        } else {
            let mut outputs_serialized = vec![];
            let outputs_serialized_bytes = outputs_encrypted.serialize(&context, &mut outputs_serialized).unwrap();
            assert_eq!(outputs_serialized.len(), outputs_encrypted.serialized_size(&context));
            outputs_encrypted = Cipher2d::deserialize(&context, &mut outputs_serialized.as_slice()).unwrap();
            outputs_serialized_bytes
        };

        let output_decrypted = match args.ckks {
            false => MessageVector::U(helper.decrypt_outputs_bfv(encoder.as_bfv(), &decryptor, &outputs_encrypted)),
            true => MessageVector::F(helper.decrypt_outputs_ckks(encoder.as_ckks(), &decryptor, &outputs_encrypted)),
        };

        match output_decrypted {
            MessageVector::U(output_decrypted) => {
                let mut outputs_plain = vec![0; batch_size * output_dims];
                for i in 0..batch_size {
                    for j in 0..output_dims {
                        for k in 0..input_dims {
                            let mul = plain_modulus.reduce_u128(
                                inputs.as_bfv()[i * input_dims + k] as u128 * weights.as_bfv()[k * output_dims + j] as u128
                            );
                            let sum = plain_modulus.reduce(
                                outputs_plain[i * output_dims + j] + mul
                            );
                            outputs_plain[i * output_dims + j] = sum;
                        }
                        let sum = plain_modulus.reduce(
                            outputs_plain[i * output_dims + j] + biases.as_bfv()[i * output_dims + j]
                        );
                        outputs_plain[i * output_dims + j] = sum;
                    }
                }
                assert_eq!(outputs_plain, output_decrypted);
            }
            MessageVector::F(output_decrypted) => {
                let mut outputs_plain = vec![0.0; batch_size * output_dims]; 
                for i in 0..batch_size {
                    for j in 0..output_dims {
                        for k in 0..input_dims {
                            outputs_plain[i * output_dims + j] += inputs.as_ckks()[i * input_dims + k] * weights.as_ckks()[k * output_dims + j];
                        }
                        outputs_plain[i * output_dims + j] += biases.as_ckks()[i * output_dims + j];
                    }
                }
                for i in 0..outputs_plain.len() {
                    assert!((outputs_plain[i] - output_decrypted[i]).abs() < 1e-1);
                }
            }
        }

        if !args.no_pack_lwe {
            print_communication("auto-key", 1, automorphism_key_serialized_bytes, 1);
        }
        print_communication("inputs", 1, inputs_serialized_bytes, 1);
        print_communication("outputs", 1, outputs_serialized_bytes, 1);

    } else if args.implementation == "bolt" {

        
        let helper = MatmulBoltCp::new(
            batch_size, input_dims, output_dims, poly_degree
        );

        let inputs_encoded = helper.encode_inputs(encoder.as_bfv(), inputs.as_bfv());
        let weights_encoded = helper.encode_weights(encoder.as_bfv(), weights.as_bfv());
        let inputs_encrypted = inputs_encoded.encrypt_symmetric(&encryptor);
        let mut stream = vec![];
        let inputs_serialized_bytes = inputs_encrypted.serialize(&context, &mut stream).unwrap();
        let mut read_stream = stream.as_slice();
        let inputs_encrypted = Cipher2d::deserialize(&context, &mut read_stream).unwrap();
        
        let timer = Timer::new().tabs(1);
        let mut outputs_encrypted = helper.multiply(&evaluator, &galois_key, &inputs_encrypted, &weights_encoded);
        timer.finish("matmul");
        
        let biases_encoded = helper.encode_outputs(encoder.as_bfv(), biases.as_bfv());
        // println!("biases len = {}", biases_encoded.data.len() * biases_encoded.data[0].len());
        outputs_encrypted.add_plain_inplace(&evaluator, &biases_encoded);

        let outputs_serialized_bytes = {
            let mut outputs_serialized = vec![];
            let outputs_serialized_bytes = outputs_encrypted.serialize(&context, &mut outputs_serialized).unwrap();
            assert_eq!(outputs_serialized.len(), outputs_encrypted.serialized_size(&context));
            outputs_encrypted = Cipher2d::deserialize(&context, &mut outputs_serialized.as_slice()).unwrap();
            outputs_serialized_bytes
        };

        let decrypted = outputs_encrypted.decrypt(&decryptor);
        let output_decrypted = helper.decode_outputs(encoder.as_bfv(), &decrypted);

        let mut outputs_plain = vec![0; batch_size * output_dims];
        for i in 0..batch_size {
            for j in 0..output_dims {
                for k in 0..input_dims {
                    let mul = plain_modulus.reduce_u128(
                        inputs.as_bfv()[i * input_dims + k] as u128 * weights.as_bfv()[k * output_dims + j] as u128
                    );
                    let sum = plain_modulus.reduce(
                        outputs_plain[i * output_dims + j] + mul
                    );
                    outputs_plain[i * output_dims + j] = sum;
                }
                let sum = plain_modulus.reduce(
                    outputs_plain[i * output_dims + j] + biases.as_bfv()[i * output_dims + j]
                );
                outputs_plain[i * output_dims + j] = sum;
            }
        }
        assert_eq!(outputs_plain, output_decrypted);
                
        print_communication("galois-key", 1, galois_key_serialized_bytes, 1);
        print_communication("inputs", 1, inputs_serialized_bytes, 1);
        print_communication("outputs", 1, outputs_serialized_bytes, 1);

    }
    
}