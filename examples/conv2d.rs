use heathcliff::{
    HeContext, Encryptor, Decryptor,
    BatchEncoder, Evaluator, CKKSEncoder,
    EncryptionParameters, KeyGenerator, 
    SchemeType, SerializableWithHeContext,
    app::{matmul::{
        MatmulHelperObjective,
        Cipher2d,
    }, conv2d::Conv2dHelper}, 
    Modulus, CoeffModulus,
    perf_utils::{
        TimerOnce as Timer,
        print_communication,
    },
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

    #[arg(short='B', default_value_t = 1)]
    batch_size: usize,

    #[arg(short='I', default_value_t = 64)]
    input_channels: usize,

    #[arg(short='O', default_value_t = 256)]
    output_channels: usize,

    #[arg(short='H', default_value_t = 56)]
    image_height: usize,

    #[arg(short='W', default_value_t = 0)]
    image_width: usize,

    #[arg(long="kh", default_value_t = 3)]
    kernel_height: usize,

    #[arg(long="kw", default_value_t = 0)]
    kernel_width: usize,

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

}

fn main() {

    let mut args = Arguments::parse();
    // let objective = match args.objective.to_lowercase().as_str() {
    //     "cipherplain" => MatmulHelperObjective::CipherPlain,
    //     "plaincipher" => MatmulHelperObjective::PlainCipher,
    //     "cpaddpc" => MatmulHelperObjective::CpAddPc,
    //     _ => panic!("Invalid objective. Should be one of CipherPlain, PlainCipher, CpAddPc"),
    // };
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
    if args.ckks {
        println!("  Scheme            = CKKS");
    } else {
        println!("  Scheme            = BFV");
    }
    if args.image_width == 0 {
        args.image_width = args.image_height;
    }
    if args.kernel_width == 0 {
        args.kernel_width = args.kernel_height;
    }
    println!("  B = batch size    = {}", args.batch_size);
    println!("  I = in channels   = {}", args.input_channels);
    println!("  O = out channels  = {}", args.output_channels);
    println!("  H = image height  = {}", args.image_height);
    println!("  W = image width   = {}", args.image_width);
    println!("  h = kernel height = {}", args.kernel_height);
    println!("  w = kernel width  = {}", args.kernel_width);
    
    println!("  poly degree       = {}", poly_degree);
    if !args.ckks {
        println!("  log t             = {}", args.log_t);
    }
    if args.ckks {
        println!("  scale             = {}", args.scale);
    }
    println!("  log q             = {:?}", log_q);

    let plain_modulus = Modulus::new(1 << args.log_t);
    let scale = args.scale;
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

    println!("[Running]");
    let encoder = match args.ckks {
        false => Encoder::BatchEncoder(BatchEncoder::new(context.clone())),
        true => Encoder::CKKSEncoder(CKKSEncoder::new(context.clone())),
    };
    let keygen = KeyGenerator::new(context.clone());
    let encryptor = Encryptor::new(context.clone()).set_secret_key(keygen.secret_key().clone());
    let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
    let evaluator = Evaluator::new(context.clone());

    let batch_size = args.batch_size;
    let input_channels = args.input_channels;
    let output_channels = args.output_channels;
    let image_height = args.image_height;
    let image_width = args.image_width;
    let kernel_height = args.kernel_height;
    let kernel_width = args.kernel_width;
    let poly_modulus_degree = poly_degree;

    let helper = Conv2dHelper::new(
        batch_size, input_channels, output_channels, image_height, image_width, kernel_height, kernel_width,
        poly_modulus_degree, MatmulHelperObjective::CipherPlain
    );
    
    let mut rng = rand::thread_rng();
    let rand_array = 
    |k: usize, rng: &mut rand::rngs::ThreadRng, modulus: &Modulus| -> MessageVector {
        match args.ckks {
            false => MessageVector::U((0..k).map(|_| modulus.reduce(rng.gen())).collect::<Vec<_>>()),
            true => MessageVector::F((0..k).map(|_| rng.gen_range(-2.0..2.0)).collect::<Vec<_>>())
        }
    };

    let input_size = batch_size * input_channels * image_height * image_width;
    let output_height = image_height - kernel_height + 1;
    let output_width = image_width - kernel_width + 1;
    let output_size = batch_size * output_channels * output_height * output_width;
    let weight_size = input_channels * output_channels * kernel_height * kernel_width;

    let inputs = rand_array(input_size, &mut rng, &plain_modulus);
    let weights = rand_array(weight_size, &mut rng, &plain_modulus);
    let biases = rand_array(output_size, &mut rng, &plain_modulus);

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
    let mut outputs_encrypted = helper.conv2d(&evaluator, &inputs_encrypted, &weights_encoded);
    timer.finish("matmul");

    let biases_encoded = match args.ckks { 
        false => helper.encode_outputs_bfv(encoder.as_bfv(), biases.as_bfv()),
        true => helper.encode_outputs_ckks(encoder.as_ckks(), biases.as_ckks(), None, scale * scale / params.coeff_modulus()[params.coeff_modulus().len() - 2].value() as f64),
    };
    // println!("biases len = {}", biases_encoded.data.len() * biases_encoded.data[0].len());
    if args.ckks {
        outputs_encrypted.rescale_to_next_inplace(&evaluator);
    }
    outputs_encrypted.add_plain_inplace(&evaluator, &biases_encoded);

    let outputs_serialized_bytes = {
        let output_terms = helper.output_terms();
        let mut stream = vec![];
        let outputs_serialized_bytes = outputs_encrypted.serialize_terms(&context, &output_terms, &mut stream).unwrap();
        let mut read_stream = stream.as_slice();
        outputs_encrypted = Cipher2d::deserialize_terms(&context, &output_terms, &mut read_stream).unwrap();
        outputs_serialized_bytes
    };

    let output_decrypted = match args.ckks {
        false => MessageVector::U(helper.decrypt_outputs_bfv(encoder.as_bfv(), &decryptor, &outputs_encrypted)),
        true => MessageVector::F(helper.decrypt_outputs_ckks(encoder.as_ckks(), &decryptor, &outputs_encrypted)),
    };

    let correct = match output_decrypted {
        MessageVector::U(output_decrypted) => {
            let mut outputs_plain = vec![0; output_size];
            for b in 0..batch_size {
                for oc in 0..output_channels {
                    for i in 0..output_height {
                        for j in 0..output_width {
                            let mut sum = 0;
                            for ic in 0..input_channels {
                                for kh in 0..kernel_height {
                                    for kw in 0..kernel_width {
                                        let input_index = b * input_channels * image_height * image_width + ic * image_height * image_width + (i + kh) * image_width + (j + kw);
                                        let weight_index = oc * input_channels * kernel_height * kernel_width + ic * kernel_height * kernel_width + kh * kernel_width + kw;
                                        sum = plain_modulus.reduce(
                                            sum + plain_modulus.reduce_u128(
                                                (inputs.as_bfv()[input_index] as u128) * 
                                                (weights.as_bfv()[weight_index] as u128)
                                            )
                                        );
                                    }
                                }
                            }
                            let output_index = b * output_channels * output_height * output_width + oc * output_height * output_width + i * output_width + j;
                            outputs_plain[output_index] = plain_modulus.reduce(sum + biases.as_bfv()[output_index]);
                        }
                    }
                }
            }
            outputs_plain == output_decrypted
        }
        MessageVector::F(output_decrypted) => {
            let mut outputs_plain = vec![0.0; output_size];
            for b in 0..batch_size {
                for oc in 0..output_channels {
                    for i in 0..output_height {
                        for j in 0..output_width {
                            let mut sum = 0.0;
                            for ic in 0..input_channels {
                                for kh in 0..kernel_height {
                                    for kw in 0..kernel_width {
                                        let input_index = b * input_channels * image_height * image_width + ic * image_height * image_width + (i + kh) * image_width + (j + kw);
                                        let weight_index = oc * input_channels * kernel_height * kernel_width + ic * kernel_height * kernel_width + kh * kernel_width + kw;
                                        sum += inputs.as_ckks()[input_index] * weights.as_ckks()[weight_index];
                                    }
                                }
                            }
                            let output_index = b * output_channels * output_height * output_width + oc * output_height * output_width + i * output_width + j;
                            outputs_plain[output_index] = sum + biases.as_ckks()[output_index];
                        }
                    }
                }
            }
            let mut correct = true;
            for i in 0..outputs_plain.len() {
                correct = correct && (outputs_plain[i] - output_decrypted[i]).abs() < 1e-1;
            }
            correct
        }
    };

    print_communication("inputs", 1, inputs_serialized_bytes, 1);
    print_communication("outputs", 1, outputs_serialized_bytes, 1);

    if !correct {
        println!("Outputs are incorrect!");
    };
    
}