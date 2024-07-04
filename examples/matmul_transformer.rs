use std::{sync::Arc, time::Duration};

use heathcliff::{
    app::matmul::{
        bolt_cc_cr::MatmulBoltCcCr, bolt_cc_dc::MatmulBoltCcDc, bolt_cp::MatmulBoltCp, cheetah::MatmulHelper as MatmulCheetah, Cipher2d, MatmulHelperObjective
    }, perf_utils::{
        print_communication, print_time, TimerOnce as Timer
    }, BatchEncoder, CoeffModulus, Decryptor, EncryptionParameters, Encryptor, Evaluator, ExpandSeed, GaloisKeys, HeContext, KeyGenerator, Modulus, RelinKeys, SchemeType, SerializableWithHeContext
};
use clap::Parser;
use rand::{Rng, RngCore, SeedableRng};

fn random_f64_vector(rng: &mut impl Rng, size: usize, range: f64) -> Vec<f64> {
    (0..size).map(|_| rng.gen_range(-range..range)).collect()
}

fn f64_matmul(m: usize, r: usize, n: usize, a: &[f64], b: &[f64]) -> Vec<f64> {
    assert_eq!(a.len(), m * r);
    assert_eq!(b.len(), r * n);
    let mut c = vec![0.0; m * n];
    for i in 0..m {
        for j in 0..n {
            for k in 0..r {
                c[i * n + j] += a[i * r + k] * b[k * n + j];
            }
        }
    }
    c
}

fn measure_time<T>(prompt: &str, f: impl FnOnce() -> T) -> T {
    let timer = Timer::new().tabs(2);
    let result = f();
    timer.finish(prompt);
    result
}

fn trouble<T>(he_context: &Arc<HeContext>, x: T) -> (T, usize) where T: SerializableWithHeContext {
    let mut stream = vec![];
    let bytes = x.serialize(he_context, &mut stream).unwrap();
    let mut read_stream = stream.as_slice();
    let y = T::deserialize(he_context, &mut read_stream).unwrap();
    (y, bytes)
}

#[derive(Parser)]
struct Arguments {

    #[arg(short='i', default_value="cheetah")]
    implementation: String,

    // transformer dimensions
    #[arg(short='D', default_value_t = 128)]
    d_model: usize,
    #[arg(short='H', default_value_t = 2)]
    heads: usize,
    #[arg(short='N', default_value_t = 64)]
    sequence_length: usize,
    #[arg(short='F', default_value_t = 4)]
    feedforward_expansion: usize,

    #[arg(short='p', default_value_t = 8192)]
    poly_modulus_degree: usize,
    #[arg(short='t', long, default_value_t = 37)]
    cp_log_t: usize,
    #[arg(short='q', long,  default_value="60,60,60")]
    cp_log_q: String,
    #[arg(short='s', long, default_value_t = 12)]
    cp_log_scale: usize,

    #[arg(long, default_value="same_as_cp")]
    cc_log_t: String,
    #[arg(long, default_value="60,60,49,60")]
    cc_log_q: String,
    #[arg(long, default_value="same_as_cp")]
    cc_log_scale: String,

    #[arg(short='P', long="no-pack-lwe", action=clap::ArgAction::SetTrue)]
    no_pack_lwe: bool,

    #[arg(short='S', default_value_t = 0)]
    seed: u64,
}

struct ContextSet {
    plain_modulus: Modulus,
    params: EncryptionParameters,
    context: Arc<HeContext>,
    encoder: BatchEncoder,
    // keygen: KeyGenerator,
    encryptor: Encryptor,
    decryptor: Decryptor,
    evaluator: Evaluator,
    automorphism_key: GaloisKeys,
    galois_key: GaloisKeys,
    relin_key: RelinKeys,
    log_scale: usize,

    automorphism_key_serialized_size: usize,
    galois_key_serialized_size: usize,
    relin_key_serialized_size: usize,
}

impl ContextSet {

    fn create(implementation: String, poly_degree: usize, log_t: usize, log_q: Vec<usize>, log_scale: usize) -> ContextSet {
        let (plain_modulus, params, context) = match implementation.as_str() {
            "cheetah" => {
                let plain_modulus = Modulus::new(1 << log_t);
                let params = EncryptionParameters::new(SchemeType::BFV)
                    .set_plain_modulus(&plain_modulus)
                    .set_coeff_modulus(&CoeffModulus::create(poly_degree, log_q))
                    .set_poly_modulus_degree(poly_degree);
                let context = HeContext::new(params.clone(), true, heathcliff::SecurityLevel::None);
                (plain_modulus, params, context)
            },
            "bolt" => {
                let mut total_bits = vec![log_t];
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

        let encoder = BatchEncoder::new(context.clone());
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
        let relin_key = keygen.create_relin_keys(true);
        let mut stream = vec![];
        let relin_key_serialized_bytes = relin_key.serialize(&context, &mut stream).unwrap();
        let mut read_stream = stream.as_slice();
        let relin_key = RelinKeys::deserialize(&context, &mut read_stream).unwrap();

        ContextSet {
            plain_modulus, params, context,
            encoder, encryptor, decryptor, evaluator,
            automorphism_key, galois_key, relin_key,
            automorphism_key_serialized_size: automorphism_key_serialized_bytes,
            galois_key_serialized_size: galois_key_serialized_bytes,
            relin_key_serialized_size: relin_key_serialized_bytes,
            log_scale
        }

    }

    pub fn to_ring(&self, vec: &[f64], override_log_scale: Option<usize>) -> Vec<u64> {
        let scale = override_log_scale.unwrap_or(self.log_scale);
        let scale = 2.0f64.powi(scale as i32);
        let modulus = self.plain_modulus.value();
        vec.iter().map(|&x| {
            if x >= 0.0 {
                let r = (x * scale) as u64; assert!(r < (modulus + 1) / 2);
                r
            } else { 
                let r = modulus - (-x * scale) as u64; assert!(r >= (modulus + 1) / 2);
                r
            }
        }).collect()
    }

    pub fn to_decimal(&self, vec: &[u64], override_log_scale: Option<usize>) -> Vec<f64> {
        let scale = override_log_scale.unwrap_or(self.log_scale);
        let scale = 2.0f64.powi(scale as i32);
        let modulus = self.plain_modulus.value();
        vec.iter().map(|&x| {
            let x = if x < (modulus + 1) / 2 {
                x as f64
            } else {
                (x as i64 - modulus as i64) as f64
            };
            x / scale
        }).collect()
    }

    pub fn plain_matmul(&self, m: usize, r: usize, n: usize, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), m * r);
        assert_eq!(b.len(), r * n);
        let mut c = vec![0; m * n];
        let modulus = self.plain_modulus.value();
        for i in 0..m {
            for j in 0..n {
                for k in 0..r {
                    let a = a[i * r + k];
                    let b = b[k * n + j];
                    c[i * n + j] += a * b % modulus;
                    c[i * n + j] %= modulus;
                }
            }
        }
        c
    }

    pub fn random_scaled_u64_vector(&self, rng: &mut impl RngCore, size: usize, override_log_scale: Option<usize>) -> (Vec<f64>, Vec<u64>) {
        let f = random_f64_vector(rng, size, 1.0);
        let r = self.to_ring(&f, override_log_scale);
        (f, r)
    }

    pub fn random_ring_vector(&self, rng: &mut impl RngCore, size: usize) -> Vec<u64> {
        (0..size).map(|_| rng.next_u64() % self.plain_modulus.value()).collect()
    }

    pub fn add_ring_vector(&self, a: &[u64], b: &[u64]) -> Vec<u64> {
        assert_eq!(a.len(), b.len());
        a.iter().zip(b.iter()).map(|(x, y)| (x + y) % self.plain_modulus.value()).collect()
    }

    pub fn neg_ring_vector(&self, a: &[u64]) -> Vec<u64> {
        a.iter().map(|&x| (self.plain_modulus.value() - x) % self.plain_modulus.value()).collect()
    }

    pub fn split_shares(&self, rng: &mut impl RngCore, a: &[u64]) -> (Vec<u64>, Vec<u64>) {
        let s = self.random_ring_vector(rng, a.len());
        let b = self.add_ring_vector(a, &s);
        (self.neg_ring_vector(&s), b)
    }

}

fn near_f64_vector(a: &[f64], b: &[f64]) -> f64 {
    assert_eq!(a.len(), b.len());
    // get max difference
    a.iter().zip(b.iter()).map(|(x, y)| (x - y).abs()).fold(0.0, f64::max)
}

fn cheetah_cp(rng: &mut impl Rng, helper: &MatmulCheetah, cp_context: &ContextSet, pack_lwe: bool) -> (Duration, usize) {
    let m = helper.batch_size; let r = helper.input_dims; let n = helper.output_dims;
    let (xf, x) = cp_context.random_scaled_u64_vector(rng, m * r, None);
    let (wf, w) = cp_context.random_scaled_u64_vector(rng, r * n, None);
    let s = cp_context.random_ring_vector(rng, m * n);
    let yf_truth = f64_matmul(m, r, n, &xf, &wf);
    let timer = Timer::new().tabs(1);
    println!("  Time");
    let xc = measure_time("x encode", || 
        helper.encode_inputs_bfv(&cp_context.encoder, &x));
    let xc = measure_time("x encrypt", ||
        xc.encrypt_symmetric(&cp_context.encryptor));
    let wc = measure_time("w encode", ||
        helper.encode_weights_bfv(&cp_context.encoder, &w));
    let sc = measure_time("s encode", ||
        helper.encode_outputs_bfv(&cp_context.encoder, &s));
    let (xc, xs) = measure_time("x trouble", || 
        trouble(&cp_context.context, xc));
    let mut yc = measure_time("matmul", ||
        helper.matmul(&cp_context.evaluator, &xc, &wc));
    if pack_lwe {
        yc = measure_time("y packlwe", ||
            helper.pack_outputs(&cp_context.evaluator, &cp_context.automorphism_key, &yc));
    }
    measure_time("add", ||
        yc.add_plain_inplace(&cp_context.evaluator, &sc));
    let (yc, ys) = measure_time("y trouble", || {
        if !pack_lwe {
            let output_terms = helper.output_terms();
            let mut stream = vec![];
            let outputs_serialized_bytes = yc.serialize_terms(&cp_context.context, &output_terms, &mut stream).unwrap();
            let mut read_stream = stream.as_slice();
            let yc = Cipher2d::deserialize_terms(&cp_context.context, &output_terms, &mut read_stream).unwrap();
            (yc, outputs_serialized_bytes)
        } else {
            let mut outputs_serialized = vec![];
            let outputs_serialized_bytes = yc.serialize(&cp_context.context, &mut outputs_serialized).unwrap();
            assert_eq!(outputs_serialized.len(), yc.serialized_size(&cp_context.context));
            let yc = Cipher2d::deserialize(&cp_context.context, &mut outputs_serialized.as_slice()).unwrap();
            (yc, outputs_serialized_bytes)
        }
    });
    let y = measure_time("y decode", ||
        helper.decrypt_outputs_bfv(&cp_context.encoder, &cp_context.decryptor, &yc));
    let time = timer.finish("Time total");
    let y = cp_context.add_ring_vector(&y, &cp_context.neg_ring_vector(&s));
    let yf = cp_context.to_decimal(&y, Some(cp_context.log_scale * 2));
    let diff = near_f64_vector(&yf, &yf_truth);
    println!("  Comm");
    print_communication("x size", 2, xs, 1);
    print_communication("y size", 2, ys, 1);
    print_communication("Comm total", 1, xs + ys, 1);
    println!("  Difference   : {:>9.6}", diff);
    (time, xs + ys)
}

fn cheetah_cc(rng: &mut impl Rng, helper: &MatmulCheetah, cp_context: &ContextSet, pack_lwe: bool) -> (Duration, usize) {
    let m = helper.batch_size; let r = helper.input_dims; let n = helper.output_dims;
    let (xf, x) = cp_context.random_scaled_u64_vector(rng, m * r, None);
    let (wf, w) = cp_context.random_scaled_u64_vector(rng, r * n, None);
    let (x0, x1) = cp_context.split_shares(rng, &x);
    let (w0, w1) = cp_context.split_shares(rng, &w);
    let s = cp_context.random_ring_vector(rng, m * n);
    let yf_truth = f64_matmul(m, r, n, &xf, &wf);
    let timer = Timer::new().tabs(1);
    println!("  Time");
    let x0c = measure_time("x0 encode", || 
        helper.encode_inputs_bfv(&cp_context.encoder, &x0));
        let x1c = measure_time("x1 encode", || 
            helper.encode_inputs_bfv(&cp_context.encoder, &x1));
    let x1c = measure_time("x1 encrypt", ||
        x1c.encrypt_symmetric(&cp_context.encryptor));
    let w0c = measure_time("w0 encode", ||
        helper.encode_weights_bfv(&cp_context.encoder, &w0));
        let w1c = measure_time("w1 encode", ||
            helper.encode_weights_bfv(&cp_context.encoder, &w1));
    let w1c = measure_time("w1 encrypt", ||
        w1c.encrypt_symmetric(&cp_context.encryptor));
    let sc = measure_time("s encode", ||
        helper.encode_outputs_bfv(&cp_context.encoder, &s));
    let (x1c, x1s) = measure_time("x1 trouble", || 
        trouble(&cp_context.context, x1c));
    let (w1c, w1s) = measure_time("w1 trouble", ||
        trouble(&cp_context.context, w1c));
    let mut yc = measure_time("matmul", || {
        let x1w0 = helper.matmul(&cp_context.evaluator, &x1c, &w0c);
        let x0w1 = helper.matmul_reverse(&cp_context.evaluator, &x0c, &w1c);
        let mut yc = x1w0; yc.add_inplace(&cp_context.evaluator, &x0w1);
        yc
    });
    if pack_lwe {
        yc = measure_time("y packlwe", ||
            helper.pack_outputs(&cp_context.evaluator, &cp_context.automorphism_key, &yc));
    }
    measure_time("add", ||
        yc.add_plain_inplace(&cp_context.evaluator, &sc));
    let (yc, ys) = measure_time("y trouble", || {
        if !pack_lwe {
            let output_terms = helper.output_terms();
            let mut stream = vec![];
            let outputs_serialized_bytes = yc.serialize_terms(&cp_context.context, &output_terms, &mut stream).unwrap();
            let mut read_stream = stream.as_slice();
            let yc = Cipher2d::deserialize_terms(&cp_context.context, &output_terms, &mut read_stream).unwrap();
            (yc, outputs_serialized_bytes)
        } else {
            let mut outputs_serialized = vec![];
            let outputs_serialized_bytes = yc.serialize(&cp_context.context, &mut outputs_serialized).unwrap();
            assert_eq!(outputs_serialized.len(), yc.serialized_size(&cp_context.context));
            let yc = Cipher2d::deserialize(&cp_context.context, &mut outputs_serialized.as_slice()).unwrap();
            (yc, outputs_serialized_bytes)
        }
    });
    let y = measure_time("y decode", ||
        helper.decrypt_outputs_bfv(&cp_context.encoder, &cp_context.decryptor, &yc));
    let time = timer.finish("Time total");
    let y = cp_context.add_ring_vector(&y, &cp_context.neg_ring_vector(&s));
    let y = cp_context.add_ring_vector(&y, &cp_context.plain_matmul(m, r, n, &x0, &w0));
    let y = cp_context.add_ring_vector(&y, &cp_context.plain_matmul(m, r, n, &x1, &w1));
    let yf = cp_context.to_decimal(&y, Some(cp_context.log_scale * 2));
    let diff = near_f64_vector(&yf, &yf_truth);
    println!("  Comm");
    print_communication("x1 size", 2, x1s, 1);
    print_communication("w1 size", 2, w1s, 1);
    print_communication("y size", 2, ys, 1);
    let comm_total = x1s + w1s + ys;
    print_communication("Comm total", 1, comm_total, 1);
    println!("  Difference   : {:>9.6}", diff);
    (time, comm_total)
}

fn run_cheetah(args: &Arguments, cp_context: &ContextSet) {
    
    let d_model = args.d_model;
    let heads = args.heads;
    let sequence_length = args.sequence_length;
    let poly_degree = cp_context.params.poly_modulus_degree();
    let pack_lwe = !args.no_pack_lwe;
    let d_ff = d_model * args.feedforward_expansion;

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(args.seed);

    println!("\n[In projection]");
    let helper = MatmulCheetah::new(
        sequence_length, d_model, 3 * d_model, 
        poly_degree, MatmulHelperObjective::CipherPlain, pack_lwe
    );
    let (time0, comm0) = cheetah_cp(&mut rng, &helper, cp_context, pack_lwe);

    println!("\n[Q * K^T for one head]");
    let head_dims = d_model / heads;
    let helper = MatmulCheetah::new(
        sequence_length, head_dims, sequence_length,
        poly_degree, MatmulHelperObjective::CpAddPc, pack_lwe
    );
    let (time1, comm1) = cheetah_cc(&mut rng, &helper, cp_context, pack_lwe);

    println!("\n[Softmax * V for one head]");
    let helper = MatmulCheetah::new(
        sequence_length, sequence_length, head_dims,
        poly_degree, MatmulHelperObjective::CpAddPc, pack_lwe
    );
    let (time2, comm2) = cheetah_cc(&mut rng, &helper, cp_context, pack_lwe);

    println!("\n[Out projection]");
    let helper = MatmulCheetah::new(
        sequence_length, d_model, d_model,
        poly_degree, MatmulHelperObjective::CipherPlain, pack_lwe
    );
    let (time3, comm3) = cheetah_cp(&mut rng, &helper, cp_context, pack_lwe);

    println!("\n[Feedforward 1]");
    let helper = MatmulCheetah::new(
        sequence_length, d_model, d_ff,
        poly_degree, MatmulHelperObjective::CipherPlain, pack_lwe
    );
    let (time4, comm4) = cheetah_cp(&mut rng, &helper, cp_context, pack_lwe);

    println!("\n[Feedforward 2]");
    let helper = MatmulCheetah::new(
        sequence_length, d_ff, d_model,
        poly_degree, MatmulHelperObjective::CipherPlain, pack_lwe
    );
    let (time5, comm5) = cheetah_cp(&mut rng, &helper, cp_context, pack_lwe);

    let total_time = time0 + (time1 + time2) * (heads as u32) + time3 + time4 + time5;
    let total_comm = comm0 + (comm1 + comm2) * heads + comm3 + comm4 + comm5;
    println!("\n[Estimated total]");
    print_time("Time", 1, total_time, 1);
    print_communication("Comm", 1, total_comm, 1);

    println!("\n[Setup costs]");
    if !args.no_pack_lwe {
        print_communication("auto key", 1, cp_context.automorphism_key_serialized_size, 1);
    }

}

fn bolt_inproj(rng: &mut impl Rng, helper: &MatmulBoltCp, cp_context: &ContextSet) -> (Duration, usize) {
    let m = helper.m; let r = helper.r; let n = helper.n;
    let (xf, x) = cp_context.random_scaled_u64_vector(rng, m * r, None);
    let (wf, w) = cp_context.random_scaled_u64_vector(rng, r * n, None);
    let yf_truth = f64_matmul(m, r, n, &xf, &wf);
    let timer = Timer::new().tabs(1);
    println!("  Time");
    let xc = measure_time("x encode", || 
        helper.encode_inputs(&cp_context.encoder, &x));
    let xc = measure_time("x encrypt", ||
        xc.encrypt_symmetric(&cp_context.encryptor));
    let wc = measure_time("w encode", ||
        helper.encode_weights(&cp_context.encoder, &w));
    let (xc, xs) = measure_time("x trouble", || 
        trouble(&cp_context.context, xc));
    let yc = measure_time("matmul", ||
        helper.multiply(&cp_context.evaluator, &cp_context.galois_key, &xc, &wc));
    let time = timer.finish("Time total");
    let y = helper.decode_outputs(&cp_context.encoder, &yc.decrypt(&cp_context.decryptor));
    let yf = cp_context.to_decimal(&y, Some(cp_context.log_scale * 2));
    let diff = near_f64_vector(&yf, &yf_truth);
    println!("  Comm");
    print_communication("x size", 2, xs, 1);
    println!("  Difference   : {:>9.6}", diff);
    (time, xs)
}


fn bolt_qkt(rng: &mut impl Rng, helper: &MatmulBoltCcCr, cc_context: &ContextSet) -> (Duration, usize) {
    let m = helper.m; let r = helper.r; let n = helper.n;
    let (xf, x) = cc_context.random_scaled_u64_vector(rng, m * r, None);
    let (wf, w) = cc_context.random_scaled_u64_vector(rng, r * n, None);
    let s = cc_context.random_ring_vector(rng, m * n);
    let yf_truth = f64_matmul(m, r, n, &xf, &wf);
    let timer = Timer::new().tabs(1);
    // these are already done in the in_projection step
    let xc = helper.encode_inputs(&cc_context.encoder, &x);
    let xc = xc.encrypt_symmetric(&cc_context.encryptor).expand_seed(&cc_context.context);
    let wc = helper.encode_weights(&cc_context.encoder, &w);
    let wc = wc.encrypt_symmetric(&cc_context.encryptor).expand_seed(&cc_context.context);
    println!("  Time");
    let sc = measure_time("s encode", ||
        helper.encode_outputs(&cc_context.encoder, &s));
    let mut yc = measure_time("matmul", ||
        helper.multiply(
            &cc_context.encoder, &cc_context.evaluator, 
            &cc_context.galois_key, &cc_context.relin_key,
            &xc, &wc
        )
    );
    measure_time("add", ||
        yc.add_plain_inplace(&cc_context.evaluator, &sc));
    let (yc, ys) = measure_time("y trouble", || {
        let mut outputs_serialized = vec![];
        let outputs_serialized_bytes = yc.serialize(&cc_context.context, &mut outputs_serialized).unwrap();
        assert_eq!(outputs_serialized.len(), yc.serialized_size(&cc_context.context));
        let yc = Cipher2d::deserialize(&cc_context.context, &mut outputs_serialized.as_slice()).unwrap();
        (yc, outputs_serialized_bytes)
    });
    let y = measure_time("y decode", || {
        let decrypted = yc.decrypt(&cc_context.decryptor);
        helper.decode_outputs(&cc_context.encoder, &decrypted)
    });
    let time = timer.finish("Time total");
    let y = cc_context.add_ring_vector(&y, &cc_context.neg_ring_vector(&s));
    let yf = cc_context.to_decimal(&y, Some(cc_context.log_scale * 2));
    let diff = near_f64_vector(&yf, &yf_truth);
    println!("  Comm");
    print_communication("y size", 2, ys, 1);
    println!("  Difference   : {:>9.6}", diff);
    (time, ys)
}


fn bolt_sv(rng: &mut impl Rng, helper: &MatmulBoltCcDc, cc_context: &ContextSet) -> (Duration, usize) {
    let m = helper.m; let r = helper.r; let n = helper.n;
    let (xf, x) = cc_context.random_scaled_u64_vector(rng, m * r, None);
    let (wf, w) = cc_context.random_scaled_u64_vector(rng, r * n, None);
    let yf_truth = f64_matmul(m, r, n, &xf, &wf);
    let timer = Timer::new().tabs(1);
    // these are already done in the in_projection step
    let wc = helper.encode_weights(&cc_context.encoder, &w);
    let wc = wc.encrypt_symmetric(&cc_context.encryptor).expand_seed(&cc_context.context);
    println!("  Time");
    let xc = measure_time("x encode", || 
        helper.encode_inputs(&cc_context.encoder, &x));
    let xc = measure_time("x encrypt", ||
        xc.encrypt_symmetric(&cc_context.encryptor));
    let (xc, xs) = measure_time("x trouble", || 
        trouble(&cc_context.context, xc));
    let yc = measure_time("matmul", ||
        helper.multiply(
            &cc_context.encoder, &cc_context.evaluator, 
            &cc_context.galois_key, &cc_context.relin_key, 
            &xc, &wc
        )
    );
    let time = timer.finish("Time total");
    let y = helper.decode_outputs(&cc_context.encoder, &yc.decrypt(&cc_context.decryptor));
    let yf = cc_context.to_decimal(&y, Some(cc_context.log_scale * 2));
    let diff = near_f64_vector(&yf, &yf_truth);
    println!("  Comm");
    print_communication("x size", 2, xs, 1);
    println!("  Difference   : {:>9.6}", diff);
    (time, xs)
}

fn bolt_outproj(rng: &mut impl Rng, helper: &MatmulBoltCp, cp_context: &ContextSet) -> (Duration, usize) {
    let m = helper.m; let r = helper.r; let n = helper.n;
    let (xf, x) = cp_context.random_scaled_u64_vector(rng, m * r, None);
    let (wf, w) = cp_context.random_scaled_u64_vector(rng, r * n, None);
    let s = cp_context.random_ring_vector(rng, m * n);
    let yf_truth = f64_matmul(m, r, n, &xf, &wf);
    let timer = Timer::new().tabs(1);
    // these are already done in the sv step
    let xc = helper.encode_inputs(&cp_context.encoder, &x);
    let xc = xc.encrypt_symmetric(&cp_context.encryptor).expand_seed(&cp_context.context);
    println!("  Time");
    let wc = measure_time("w encode", ||
        helper.encode_weights(&cp_context.encoder, &w));
    let sc = measure_time("s encode", ||
        helper.encode_outputs(&cp_context.encoder, &s));
    let mut yc = measure_time("matmul", ||
        helper.multiply(&cp_context.evaluator, &cp_context.galois_key, &xc, &wc));
    measure_time("add", ||
        yc.add_plain_inplace(&cp_context.evaluator, &sc));
    let (yc, ys) = measure_time("y trouble", || {
        let mut outputs_serialized = vec![];
        let outputs_serialized_bytes = yc.serialize(&cp_context.context, &mut outputs_serialized).unwrap();
        assert_eq!(outputs_serialized.len(), yc.serialized_size(&cp_context.context));
        let yc = Cipher2d::deserialize(&cp_context.context, &mut outputs_serialized.as_slice()).unwrap();
        (yc, outputs_serialized_bytes)
    });
    let y = measure_time("y decode", || {
        let decrypted = yc.decrypt(&cp_context.decryptor);
        helper.decode_outputs(&cp_context.encoder, &decrypted)
    });
    let time = timer.finish("Time total");
    let y = cp_context.add_ring_vector(&y, &cp_context.neg_ring_vector(&s));
    let yf = cp_context.to_decimal(&y, Some(cp_context.log_scale * 2));
    let diff = near_f64_vector(&yf, &yf_truth);
    println!("  Comm");
    print_communication("y size", 2, ys, 1);
    println!("  Difference   : {:>9.6}", diff);
    (time, ys)
}


fn bolt_cp(rng: &mut impl Rng, helper: &MatmulBoltCp, cp_context: &ContextSet) -> (Duration, usize) {
    let m = helper.m; let r = helper.r; let n = helper.n;
    let (xf, x) = cp_context.random_scaled_u64_vector(rng, m * r, None);
    let (wf, w) = cp_context.random_scaled_u64_vector(rng, r * n, None);
    let s = cp_context.random_ring_vector(rng, m * n);
    let yf_truth = f64_matmul(m, r, n, &xf, &wf);
    let timer = Timer::new().tabs(1);
    println!("  Time");
    let xc = measure_time("x encode", || 
        helper.encode_inputs(&cp_context.encoder, &x));
    let xc = measure_time("x encrypt", ||
        xc.encrypt_symmetric(&cp_context.encryptor));
    let wc = measure_time("w encode", ||
        helper.encode_weights(&cp_context.encoder, &w));
    let sc = measure_time("s encode", ||
        helper.encode_outputs(&cp_context.encoder, &s));
    let (xc, xs) = measure_time("x trouble", || 
        trouble(&cp_context.context, xc));
    let mut yc = measure_time("matmul", ||
        helper.multiply(&cp_context.evaluator, &cp_context.galois_key, &xc, &wc));
    measure_time("add", ||
        yc.add_plain_inplace(&cp_context.evaluator, &sc));
    let (yc, ys) = measure_time("y trouble", || {
        let mut outputs_serialized = vec![];
        let outputs_serialized_bytes = yc.serialize(&cp_context.context, &mut outputs_serialized).unwrap();
        assert_eq!(outputs_serialized.len(), yc.serialized_size(&cp_context.context));
        let yc = Cipher2d::deserialize(&cp_context.context, &mut outputs_serialized.as_slice()).unwrap();
        (yc, outputs_serialized_bytes)
    });
    let y = measure_time("y decode", || {
        let decrypted = yc.decrypt(&cp_context.decryptor);
        helper.decode_outputs(&cp_context.encoder, &decrypted)
    });
    let time = timer.finish("Time total");
    let y = cp_context.add_ring_vector(&y, &cp_context.neg_ring_vector(&s));
    let yf = cp_context.to_decimal(&y, Some(cp_context.log_scale * 2));
    let diff = near_f64_vector(&yf, &yf_truth);
    println!("  Comm");
    print_communication("x size", 2, xs, 1);
    print_communication("y size", 2, ys, 1);
    print_communication("Comm total", 1, xs + ys, 1);
    println!("  Difference   : {:>9.6}", diff);
    (time, xs + ys)
}

fn run_bolt(args: &Arguments, cp_context: &ContextSet, cc_context: &ContextSet) {
    
    let d_model = args.d_model;
    let heads = args.heads;
    let sequence_length = args.sequence_length;
    let poly_degree = cp_context.params.poly_modulus_degree();
    let d_ff = d_model * args.feedforward_expansion;

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(args.seed);

    println!("\n[In projection for one head of Q]");
    let head_dims = d_model / heads;
    let helper = MatmulBoltCp::new(sequence_length, d_model, head_dims, poly_degree);
    let (time0, comm0) = bolt_inproj(&mut rng, &helper, cp_context);

    println!("\n[Q * K^T for one head]");
    let helper = MatmulBoltCcCr::new(sequence_length, head_dims, sequence_length, poly_degree);
    let (time1, comm1) = bolt_qkt(&mut rng, &helper, cc_context);

    println!("\n[Softmax * V for one head]");
    let helper = MatmulBoltCcDc::new(sequence_length, sequence_length, head_dims, poly_degree);
    let (time2, comm2) = bolt_sv(&mut rng, &helper, cc_context);

    println!("\n[Out projection from one head]");
    let helper = MatmulBoltCp::new(sequence_length, head_dims, d_model, poly_degree);
    let (time3, comm3) = bolt_outproj(&mut rng, &helper, cp_context);

    println!("\n[Feedforward 1]");
    let helper = MatmulBoltCp::new(sequence_length, d_model, d_ff, poly_degree);
    let (time4, comm4) = bolt_cp(&mut rng, &helper, cp_context);

    println!("\n[Feedforward 2]");
    let helper = MatmulBoltCp::new(sequence_length, d_ff, d_model, poly_degree);
    let (time5, comm5) = bolt_cp(&mut rng, &helper, cp_context);

    let total_time = time0 * ((heads * 3) as u32) + (time1 + time2) * (heads as u32) + time3 * (heads as u32) + time4 + time5;
    let total_comm = comm0 * heads * 3 + (comm1 + comm2) * heads + comm3 * heads + comm4 + comm5;
    println!("\n[Estimated total]");
    print_time("Time", 1, total_time, 1);
    print_communication("Comm", 1, total_comm, 1);

    println!("\n[Setup costs]");
    let total = cc_context.galois_key_serialized_size + cc_context.relin_key_serialized_size + cp_context.galois_key_serialized_size;
    print_communication("cc gal key", 1, cc_context.galois_key_serialized_size, 1);
    print_communication("cc rel key", 1, cc_context.relin_key_serialized_size, 1);
    print_communication("cp gal key", 1, cp_context.galois_key_serialized_size, 1);
    print_communication("Total", 1, total, 1);

}

fn main() {
    
    // process arguments

    let mut args = Arguments::parse();
    assert!(args.d_model % args.heads == 0);
    if args.seed == 0 {
        let mut rng = rand::thread_rng();
        args.seed = rng.next_u64();
    }
    if args.implementation != "cheetah" && args.implementation != "bolt" {
        panic!("Invalid implementation. Must be 'cheetah' or 'bolt'.");
    }
    
    let cp_log_q = args.cp_log_q.split(',').map(|x| x.parse::<usize>().unwrap()).collect::<Vec<usize>>();
    let cp_log_t = args.cp_log_t;
    let cp_log_scale = args.cp_log_scale;
    
    let cc_log_q = if args.cc_log_q == "same_as_cp" {
        cp_log_q.clone()
    } else {
        args.cc_log_q.split(',').map(|x| x.parse::<usize>().unwrap()).collect::<Vec<usize>>()
    };
    let cc_log_t = if args.cc_log_t == "same_as_cp" {
        cp_log_t
    } else {
        args.cc_log_t.parse::<usize>().unwrap()
    };
    let cc_log_scale = if args.cc_log_scale == "same_as_cp" {
        cp_log_scale
    } else {
        args.cc_log_scale.parse::<usize>().unwrap()
    };

    // create he contexts
    let cp_context = ContextSet::create(args.implementation.clone(), 
        args.poly_modulus_degree, cp_log_t, cp_log_q, cp_log_scale);
    let cc_context = ContextSet::create(args.implementation.clone(), 
        args.poly_modulus_degree, cc_log_t, cc_log_q, cc_log_scale);

    // run
    if args.implementation == "cheetah" {
        run_cheetah(&args, &cp_context);
    } else {
        run_bolt(&args, &cp_context, &cc_context);
    }

}