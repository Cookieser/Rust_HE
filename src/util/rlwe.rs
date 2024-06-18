pub mod sample {
    use crate::util::{self, he_standard_params};
    pub const NOISE_STANDARD_DEVIATION: f64 = he_standard_params::HE_HE_STANDARD_PARAMS_ERROR_STD_DEV;
    pub const NOISE_DISTRIBUTION_WITH_MULTIPLIER: f64 = 6.0;
    pub const NOISE_MAX_DEVIATION: f64 = NOISE_STANDARD_DEVIATION * NOISE_DISTRIBUTION_WITH_MULTIPLIER;

    use rand::{Rng, distributions::Uniform, prelude::Distribution};
    use crate::EncryptionParameters;

    #[derive(Clone, Copy)]
    struct ClippedNormal {
        normal: rand_distr::Normal<f64>,
        max_deviation: f64,
    }

    impl Distribution<f64> for ClippedNormal {
        fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> f64 {
            let mean = self.normal.mean();
            loop {
                let sample = self.normal.sample(rng);
                if (sample - mean).abs() <= self.max_deviation {
                    break sample;
                }
            }
        }
    }

    
    impl ClippedNormal {
        #[allow(unused)]
        fn new(mean: f64, standard_deviation: f64, max_deviation: f64) -> Self {
            assert!(max_deviation > 0.0, "[Invalid argument] Max deviation must be positive.");
            assert!(standard_deviation > 0.0, "[Invalid argument] Standard deviation must be positive.");
            Self {
                normal: rand_distr::Normal::new(mean, standard_deviation).unwrap(),
                max_deviation,
            }
        }
    }

    pub fn ternary<T: Rng>(rng: &mut T, parms: &EncryptionParameters, destination: &mut[u64]) {
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();

        let distribution = Uniform::new_inclusive(-1, 1);
        for i in 0..coeff_count {
            let sampled = rng.sample(distribution);
            for j in 0..coeff_modulus_size {
                destination[i + j * coeff_count] = match sampled {
                    -1 => coeff_modulus[j].value() - 1,
                    0 => 0,
                    1 => 1,
                    _ => unreachable!()
                };
            }
        }
    }

    /*
    pub fn normal(rng: Rc<RefCell<impl Rng>>, parms: &EncryptionParameters, destination: &mut[u64]) {
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();

        if util::are_close_f64(0.0, NOISE_MAX_DEVIATION) {
            util::set_zero_uint(destination); return;
        }

        let distribution = ClippedNormal::new(
            0.0, NOISE_STANDARD_DEVIATION, NOISE_MAX_DEVIATION
        );
        for i in 0..coeff_count {
            let sampled = rng.as_ref().borrow_mut().sample(distribution) as i64;
            for j in 0..coeff_modulus_size {
                destination[i + j * coeff_count] = 
                    if sampled > 0 {
                        sampled as u64
                    } else {
                        (coeff_modulus[j].value() as i64 + sampled) as u64
                    };
            }
        }
    }
    */

    pub fn centered_binomial<T: Rng>(rng: &mut T, parms: &EncryptionParameters, destination: &mut[u64]) {
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();

        if util::are_close_f64(0.0, NOISE_MAX_DEVIATION) {
            util::set_zero_uint(destination); return;
        }

        if !util::are_close_f64(3.2, NOISE_STANDARD_DEVIATION) {
            panic!("[Logic error] centered binomial distribution only supports standard deviation 3.2; use rounded Gaussian instead.");
        }

        let cbd = |rng: &mut T| {
            let mut x = [0; 6];
            rng.fill_bytes(&mut x);
            x[2] &= 0x1f; x[5] &= 0x1f;
            util::hamming_weight(x[0]) + util::hamming_weight(x[1]) + util::hamming_weight(x[2])
            - util::hamming_weight(x[3]) - util::hamming_weight(x[4]) - util::hamming_weight(x[5])
        };

        for i in 0..coeff_count {
            let sampled = cbd(rng);
            for j in 0..coeff_modulus_size {
                destination[i + j * coeff_count] = 
                    if sampled >= 0 {
                        sampled as u64
                    } else {
                        coeff_modulus[j].value() - sampled.unsigned_abs() as u64
                    };
            }
        }
    }

    pub fn uniform<T: Rng>(rng: &mut T, parms: &EncryptionParameters, destination: &mut[u64]) {
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();

        for j in 0..coeff_modulus_size {
            let modulus = coeff_modulus[j].value();
            let distribution = Uniform::new_inclusive(0, modulus - 1);
            for i in 0..coeff_count {
                destination[i + j * coeff_count] = rng.sample(distribution);
            }
        }
    }

}

pub mod encrypt_zero {

    use rand::{RngCore, SeedableRng};

    use crate::{
        PublicKey, 
        context::HeContext, 
        ParmsID, 
        Ciphertext,
        polymod, SchemeType, SecretKey, util::{random_generator::PRNGSeed, BlakeRNG},
    };
    use super::sample;

    pub fn asymmetric_with_u_prng(
        public_key: &PublicKey, context: &HeContext, 
        parms_id: &ParmsID, is_ntt_form: bool, 
        u_prng: &mut BlakeRNG,
        destination: &mut Ciphertext
    ) {

        let context_data = context.get_context_data(parms_id).unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let plain_modulus = parms.plain_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();
        let ntt_tables = context_data.small_ntt_tables();
        let encrypted_size = public_key.as_ciphertext().size();
        let scheme_type = parms.scheme();
        let public_key = public_key.as_ciphertext();

        // Make destination have right size and parms_id
        // Ciphertext (c_0,c_1, ...)
        destination.resize(context, parms_id, encrypted_size);
        destination.set_is_ntt_form(is_ntt_form);
        destination.set_scale(1.0);
        destination.set_correction_factor(1);

        // c[j] = public_key[j] * u + e[j] in BFV/CKKS = public_key[j] * u + p * e[j] in BGV
        // where e[j] <-- chi, u <-- R_3

        // Create a PRNG; u and the noise/error share the same PRNG
        let mut prng = context.create_random_generator();

        // Create u <-- Ring_3
        let mut u = vec![0; coeff_count * coeff_modulus_size];
        sample::ternary(u_prng, parms, &mut u);

        // c[j] = u * public_key[j]
        polymod::ntt_p(&mut u, coeff_count, ntt_tables);
        for j in 0..encrypted_size {
            polymod::dyadic_product_p(&u, public_key.poly(j), coeff_count, coeff_modulus, destination.poly_mut(j));
            if !is_ntt_form {
                polymod::intt_p(destination.poly_mut(j), coeff_count, ntt_tables); 
            }
        }

        // Create e[j] <-- chi
        // c[j] = public_key[j] * u + e[j] in BFV/CKKS, = public_key[j] * u + p * e[j] in BGV,
        for j in 0..encrypted_size {
            sample::centered_binomial(&mut prng, parms, &mut u); // Reuse u as e
            if is_ntt_form {
                polymod::ntt_p(&mut u, coeff_count, ntt_tables);
            }
            if scheme_type == SchemeType::BGV {
                polymod::multiply_scalar_inplace_p(
                    &mut u, plain_modulus.value(), coeff_count, coeff_modulus);
            }
            polymod::add_inplace_p(
                destination.poly_mut(j), &u, coeff_count, coeff_modulus);
        }

    }
    
    pub fn asymmetric(public_key: &PublicKey, context: &HeContext, parms_id: &ParmsID, is_ntt_form: bool, destination: &mut Ciphertext) {
        let mut prng = context.create_random_generator();
        asymmetric_with_u_prng(public_key, context, parms_id, is_ntt_form, &mut prng, destination);
    }

    pub fn symmetric_with_c1_prng(
        secret_key: &SecretKey, context: &HeContext,
        parms_id: &ParmsID, is_ntt_form: bool,
        c1_prng: &mut BlakeRNG,
        mut save_seed: bool, destination: &mut Ciphertext
    ) {
        
        let context_data = context.get_context_data(parms_id).unwrap();
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let plain_modulus = parms.plain_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let coeff_count = parms.poly_modulus_degree();
        let ntt_tables = context_data.small_ntt_tables();
        let encrypted_size = 2;
        let scheme_type = parms.scheme();
        let secret_key = secret_key.as_plaintext();

        // Make destination have right size and parms_id
        // Ciphertext (c_0,c_1, ...)
        destination.resize(context, parms_id, encrypted_size);
        destination.set_is_ntt_form(is_ntt_form);
        destination.set_scale(1.0);
        destination.set_correction_factor(1);

        // If a polynomial is too small to store UniformRandomGeneratorInfo,
        // it is best to just disable save_seed. Note that the size needed is
        // the size of UniformRandomGeneratorInfo plus one (uint64_t) because
        // of an indicator word that indicates a seeded ciphertext.
        let poly_u64_count = coeff_count * coeff_modulus_size;
        let prng_seed_byte_count = std::mem::size_of::<PRNGSeed>();
        let prng_seed_u64_count = (prng_seed_byte_count + 7) / 8;
        if poly_u64_count < prng_seed_u64_count + 1 {
            save_seed = false;
        }

        // Create an instance of a random number generator used for sampling the noise/error below.
        let mut bootstrap_prng = context.create_random_generator();

        // Random seed for sampling u, i.e. the second term of the ciphertext.
        let mut public_prng_seed: PRNGSeed = PRNGSeed::default();
        c1_prng.fill_bytes(public_prng_seed.as_mut());

        // Set up a new default PRNG for expanding u from the seed sampled above
        let mut ciphertext_prng = BlakeRNG::from_seed(public_prng_seed);

        // Generate ciphertext: (c[0], c[1]) = ([-(as+ e)]_q, a) in BFV/CKKS
        // Generate ciphertext: (c[0], c[1]) = ([-(as+pe)]_q, a) in BGV
        
        if is_ntt_form || !save_seed {
            // Directly sample NTT form
            sample::uniform(&mut ciphertext_prng, parms, destination.poly_mut(1));
        } else if save_seed {
            // Sample non-NTT form and store the seed
            sample::uniform(&mut ciphertext_prng, parms, destination.poly_mut(1));
            // Transform the c1 into NTT representation
            polymod::ntt_p(destination.poly_mut(1), coeff_count, ntt_tables);
        }
        
        // Sample e <-- chi
        let mut noise = vec![0; coeff_count * coeff_modulus_size];
        sample::centered_binomial(&mut bootstrap_prng, parms, &mut noise);

        // Calculate -(as+ e) (mod q) and store in c[0] in BFV/CKKS
        // Calculate -(as+pe) (mod q) and store in c[0] in BGV
        unsafe { // We need to access c0 as mutable but c1 as immutable
            let c0 = std::slice::from_raw_parts_mut(destination.poly_mut(0).as_mut_ptr(), coeff_count * coeff_modulus_size);
            let c1 = std::slice::from_raw_parts(destination.poly(1).as_ptr(), coeff_count * coeff_modulus_size);
            polymod::dyadic_product_p(secret_key.data(), c1, coeff_count, coeff_modulus, c0);
        }
        
        if is_ntt_form {
            // Transform the noise e into NTT representation
            polymod::ntt_p(&mut noise, coeff_count, ntt_tables);
        } else {
            polymod::intt_p(destination.poly_mut(0), coeff_count, ntt_tables);
        }
        if let SchemeType::BGV = scheme_type {
            polymod::multiply_scalar_inplace_p(&mut noise, plain_modulus.value(), coeff_count, coeff_modulus);
        }
        // c0 = as + noise
        polymod::add_inplace_p(destination.poly_mut(0), &noise, coeff_count, coeff_modulus);
        // (as + noise, a) -> (-(as + noise), a),
        polymod::negate_inplace_p(destination.poly_mut(0), coeff_count, coeff_modulus);

        if !is_ntt_form && !save_seed {
            // Transform the c1 into non-NTT representation
            polymod::intt_p(destination.poly_mut(1), coeff_count, ntt_tables);
        }

        if save_seed {
            // Set flag u64 to c1[0]
            destination.poly_component_mut(1, 0)[0] = crate::text::CIPHERTEXT_SEED_FLAG;
            // Save the seed after c1[0]
            unsafe {
                let seed_ptr = destination.poly_component_mut(1, 0).as_mut_ptr().offset(1) as *mut u8;
                let seed_slice = std::slice::from_raw_parts_mut(seed_ptr, prng_seed_byte_count);
                seed_slice.copy_from_slice(public_prng_seed.as_ref());
            }
        }

        
    }

    pub fn symmetric(
        secret_key: &SecretKey, context: &HeContext, 
        parms_id: &ParmsID, is_ntt_form: bool, 
        save_seed: bool, destination: &mut Ciphertext
    ) {

        let mut c1_prng = context.create_random_generator();
        symmetric_with_c1_prng(secret_key, context, parms_id, is_ntt_form, &mut c1_prng, save_seed, destination);
        
    }

}