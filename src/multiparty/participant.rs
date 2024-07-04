use std::{sync::Arc, io::{Write, Read}};
use std::rc::Rc;
use std::cell::RefCell;
use crate::{
    util::{BlakeRNG, NTTTables}, polymod, 
    SecretKey, HeContext, KeyGenerator, PublicKey, 
    ParmsID, PolynomialSerializer, PARMS_ID_ZERO, 
    RelinKeys, Ciphertext, KSwitchKeys, 
    EncryptionParameters, Plaintext, 
    ExpandSeed, ValCheck, Evaluator,
};

pub struct Participant {
    common_rng: Rc<RefCell<BlakeRNG>>,
    context: Arc<HeContext>,
    key_generator: KeyGenerator,
    evaluator: Evaluator,
    pub participant_count: usize,
    pub participant_id: usize,
}

pub struct PolynomialRevelationProtocol<'a> {
    parms_id: ParmsID,
    participant: &'a Participant,
    broadcasted: Vec<Option<Vec<u64>>>,
    result: Vec<u64>,
}

pub struct PublicKeyGenerationProtocol<'a> {
    p1_reveal: PolynomialRevelationProtocol<'a>,
    result: PublicKey,
}

pub struct SecretKeyRevelationProtocol<'a> {
    s_reveal: PolynomialRevelationProtocol<'a>,
}

pub struct RelinKeysGenerationProtocol<'a> {
    participant: &'a Participant,
    u: Vec<Vec<u64>>,
    h1: Vec<Vec<u64>>,
    h0_disclosure: Vec<PolynomialRevelationProtocol<'a>>,
    h1_disclosure: Vec<PolynomialRevelationProtocol<'a>>,
}

pub struct KeySwitchProtocol<'a> {
    participant: &'a Participant,
    cipher: Ciphertext,
    h_reveal: PolynomialRevelationProtocol<'a>,
}

pub struct DecryptionProtocol<'a> {
    participant: &'a Participant,
    cipher: Ciphertext,
    h_reveal: PolynomialRevelationProtocol<'a>,
}

pub struct PublicKeySwitchProtocol<'a> {
    participant: &'a Participant,
    cipher: Ciphertext,
    h0_reveal: PolynomialRevelationProtocol<'a>,
    h1_reveal: PolynomialRevelationProtocol<'a>,
}

pub trait ShareEncoder {
    type Share;
    fn encode(&self, share: &Self::Share) -> Plaintext;
    fn decode(&self, plaintext: &Plaintext) -> Self::Share;
}

pub trait ShareSampler {
    type Share;
    fn sample(&self, prng: &mut BlakeRNG) -> Self::Share;
}

pub struct CipherToSharesProtocol<'a, Share> {
    participant: &'a Participant,
    cipher: Option<Ciphertext>,
    share: Option<Share>,
    h_reveal: PolynomialRevelationProtocol<'a>,
}
pub struct ElementWiseVectorProductProtocol<'a>{
    public_key: PublicKeyGenerationProtocol<'a>,
    //relin_key: RelinKeysGenerationProtocol<'a>,
    //pubKeySwitch: PublicKeySwitchProtocol<'a>,
}

fn sample_noise(prng: &mut BlakeRNG, poly_degree: usize, parms: &EncryptionParameters, ntt_tables: &[NTTTables], is_ntt_form: bool, output: &mut [u64]) {
    use crate::util::rlwe;
    use crate::SchemeType;
    let coeff_count = poly_degree;
    rlwe::sample::centered_binomial(prng, parms, output);
    let scheme_type = parms.scheme();
    match scheme_type {
        SchemeType::BGV => {
            if is_ntt_form {
                polymod::ntt_p(output, coeff_count, ntt_tables);
            }
            polymod::multiply_scalar_inplace_p(
                output, parms.plain_modulus().value(), coeff_count, parms.coeff_modulus());
        }
        _ => {
            if is_ntt_form {
                polymod::ntt_p(output, coeff_count, ntt_tables);
            }
        }
    }
}

fn decrypt_polynomial(context: &Arc<HeContext>, polynomial: &[u64], reference_ciphertext: &Ciphertext, parms_id: &ParmsID) -> Plaintext {
    let context_data = context.get_context_data(parms_id).unwrap();
    let parms = context_data.parms();
    let scheme = parms.scheme();
    let poly_degree = parms.poly_modulus_degree();
    let moduli = parms.coeff_modulus();
    let target = polynomial;

    use crate::SchemeType;
    use crate::util;
    let mut destination = Plaintext::new();
    match scheme {
        SchemeType::BFV => {
            destination.set_parms_id(PARMS_ID_ZERO);
            destination.resize(poly_degree);
            context_data.rns_tool()
                .decrypt_scale_and_round(target, destination.data_mut());
            let plain_coeff_count = util::get_significant_uint64_count_uint(destination.data());
            destination.resize(plain_coeff_count.max(1));
        },
        SchemeType::CKKS => {
            destination.set_parms_id(PARMS_ID_ZERO);
            destination.resize(moduli.len() * poly_degree);
            destination.data_mut().copy_from_slice(target);
            destination.set_parms_id(*reference_ciphertext.parms_id());
            destination.set_scale(reference_ciphertext.scale());
        },
        SchemeType::BGV => {
            destination.set_parms_id(PARMS_ID_ZERO);
            destination.resize(poly_degree);
            context_data.rns_tool()
                .decrypt_scale_and_round(target, destination.data_mut());
            let plain_modulus = context_data.parms().plain_modulus();
            if reference_ciphertext.correction_factor() != 1 {
                let mut fix = 1;
                if !util::try_invert_u64_mod(reference_ciphertext.correction_factor(), plain_modulus, &mut fix) {
                    panic!("[Logic error] Correction factor is not invertible.");
                }
                polymod::multiply_scalar_inplace(destination.data_mut(), fix, plain_modulus);
            }
            let plain_coeff_count = util::get_significant_uint64_count_uint(destination.data());
            destination.resize(plain_coeff_count.max(1));
        },
        _ => {
            panic!("Scheme not supported");
        }
    }
    destination
}

impl Participant {

    pub fn context(&self) -> &Arc<HeContext> {
        &self.context
    }

    pub fn borrow_common_rng(&self) -> std::cell::RefMut<BlakeRNG> {
        self.common_rng.borrow_mut()
    }

    pub fn secret_key(&self) -> &SecretKey {
        self.key_generator.secret_key()
    }

    pub fn update_secret_key(&mut self, new_secret_key: &SecretKey) {
        let new_generator = KeyGenerator::from_sk(self.context.clone(), new_secret_key.clone());
        self.key_generator = new_generator;
    }

    pub fn new(participant_count: usize, participant_id: usize, context: Arc<HeContext>, common_rng: BlakeRNG) -> Self {
        let key_gen = KeyGenerator::new(context.clone());
        // let encryptor = Encryptor::new(context.clone()).set_secret_key(key_gen.secret_key().clone());
        Self {
            common_rng: Rc::new(RefCell::new(common_rng)),
            // evaluator: Evaluator::new(context.clone()),
            evaluator: Evaluator::new(context.clone()),
            context,
            key_generator: key_gen,
            // encryptor,
            participant_count,
            participant_id,
        }
    }

    pub fn generate_public_key(&mut self) -> PublicKeyGenerationProtocol {
        let p0p1 = self.key_generator.create_public_key_with_u_prng(false, &mut self.borrow_common_rng());
        let broadcasted = vec![None; self.participant_count];
        PublicKeyGenerationProtocol {
            p1_reveal: PolynomialRevelationProtocol { 
                parms_id: *(p0p1.parms_id()), 
                participant: self, 
                broadcasted, 
                result: p0p1.as_ciphertext().poly(0).to_vec(),
            },
            result: p0p1,
        }
    }

    pub fn reveal_secret_key(&self) -> SecretKeyRevelationProtocol {
        let s = self.key_generator.secret_key().as_plaintext();
        let broadcasted = vec![None; self.participant_count];
        SecretKeyRevelationProtocol {
            s_reveal: PolynomialRevelationProtocol {
                participant: self, 
                broadcasted, 
                result: s.data().to_vec(),
                parms_id: *s.parms_id(),
            },
        }
    }

    pub fn generate_relin_keys(&mut self) -> RelinKeysGenerationProtocol {
        RelinKeysGenerationProtocol::new(self)
    }

    pub fn key_switch(&self, cipher: &Ciphertext, new_secret_key: &SecretKey) -> KeySwitchProtocol {

        assert_eq!(cipher.size(), 2, "For keyswitching, the ciphertext size must be 2 polynomials.");

        let cipher_context_data = self.context().get_context_data(cipher.parms_id()).unwrap();
        let key_context_data = self.context().key_context_data().unwrap();
        let key_parms = key_context_data.parms();
        let poly_degree = key_parms.poly_modulus_degree();
        let is_ntt_form = cipher.is_ntt_form();
        let cipher_parms = cipher_context_data.parms();
        let cipher_moduli = cipher_parms.coeff_modulus();
        
        // hi = (si - s'i) * c1 + e
        let mut hi = self.secret_key().as_plaintext().data()[..poly_degree * cipher_moduli.len()].to_vec();
        let s_prime = new_secret_key.data();
        polymod::sub_inplace_p(&mut hi, s_prime, poly_degree, cipher_moduli); // no need to do on key_moduli.

        let mut tmp = cipher.poly(1).to_vec();

        if !is_ntt_form {
            polymod::ntt_p(&mut tmp, poly_degree, cipher_context_data.small_ntt_tables());
        }
        polymod::dyadic_product_inplace_p(&mut hi, &tmp, poly_degree, cipher_moduli);
        let mut rng = self.context().create_random_generator();
        sample_noise(&mut rng, poly_degree, cipher_parms, cipher_context_data.small_ntt_tables(), true, &mut tmp);
        polymod::add_inplace_p(&mut hi, &tmp, poly_degree, cipher_moduli);
        if !is_ntt_form {
            polymod::intt_p(&mut hi, poly_degree, cipher_context_data.small_ntt_tables());
        }

        KeySwitchProtocol {
            participant: self,
            cipher: cipher.clone(),
            h_reveal: PolynomialRevelationProtocol {
                participant: self,
                broadcasted: vec![None; self.participant_count],
                result: hi,
                parms_id: *cipher.parms_id(),
            },
        }

    }
    
    pub fn decrypt(&self, cipher: &Ciphertext) -> DecryptionProtocol {

        if cipher.contains_seed() {
            panic!("[Invalid argument] Seed should be expanded first.");
        }
        if !cipher.is_valid_for(self.context()) {
            panic!("[Invalid argument] Ciphertext is not valid for encryption parameters.");
        }
        if cipher.size() < crate::util::HE_CIPHERTEXT_SIZE_MIN {
            panic!("[Invalid argument] Ciphertext is empty.");
        }

        assert_eq!(cipher.size(), 2, "For keyswitching, the ciphertext size must be 2 polynomials.");

        let cipher_context_data = self.context().get_context_data(cipher.parms_id()).unwrap();
        let key_context_data = self.context().key_context_data().unwrap();
        let key_parms = key_context_data.parms();
        let poly_degree = key_parms.poly_modulus_degree();
        let is_ntt_form = cipher.is_ntt_form();
        let cipher_parms = cipher_context_data.parms();
        let cipher_moduli = cipher_parms.coeff_modulus();
        
        // hi = (si - s'i) * c1 + e
        let mut hi = self.secret_key().as_plaintext().data()[..poly_degree * cipher_moduli.len()].to_vec();

        let mut tmp = cipher.poly(1).to_vec();

        if !is_ntt_form {
            polymod::ntt_p(&mut tmp, poly_degree, cipher_context_data.small_ntt_tables());
        }
        polymod::dyadic_product_inplace_p(&mut hi, &tmp, poly_degree, cipher_moduli);
        let mut rng = self.context().create_random_generator();
        sample_noise(&mut rng, poly_degree, cipher_parms, cipher_context_data.small_ntt_tables(), true, &mut tmp);
        polymod::add_inplace_p(&mut hi, &tmp, poly_degree, cipher_moduli);
        if !is_ntt_form {
            polymod::intt_p(&mut hi, poly_degree, cipher_context_data.small_ntt_tables());
        }

        DecryptionProtocol {
            participant: self,
            cipher: cipher.clone(),
            h_reveal: PolynomialRevelationProtocol {
                participant: self,
                broadcasted: vec![None; self.participant_count],
                result: hi,
                parms_id: *cipher.parms_id(),
            },
        }

    }

    pub fn public_key_switch(&self, cipher: &Ciphertext, new_public_key: &PublicKey) -> PublicKeySwitchProtocol {

        assert_eq!(cipher.size(), 2, "For keyswitching, the ciphertext size must be 2 polynomials.");

        use crate::util::rlwe;
        let cipher_context_data = self.context().get_context_data(cipher.parms_id()).unwrap();
        let key_context_data = self.context().key_context_data().unwrap();
        let key_parms = key_context_data.parms();
        let poly_degree = key_parms.poly_modulus_degree();
        let is_ntt_form = cipher.is_ntt_form();
        let cipher_parms = cipher_context_data.parms();
        let cipher_moduli = cipher_parms.coeff_modulus();
        let ntt_tables = cipher_context_data.small_ntt_tables();
        let mut rng = self.context().create_random_generator();
        
        // h0i = si c1 + ui p'0 + e
        let mut h0i = self.secret_key().as_plaintext().data()[..poly_degree * cipher_moduli.len()].to_vec();
        let mut tmp = cipher.poly(1).to_vec();
        let mut ui = vec![0; tmp.len()];
        if !is_ntt_form {
            polymod::ntt_p(&mut tmp, poly_degree, cipher_context_data.small_ntt_tables());
        }
        polymod::dyadic_product_inplace_p(&mut h0i, &tmp, poly_degree, cipher_moduli);
        rlwe::sample::ternary(&mut rng, cipher_parms, &mut ui);
        polymod::ntt_p(&mut ui, poly_degree, ntt_tables);
        tmp.copy_from_slice(&ui);
        polymod::dyadic_product_inplace_p(&mut tmp, new_public_key.as_ciphertext().poly(0), poly_degree, cipher_moduli);
        polymod::add_inplace_p(&mut h0i, &tmp, poly_degree, cipher_moduli);
        sample_noise(&mut rng, poly_degree, cipher_parms, cipher_context_data.small_ntt_tables(), true, &mut tmp);
        polymod::add_inplace_p(&mut h0i, &tmp, poly_degree, cipher_moduli);
        if !is_ntt_form {
            polymod::intt_p(&mut h0i, poly_degree, cipher_context_data.small_ntt_tables());
        }

        // h1i = ui p'1 + e
        let mut h1i = new_public_key.as_ciphertext().poly(1)[..poly_degree * cipher_moduli.len()].to_vec();
        polymod::dyadic_product_inplace_p(&mut h1i, &ui, poly_degree, cipher_moduli);
        sample_noise(&mut rng, poly_degree, cipher_parms, cipher_context_data.small_ntt_tables(), true, &mut tmp);
        polymod::add_inplace_p(&mut h1i, &tmp, poly_degree, cipher_moduli);
        if !is_ntt_form {
            polymod::intt_p(&mut h1i, poly_degree, cipher_context_data.small_ntt_tables());
        }

        PublicKeySwitchProtocol {
            participant: self,
            cipher: cipher.clone(),
            h0_reveal: PolynomialRevelationProtocol {
                participant: self,
                broadcasted: vec![None; self.participant_count],
                result: h0i,
                parms_id: *cipher.parms_id(),
            },
            h1_reveal: PolynomialRevelationProtocol {
                participant: self,
                broadcasted: vec![None; self.participant_count],
                result: h1i,
                parms_id: *cipher.parms_id(),
            },
        }

    }

    pub fn cipher_to_shares<S, E>(&self, mut cipher: Ciphertext, share_sampler: &S, share_encoder: &E) -> CipherToSharesProtocol<S::Share>
    where 
        S: ShareSampler,
        E: ShareEncoder<Share=S::Share>,
    {

        assert_eq!(cipher.size(), 2, "For keyswitching, the ciphertext size must be 2 polynomials.");

        let cipher_context_data = self.context().get_context_data(cipher.parms_id()).unwrap();
        let key_context_data = self.context().key_context_data().unwrap();
        let key_parms = key_context_data.parms();
        let poly_degree = key_parms.poly_modulus_degree();
        let is_ntt_form = cipher.is_ntt_form();
        let cipher_parms = cipher_context_data.parms();
        let cipher_moduli = cipher_parms.coeff_modulus();
        
        // hi = si * c1 + e
        let mut hi = self.secret_key().as_plaintext().data()[..poly_degree * cipher_moduli.len()].to_vec();
        let mut tmp = cipher.poly(1).to_vec();

        if !is_ntt_form {
            polymod::ntt_p(&mut tmp, poly_degree, cipher_context_data.small_ntt_tables());
        }
        polymod::dyadic_product_inplace_p(&mut hi, &tmp, poly_degree, cipher_moduli);
        let mut rng = self.context().create_random_generator();
        sample_noise(&mut rng, poly_degree, cipher_parms, cipher_context_data.small_ntt_tables(), true, &mut tmp);
        polymod::add_inplace_p(&mut hi, &tmp, poly_degree, cipher_moduli);
        if !is_ntt_form {
            polymod::intt_p(&mut hi, poly_degree, cipher_context_data.small_ntt_tables());
        }

        if self.participant_id != 0 {
            let share = share_sampler.sample(&mut rng);
            let plaintext = share_encoder.encode(&share);
            cipher.poly_mut(0).iter_mut().for_each(|x| *x = 0);
            self.evaluator.sub_plain_inplace(&mut cipher, &plaintext);
            polymod::add_inplace_p(&mut hi, cipher.poly(0), poly_degree, cipher_moduli);
            CipherToSharesProtocol {
                participant: self,
                share: Some(share),
                cipher: None,
                h_reveal: PolynomialRevelationProtocol {
                    participant: self,
                    broadcasted: vec![None; self.participant_count],
                    result: hi,
                    parms_id: *cipher.parms_id(),
                },
            }
        } else {
            let parms_id = *cipher.parms_id();
            CipherToSharesProtocol {
                participant: self,
                share: None,
                cipher: Some(cipher),
                h_reveal: PolynomialRevelationProtocol {
                    participant: self,
                    broadcasted: vec![None; self.participant_count],
                    result: hi,
                    parms_id,
                },
            }
        }

    }

    pub fn shares_to_cipher<Share, E>(&mut self, share: &Share, share_encoder: &E) -> KeySwitchProtocol 
    where
        E: ShareEncoder<Share=Share>
    {
        let mut common_rng = self.borrow_common_rng();
        let cipher_context_data = self.context.first_context_data().unwrap();
        let cipher_parms = cipher_context_data.parms();
        let poly_degree = cipher_parms.poly_modulus_degree();
        let cipher_moduli = cipher_parms.coeff_modulus();
        let plain = share_encoder.encode(share);
        let mut cipher = Ciphertext::new();
        let parms_id = cipher_context_data.parms_id();
        cipher.resize(&self.context, parms_id, 2);
        if cipher_context_data.is_ckks() {
            cipher.set_is_ntt_form(true);
        } else {
            cipher.set_is_ntt_form(false);
        }
        self.evaluator.add_plain_inplace(&mut cipher, &plain);
        crate::util::rlwe::sample::uniform(&mut common_rng as &mut BlakeRNG, cipher_context_data.parms(), cipher.poly_mut(1));
        let is_ntt_form = cipher.is_ntt_form();

        // hi = -si * c1 + e
        let mut hi = self.secret_key().as_plaintext().data()[..poly_degree * cipher_moduli.len()].to_vec();
        polymod::negate_inplace_p(&mut hi, poly_degree, cipher_moduli); // no need to do on key_moduli.

        let mut tmp = cipher.poly(1).to_vec();

        if !is_ntt_form {
            polymod::ntt_p(&mut tmp, poly_degree, cipher_context_data.small_ntt_tables());
        }
        polymod::dyadic_product_inplace_p(&mut hi, &tmp, poly_degree, cipher_moduli);
        let mut rng = self.context().create_random_generator();
        sample_noise(&mut rng, poly_degree, cipher_parms, cipher_context_data.small_ntt_tables(), true, &mut tmp);
        polymod::add_inplace_p(&mut hi, &tmp, poly_degree, cipher_moduli);
        if !is_ntt_form {
            polymod::intt_p(&mut hi, poly_degree, cipher_context_data.small_ntt_tables());
        }
        if self.participant_id != 0 {
            polymod::add_inplace_p(&mut hi, cipher.poly(0), poly_degree, cipher_moduli);
        }
        
        KeySwitchProtocol {
            participant: self,
            cipher: cipher.clone(),
            h_reveal: PolynomialRevelationProtocol {
                participant: self,
                broadcasted: vec![None; self.participant_count],
                result: hi,
                parms_id: *cipher.parms_id(),
            },
        }

    }

    pub fn element_wise_vector_product(&mut self) -> ElementWiseVectorProductProtocol {
        let p0p1 = self.key_generator.create_public_key_with_u_prng(false, &mut self.borrow_common_rng());
        let broadcasted = vec![None; self.participant_count];

        //let relin_key_protocol = RelinKeysGenerationProtocol::new(self);


        ElementWiseVectorProductProtocol{
            public_key: PublicKeyGenerationProtocol {
                p1_reveal: PolynomialRevelationProtocol { 
                    parms_id: *(p0p1.parms_id()), 
                    participant: self, 
                    broadcasted, 
                    result: p0p1.as_ciphertext().poly(0).to_vec(),
                },
                result: p0p1,
            }
            //relin_key:relin_key_protocol,

        }



    }

}

impl<'a> PolynomialRevelationProtocol<'a> {

    pub fn receive<T: Read>(&mut self, sender_id: usize, stream: &mut T) -> std::io::Result<()> {
        let polynomial = PolynomialSerializer::deserialize_polynomial(&self.participant.context, stream)?;
        self.broadcasted[sender_id] = Some(polynomial);
        Ok(())
    }

    pub fn send<T: Write>(&self, stream: &mut T) -> std::io::Result<()> {
        PolynomialSerializer::serialize_polynomial(&self.participant.context, stream, &self.result, self.parms_id)?;
        Ok(())
    }

    pub fn finish(&mut self) -> &Vec<u64> {
        // check that all participants have sent their messages
        let all_sent = self.broadcasted
            .iter().enumerate()
            .all(|(i, x)| x.is_some() || i == self.participant.participant_id);
        assert!(all_sent, "Not all participants have sent their messages");
        // get polydegree and moduli
        if self.parms_id != PARMS_ID_ZERO {
            let context = self.participant.context();
            let context_data = context.get_context_data(&self.parms_id).unwrap();
            let parms = context_data.parms();
            let degree = parms.poly_modulus_degree();
            let moduli = parms.coeff_modulus();
            // add all p0
            for (i, p0) in self.broadcasted.iter().enumerate() {
                if let Some(p0) = p0 {
                    polymod::add_inplace_p(&mut self.result, p0, degree, moduli);
                } else {
                    assert!(i == self.participant.participant_id);
                }
            }
        } else {
            let context = self.participant.context();
            let context_data = context.first_context_data().unwrap();
            let modulus = context_data.parms().plain_modulus();
            for (i, p0) in self.broadcasted.iter().enumerate() {
                if let Some(p0) = p0 {
                    polymod::add_inplace(&mut self.result, p0, modulus);
                } else {
                    assert!(i == self.participant.participant_id);
                }
            }

        }
        // return
        &self.result
    }

    pub fn finish_take(mut self) -> Vec<u64> {
        self.finish();
        self.result
    }

}

impl<'a> PublicKeyGenerationProtocol<'a> {
    
    pub fn receive<T: Read>(&mut self, sender_id: usize, stream: &mut T) -> std::io::Result<()> {
        self.p1_reveal.receive(sender_id, stream)
    }

    pub fn send<T: Write>(&self, stream: &mut T) -> std::io::Result<()> {
        self.p1_reveal.send(stream)
    }

    pub fn finish(mut self) -> PublicKey {
        let p1 = self.p1_reveal.finish();
        self.result.as_ciphertext_mut().poly_mut(0).copy_from_slice(p1);
        self.result
    }

}

impl<'a> SecretKeyRevelationProtocol<'a> {

    pub fn receive<T: Read>(&mut self, sender_id: usize, stream: &mut T) -> std::io::Result<()> {
        self.s_reveal.receive(sender_id, stream)
    }

    pub fn send<T: Write>(&self, stream: &mut T) -> std::io::Result<()> {
        self.s_reveal.send(stream)
    }

    pub fn finish(self) -> SecretKey {
        let mut ret = self.s_reveal.participant.secret_key().clone();
        let s = self.s_reveal.finish_take();
        ret.data_mut().copy_from_slice(&s);
        ret
    }

}

impl<'a> RelinKeysGenerationProtocol<'a> {
    
    pub fn new(participant: &'a mut Participant) -> Self {

        // Reference: Mouchet et al. Multiparty Homomorphic Encryption from Ring-Learning-with-Errors
        // Protocol 2.
        // Note that for BGV, all noise e should be changed to pe.

        use crate::util::rlwe;
        
        // First sample all randomness from the common RNG tape,
        // because this needs the mutable reference to the participant.

        let key_parms = participant.context.key_context_data().unwrap().parms().clone();
        let key_moduli = key_parms.coeff_modulus();
        let key_mod_count = key_moduli.len();
        let decomp_moduli = &key_moduli[0..key_mod_count-1];
        let decomp_mod_count = decomp_moduli.len();
        let poly_degree = key_parms.poly_modulus_degree();
        let mut common_rng = &mut participant.borrow_common_rng() as &mut BlakeRNG;

        let mut a = Vec::with_capacity(decomp_mod_count);
        for _j in 0..decomp_mod_count {
            // sample a <-- uniform. directly sample as NTT form
            let mut aj = vec![0; key_mod_count * poly_degree];
            rlwe::sample::uniform(&mut common_rng, &key_parms, &mut aj);
            a.push(aj);
        }

        // Step 1: (h0i, h1i) = (-ui * a + si * w + e, si * a + e)
        
        let si = participant.secret_key().data();
        let mut self_rng = participant.context.create_random_generator();
        let context = participant.context();
        let key_context_data = context.key_context_data().unwrap();
        let key_ntt_tables = key_context_data.small_ntt_tables();
        let mut temp = vec![0; key_mod_count * poly_degree];
        
        let context_sample_noise = |prng: &mut BlakeRNG, output: &mut [u64]| {
            sample_noise(prng, poly_degree, &key_parms, key_ntt_tables, true, output);
        };

        let mut u = vec![]; u.reserve_exact(decomp_mod_count);
        let mut h0 = vec![]; h0.reserve_exact(decomp_mod_count);
        let mut h1 = vec![]; h1.reserve_exact(decomp_mod_count);
        
        for j in 0..decomp_mod_count {

            // h0i = -ui * a + si * w + e
            let aj = &a[j];
            // sample u <-- ternary. sample as non-NTT form
            let mut uj = vec![0; key_mod_count * poly_degree];
            rlwe::sample::ternary(&mut self_rng, &key_parms, &mut uj);
            // transform u to NTT form
            polymod::ntt_p(&mut uj, poly_degree, key_ntt_tables);
            // -u * a
            polymod::dyadic_product_p(&uj, aj, poly_degree, key_moduli, &mut temp);
            polymod::negate_inplace_p(&mut temp, poly_degree, key_moduli);
            let mut h0j = temp.clone();
            u.push(uj);
            // si * w. see reference in key.rs/KeyGenerator::generate_one_kswitch_key
            let factor = key_moduli[j].reduce(key_moduli[key_mod_count-1].value());
            polymod::multiply_scalar(
                &si[j * poly_degree .. (j + 1) * poly_degree], 
                factor, &key_moduli[j], 
                &mut temp[0..poly_degree]
            );
            polymod::add_inplace(
                &mut h0j[j * poly_degree .. (j + 1) * poly_degree],
                &temp[0..poly_degree],
                &key_moduli[j]
            );
            // e
            context_sample_noise(&mut self_rng, &mut temp);
            polymod::add_inplace_p(&mut h0j, &temp, poly_degree, key_moduli);
            h0.push(h0j);

            // h1i = si * a + e
            polymod::dyadic_product_p(si, aj, poly_degree, key_moduli, &mut temp);
            let mut h1j = temp.clone();
            context_sample_noise(&mut self_rng, &mut temp);
            polymod::add_inplace_p(&mut h1j, &temp, poly_degree, key_moduli);
            h1.push(h1j);
        }

        let h0_disclosure = h0.into_iter().map(|h0j| {
            PolynomialRevelationProtocol {
                participant,
                broadcasted: vec![None; participant.participant_count],
                result: h0j,
                parms_id: *key_parms.parms_id(),
            }
        }).collect::<Vec<_>>();

        let h1_disclosure = h1.into_iter().map(|h1j| {
            PolynomialRevelationProtocol {
                participant,
                broadcasted: vec![None; participant.participant_count],
                result: h1j,
                parms_id: *key_parms.parms_id(),
            }
        }).collect::<Vec<_>>();

        Self {
            h0_disclosure,
            h1_disclosure,
            u,
            participant,
            h1: Vec::new(),
        }

    }

    pub fn receive_step1<T: Read>(&mut self, sender_id: usize, stream: &mut T) -> std::io::Result<()> {
        for h0j in self.h0_disclosure.iter_mut() {
            h0j.receive(sender_id, stream)?;
        }
        for h1j in self.h1_disclosure.iter_mut() {
            h1j.receive(sender_id, stream)?;
        }
        Ok(())
    }

    pub fn send_step1<T: Write>(&self, stream: &mut T) -> std::io::Result<()> {
        for h0j in self.h0_disclosure.iter() {
            h0j.send(stream)?;
        }
        for h1j in self.h1_disclosure.iter() {
            h1j.send(stream)?;
        }
        Ok(())
    }

    pub fn step2(&mut self) {

        let h0_disclosure = std::mem::take(&mut self.h0_disclosure);
        let h1_disclosure = std::mem::take(&mut self.h1_disclosure);
        let h0 = h0_disclosure.into_iter().map(|h0j| h0j.finish_take()).collect::<Vec<_>>();
        let h1 = h1_disclosure.into_iter().map(|h1j| h1j.finish_take()).collect::<Vec<_>>();

        // Step2: (h'0i, h'1i) = (si * h0 + e, (ui - si) * h1 + e)
        
        let participant = self.participant;
        let si = participant.secret_key().data();
        let context = participant.context();
        let key_context_data = context.key_context_data().unwrap();
        let key_parms = key_context_data.parms();
        let key_ntt_tables = key_context_data.small_ntt_tables();
        let key_moduli = key_parms.coeff_modulus();
        let key_mod_count = key_moduli.len();
        let decomp_moduli = &key_moduli[0..key_mod_count-1];
        let decomp_mod_count = decomp_moduli.len();
        let poly_degree = key_parms.poly_modulus_degree();
        let mut temp = vec![0; key_mod_count * poly_degree];
        
        let context_sample_noise = |prng: &mut BlakeRNG, output: &mut [u64]| {
            sample_noise(prng, poly_degree, key_parms, key_ntt_tables, true, output);
        };

        let mut h0_prime = vec![]; 
        h0_prime.reserve_exact(decomp_mod_count);
        let mut h1_prime = vec![]; 
        h1_prime.reserve_exact(decomp_mod_count);

        let self_rng = &mut participant.context.create_random_generator();

        for j in 0..decomp_mod_count {
            
            // h'0i = si * h0 + e
            polymod::dyadic_product_p(si, &h0[j], poly_degree, key_moduli, &mut temp);
            let mut h0_prime_j = temp.clone();
            context_sample_noise(self_rng, &mut temp);
            polymod::add_inplace_p(&mut h0_prime_j, &temp, poly_degree, key_moduli);
            h0_prime.push(h0_prime_j);

            // h'1i = (ui - si) * h1 + e
            polymod::sub_inplace_p(&mut self.u[j], si, poly_degree, key_moduli);
            polymod::dyadic_product_p(&self.u[j], &h1[j], poly_degree, key_moduli, &mut temp);
            let mut h1_prime_j = temp.clone();
            context_sample_noise(self_rng, &mut temp);
            polymod::add_inplace_p(&mut h1_prime_j, &temp, poly_degree, key_moduli);
            h1_prime.push(h1_prime_j);

        }

        self.h0_disclosure = h0_prime.into_iter().map(|h0j| {
            PolynomialRevelationProtocol {
                participant,
                broadcasted: vec![None; participant.participant_count],
                result: h0j,
                parms_id: *key_parms.parms_id(),
            }
        }).collect::<Vec<_>>();

        self.h1_disclosure = h1_prime.into_iter().map(|h1j| {
            PolynomialRevelationProtocol {
                participant,
                broadcasted: vec![None; participant.participant_count],
                result: h1j,
                parms_id: *key_parms.parms_id(),
            }
        }).collect::<Vec<_>>();

        self.h1 = h1;

    }

    pub fn receive_step2<T: Read>(&mut self, sender_id: usize, stream: &mut T) -> std::io::Result<()> {
        for h0j in self.h0_disclosure.iter_mut() {
            h0j.receive(sender_id, stream)?;
        }
        for h1j in self.h1_disclosure.iter_mut() {
            h1j.receive(sender_id, stream)?;
        }
        Ok(())
    }

    pub fn send_step2<T: Write>(&self, stream: &mut T) -> std::io::Result<()> {
        for h0j in self.h0_disclosure.iter() {
            h0j.send(stream)?;
        }
        for h1j in self.h1_disclosure.iter() {
            h1j.send(stream)?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> RelinKeys {
        
        let h0_disclosure = std::mem::take(&mut self.h0_disclosure);
        let h1_disclosure = std::mem::take(&mut self.h1_disclosure);
        let mut h0_prime = h0_disclosure.into_iter().map(|h0j| h0j.finish_take()).collect::<Vec<_>>();
        let h1_prime = h1_disclosure.into_iter().map(|h1j| h1j.finish_take()).collect::<Vec<_>>();

        let participant = self.participant;
        let context = participant.context();
        let key_context_data = context.key_context_data().unwrap();
        let key_parms = key_context_data.parms();
        let key_moduli = key_parms.coeff_modulus();
        let key_mod_count = key_moduli.len();
        let key_parms_id = key_parms.parms_id();
        let poly_degree = key_parms.poly_modulus_degree();
        
        // output rlk = (h0' + h1', h1)

        let mut rlk = Vec::new(); rlk.reserve_exact(key_mod_count - 1);

        for i in 0..key_mod_count - 1 {
            polymod::add_inplace_p(&mut h0_prime[i], &h1_prime[i], poly_degree, key_moduli);
            
            let mut r = Ciphertext::new();
            r.resize(context, key_parms_id, 2);
            r.set_is_ntt_form(true);
            r.set_scale(1.0);
            r.set_correction_factor(1);
            r.set_parms_id(*key_parms_id);

            r.poly_mut(0).copy_from_slice(&h0_prime[i]);
            r.poly_mut(1).copy_from_slice(&self.h1[i]);
            
            rlk.push(PublicKey::from(r));
        }

        let rlk = vec![rlk];
        let kswitch_keys = KSwitchKeys::from_members(*key_parms_id, rlk);

        RelinKeys::new(kswitch_keys)

    }

}

impl<'a> KeySwitchProtocol<'a> {

    pub fn receive<T: Read>(&mut self, sender_id: usize, stream: &mut T) -> std::io::Result<()> {
        self.h_reveal.receive(sender_id, stream)
    }

    pub fn send<T: Write>(&self, stream: &mut T) -> std::io::Result<()> {
        self.h_reveal.send(stream)
    }

    pub fn finish(mut self) -> Ciphertext {
        let h = self.h_reveal.finish_take();
        let context_data = self.participant.context().get_context_data(self.cipher.parms_id()).unwrap();
        let parms = context_data.parms();
        let poly_degree = parms.poly_modulus_degree();
        let moduli = parms.coeff_modulus();
        polymod::add_inplace_p(self.cipher.poly_mut(0), &h, poly_degree, moduli);
        self.cipher
    }
}

impl<'a> DecryptionProtocol<'a> {

    pub fn receive<T: Read>(&mut self, sender_id: usize, stream: &mut T) -> std::io::Result<()> {
        self.h_reveal.receive(sender_id, stream)
    }

    pub fn send<T: Write>(&self, stream: &mut T) -> std::io::Result<()> {
        self.h_reveal.send(stream)
    }

    pub fn finish(self) -> Plaintext {
        let h = self.h_reveal.finish_take();
        let context_data = self.participant.context().get_context_data(self.cipher.parms_id()).unwrap();
        let parms = context_data.parms();
        let poly_degree = parms.poly_modulus_degree();
        let moduli = parms.coeff_modulus();
        let mut encrypted = self.cipher;
        
        polymod::add_inplace_p(encrypted.poly_mut(0), &h, poly_degree, moduli);
        decrypt_polynomial(self.participant.context(), encrypted.poly(0), &encrypted, encrypted.parms_id())
    }

}

impl<'a> PublicKeySwitchProtocol<'a> {
    
    pub fn receive<T: Read>(&mut self, sender_id: usize, stream: &mut T) -> std::io::Result<()> {
        self.h0_reveal.receive(sender_id, stream)?;
        self.h1_reveal.receive(sender_id, stream)?;
        Ok(())
    }

    pub fn send<T: Write>(&self, stream: &mut T) -> std::io::Result<()> {
        self.h0_reveal.send(stream)?;
        self.h1_reveal.send(stream)?;
        Ok(())
    }

    pub fn finish(self) -> Ciphertext {
        let h0 = self.h0_reveal.finish_take();
        let h1 = self.h1_reveal.finish_take();
        let context_data = self.participant.context().get_context_data(self.cipher.parms_id()).unwrap();
        let parms = context_data.parms();
        let poly_degree = parms.poly_modulus_degree();
        let moduli = parms.coeff_modulus();
        let mut encrypted = self.cipher;
        
        polymod::add_inplace_p(encrypted.poly_mut(0), &h0, poly_degree, moduli);
        encrypted.poly_mut(1).copy_from_slice(&h1);
        
        encrypted
    }

}

impl<'a, Share> CipherToSharesProtocol<'a, Share> {

    pub fn receive<T: Read>(&mut self, sender_id: usize, stream: &mut T) -> std::io::Result<()> {
        assert_eq!(self.participant.participant_id, 0, "Only the first participant can receive");
        self.h_reveal.receive(sender_id, stream)
    }

    pub fn send<T: Write>(&self, stream: &mut T) -> std::io::Result<()> {
        assert_ne!(self.participant.participant_id, 0, "The first participant cannot send");
        self.h_reveal.send(stream)
    }

    pub fn finish<E>(self, encoder: &E) -> Share
    where
        E: ShareEncoder<Share=Share>,
    {
        if self.participant.participant_id != 0 {
            self.share.unwrap()
        } else {
            let h = self.h_reveal.finish_take();
            let cipher = self.cipher.unwrap();
            let context_data = self.participant.context().get_context_data(cipher.parms_id()).unwrap();
            let parms = context_data.parms();
            let poly_degree = parms.poly_modulus_degree();
            let moduli = parms.coeff_modulus();
            let mut encrypted = cipher;
            
            polymod::add_inplace_p(encrypted.poly_mut(0), &h, poly_degree, moduli);
            let plaintext = decrypt_polynomial(self.participant.context(), encrypted.poly(0), &encrypted, encrypted.parms_id());
            encoder.decode(&plaintext)
        }
    }

}

impl<'a> ElementWiseVectorProductProtocol<'a>{


    // generate public key
    pub fn receive_publickey_gen_step<T: Read>(&mut self, sender_id: usize, stream: &mut T) -> std::io::Result<()> {
        self.public_key.receive(sender_id, stream)
    }


    pub fn send_publickey_gen_step<T: Write>(&self, stream: &mut T) -> std::io::Result<()> {
        self.public_key.send(stream)
    }

    pub fn finish_publickey_gen_step(self) -> PublicKey {
        self.public_key.finish()

    }
    /*
  
    // RelinKeys
    pub fn receive_relinkeys_step1<T: Read>(&mut self, sender_id: usize, stream: &mut T) -> std::io::Result<()> {
        self.relin_key.receive_step1(sender_id,stream)
        
    }
    pub fn send_relinkeys_step1<T: Write>(&self, stream: &mut T) -> std::io::Result<()> {
        self.relin_key.send_step1(stream)
        
    }
    pub fn relinkeys_step2(&mut self) {
        self.relin_key.step2()

    }

    pub fn receive_relinkeys_step2<T: Read>(&mut self, sender_id: usize, stream: &mut T) -> std::io::Result<()> {
        self.relin_key.receive_step2(sender_id,stream)
    }

    pub fn send_relinkeys_step2<T: Write>(&self, stream: &mut T) -> std::io::Result<()> {
        self.relin_key.send_step2(stream)
    }

    pub fn finish_relinkeys_step(mut self) -> RelinKeys {
        self.relin_key.finish()
    }
    */
    

}

#[cfg(test)]
mod tests {

    use rand::SeedableRng;

    use crate::{util::PRNGSeed, Encryptor, Decryptor, Evaluator, ExpandSeed};

    use super::*;

    #[test]
    pub fn test_gen_public_key_bfv() {
        
        use crate::create_bfv_decryptor_suite;

        let (_params, context, encoder, _keygen, _encryptor, _decryptor)
            = create_bfv_decryptor_suite(4096, 25, vec![30, 30, 30]);

        let prng_seed = PRNGSeed([1; 64]);
        let mut p0 = Participant::new(2, 0, context.clone(), BlakeRNG::from_seed(prng_seed));
        let mut p1 = Participant::new(2, 1, context.clone(), BlakeRNG::from_seed(prng_seed));

        // generate public key
        let mut protocol0 = p0.generate_public_key();
        let mut protocol1 = p1.generate_public_key();

        let mut msg0 = Vec::new();
        let mut msg1 = Vec::new();
        protocol0.send(&mut msg0).unwrap();
        protocol1.send(&mut msg1).unwrap();

        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        protocol1.receive(0, &mut msg0.as_slice()).unwrap();

        let pk0 = protocol0.finish();
        let pk1 = protocol1.finish();

        // check that both participants have the same public key
        assert_eq!(pk0.data(), pk1.data());

        // reconstruct secret key
        let mut protocol0 = p0.reveal_secret_key();
        let mut protocol1 = p1.reveal_secret_key();

        let mut msg0 = Vec::new();
        let mut msg1 = Vec::new();

        protocol0.send(&mut msg0).unwrap();
        protocol1.send(&mut msg1).unwrap();

        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        protocol1.receive(0, &mut msg0.as_slice()).unwrap();

        let sk0 = protocol0.finish();
        let sk1 = protocol1.finish();

        // check reconstruct secret key is the same
        assert_eq!(sk0.data(), sk1.data());

        // check pk - sk correspond

        let encryptor = Encryptor::new(context.clone()).set_public_key(pk0);
        let decryptor = Decryptor::new(context.clone(), sk0);

        let msg = vec![1, 3, 5, 7];
        let plain = encoder.encode_new(&msg);

        let cipher = encryptor.encrypt_new(&plain);
        let deciphered = decryptor.decrypt_new(&cipher);
        let deciphered = encoder.decode_new(&deciphered);

        assert_eq!(msg, deciphered[..4]);

    }

    #[test]
    pub fn test_gen_relin_keys_bfv() {

        use crate::create_bfv_decryptor_suite;

        let (_params, context, encoder, _keygen, _encryptor, _decryptor)
            = create_bfv_decryptor_suite(8192, 25, vec![60, 40, 60]);

        let prng_seed = PRNGSeed([1; 64]);
        let mut p0 = Participant::new(2, 0, context.clone(), BlakeRNG::from_seed(prng_seed));
        let mut p1 = Participant::new(2, 1, context.clone(), BlakeRNG::from_seed(prng_seed));

        // generate relin key
        let mut protocol0 = p0.generate_relin_keys();
        let mut protocol1 = p1.generate_relin_keys();

        let mut msg0 = Vec::new();
        let mut msg1 = Vec::new();
        protocol0.send_step1(&mut msg0).unwrap();
        protocol1.send_step1(&mut msg1).unwrap();

        protocol0.receive_step1(1, &mut msg1.as_slice()).unwrap();
        protocol1.receive_step1(0, &mut msg0.as_slice()).unwrap();

        protocol0.step2();
        protocol1.step2();

        let mut msg0 = Vec::new();
        let mut msg1 = Vec::new();
        protocol0.send_step2(&mut msg0).unwrap();
        protocol1.send_step2(&mut msg1).unwrap();

        protocol0.receive_step2(1, &mut msg1.as_slice()).unwrap();
        protocol1.receive_step2(0, &mut msg0.as_slice()).unwrap();

        let rlk0 = protocol0.finish();
        let rlk1 = protocol1.finish();

        // check that both participants have the same relin key
        let iter0 = rlk0.as_kswitch_keys().data()[0].iter();
        let iter1 = rlk1.as_kswitch_keys().data()[0].iter();
        for (rlk0i, rlk1i) in iter0.zip(iter1) {
            assert_eq!(rlk0i.data(), rlk1i.data());
        }

        // check that the relin key is correct
        
        // reconstruct secret key
        let mut protocol0 = p0.reveal_secret_key();
        let protocol1 = p1.reveal_secret_key();
        let mut msg1 = Vec::new();
        protocol1.send(&mut msg1).unwrap();
        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        let sk = protocol0.finish();

        let encryptor = Encryptor::new(context.clone()).set_secret_key(sk.clone());
        let decryptor = Decryptor::new(context.clone(), sk);
        let evaluator = Evaluator::new(context.clone());

        let msg = vec![1, 3, 5, 7];
        let plain = encoder.encode_new(&msg);
        let cipher = encryptor.encrypt_symmetric_new(&plain).expand_seed(&context);
        let mul = evaluator.multiply_new(&cipher, &cipher);
        let cipher = evaluator.relinearize_new(&mul, &rlk0);
        let deciphered = decryptor.decrypt_new(&cipher);
        let deciphered = encoder.decode_new(&deciphered);
        assert_eq!(&[1, 9, 25, 49], &deciphered[..4])
        
    }

    #[test]
    pub fn test_key_switch() {

        use crate::create_bfv_decryptor_suite;

        let (_params, context, encoder, _keygen, _encryptor, _decryptor)
            = create_bfv_decryptor_suite(4096, 25, vec![30, 30, 30]);

        let prng_seed = PRNGSeed([1; 64]);
        let mut p0 = Participant::new(2, 0, context.clone(), BlakeRNG::from_seed(prng_seed));
        let mut p1 = Participant::new(2, 1, context.clone(), BlakeRNG::from_seed(prng_seed));

        // generate public key
        let mut protocol0 = p0.generate_public_key();
        let protocol1 = p1.generate_public_key();
        let mut msg1 = Vec::new();
        protocol1.send(&mut msg1).unwrap();
        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        let pk = protocol0.finish();

        // reveal secret key
        let mut protocol0 = p0.reveal_secret_key();
        let protocol1 = p1.reveal_secret_key();
        let mut msg1 = Vec::new();
        protocol1.send(&mut msg1).unwrap();
        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        let sk = protocol0.finish();

        // new secret key
        let keygen_prime_0 = KeyGenerator::new(context.clone());
        let keygen_prime_1 = KeyGenerator::new(context.clone());
        let sk_prime_0 = keygen_prime_0.secret_key().clone();
        let sk_prime_1 = keygen_prime_1.secret_key().clone();
        let mut sk_prime = sk_prime_0.clone();
        let key_context_data = context.key_context_data().unwrap();
        let key_parms = key_context_data.parms();
        polymod::add_inplace_p(sk_prime.data_mut(), sk_prime_1.data(), 
            key_parms.poly_modulus_degree(), key_parms.coeff_modulus());

        // encrypt something
        let values = vec![1, 3, 5, 7];
        let plain = encoder.encode_new(&values);
        let encryptor = Encryptor::new(context.clone()).set_public_key(pk.clone());
        let cipher = encryptor.encrypt_new(&plain);

        // decrypt with original key
        let decryptor = Decryptor::new(context.clone(), sk.clone());
        let deciphered = decryptor.decrypt_new(&cipher);
        let deciphered = encoder.decode_new(&deciphered);
        assert_eq!(values, deciphered[..4]);

        // keyswitch to new key
        let mut protocol0 = p0.key_switch(&cipher, &sk_prime_0);
        let protocol1 = p1.key_switch(&cipher, &sk_prime_1);
        let mut msg1 = Vec::new();
        protocol1.send(&mut msg1).unwrap();
        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        let cipher_prime = protocol0.finish();

        // decrypt with sk_prime
        let decryptor = Decryptor::new(context.clone(), sk_prime);
        let deciphered = decryptor.decrypt_new(&cipher_prime);
        let deciphered = encoder.decode_new(&deciphered);
        assert_eq!(values, deciphered[..4]);

    }

    #[test]
    pub fn test_decrypt() {

        use crate::create_bfv_decryptor_suite;

        let (_params, context, encoder, _keygen, _encryptor, _decryptor)
            = create_bfv_decryptor_suite(4096, 25, vec![30, 30, 30]);

        let prng_seed = PRNGSeed([1; 64]);
        let mut p0 = Participant::new(2, 0, context.clone(), BlakeRNG::from_seed(prng_seed));
        let mut p1 = Participant::new(2, 1, context.clone(), BlakeRNG::from_seed(prng_seed));

        // generate public key
        let mut protocol0 = p0.generate_public_key();
        let protocol1 = p1.generate_public_key();
        let mut msg1 = Vec::new();
        protocol1.send(&mut msg1).unwrap();
        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        let pk = protocol0.finish();

        // encrypt something
        let values = vec![1, 3, 5, 7];
        let plain = encoder.encode_new(&values);
        let encryptor = Encryptor::new(context.clone()).set_public_key(pk.clone());
        let cipher = encryptor.encrypt_new(&plain);

        // decrypt
        let mut protocol0 = p0.decrypt(&cipher);
        let protocol1 = p1.decrypt(&cipher);
        let mut msg1 = Vec::new();
        protocol1.send(&mut msg1).unwrap();
        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        let deciphered = protocol0.finish();
        let decoded = encoder.decode_new(&deciphered);
        assert_eq!(values, decoded[..4]);

    }

    #[test]
    pub fn test_public_key_switch() {

        use crate::create_bfv_decryptor_suite;

        let (_params, context, encoder, _keygen, _encryptor, _decryptor)
            = create_bfv_decryptor_suite(4096, 25, vec![30, 30, 30]);

        let prng_seed = PRNGSeed([1; 64]);
        let mut p0 = Participant::new(2, 0, context.clone(), BlakeRNG::from_seed(prng_seed));
        let mut p1 = Participant::new(2, 1, context.clone(), BlakeRNG::from_seed(prng_seed));

        // generate public key
        let mut protocol0 = p0.generate_public_key();
        let protocol1 = p1.generate_public_key();
        let mut msg1 = Vec::new();
        protocol1.send(&mut msg1).unwrap();
        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        let pk = protocol0.finish();

        // new public key
        let keygen_prime = KeyGenerator::new(context.clone());
        let pk_prime = keygen_prime.create_public_key(false);

        // encrypt something
        let values = vec![1, 3, 5, 7];
        let plain = encoder.encode_new(&values);
        let encryptor = Encryptor::new(context.clone()).set_public_key(pk.clone());
        let cipher = encryptor.encrypt_new(&plain);

        // keyswitch to new key
        let mut protocol0 = p0.public_key_switch(&cipher, &pk_prime);
        let protocol1 = p1.public_key_switch(&cipher, &pk_prime);
        let mut msg1 = Vec::new();
        protocol1.send(&mut msg1).unwrap();
        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        let cipher_prime = protocol0.finish();

        // decrypt with sk_prime
        let decryptor = Decryptor::new(context.clone(), keygen_prime.secret_key().clone());
        let deciphered = decryptor.decrypt_new(&cipher_prime);
        let deciphered = encoder.decode_new(&deciphered);
        assert_eq!(values, deciphered[..4]);

    }

    #[test]
    pub fn test_cipher_to_shares() {

        use crate::create_bfv_decryptor_suite;
        use super::super::utils::{BFVShareSampler, BFVSimdShareEncoder};

        let (_params, context, encoder, _keygen, _encryptor, _decryptor)
            = create_bfv_decryptor_suite(4096, 25, vec![30, 30, 30]);

        let prng_seed = PRNGSeed([1; 64]);
        let mut p0 = Participant::new(2, 0, context.clone(), BlakeRNG::from_seed(prng_seed));
        let mut p1 = Participant::new(2, 1, context.clone(), BlakeRNG::from_seed(prng_seed));

        // generate public key
        let mut protocol0 = p0.generate_public_key();
        let protocol1 = p1.generate_public_key();
        let mut msg1 = Vec::new();
        protocol1.send(&mut msg1).unwrap();
        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        let pk = protocol0.finish();

        // encrypt something
        let values = vec![1, 3, 5, 7];
        let plain = encoder.encode_new(&values);
        let encryptor = Encryptor::new(context.clone()).set_public_key(pk.clone());
        let cipher = encryptor.encrypt_new(&plain);

        // decrypt
        let sampler = BFVShareSampler::new(context.clone());
        let share_encoder = BFVSimdShareEncoder::new(context.clone());
        let mut protocol0 = p0.cipher_to_shares(cipher.clone(), &sampler, &share_encoder);
        let protocol1 = p1.cipher_to_shares(cipher.clone(), &sampler, &share_encoder);
        let mut msg1 = Vec::new();
        protocol1.send(&mut msg1).unwrap();
        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        let share0 = protocol0.finish(&share_encoder);
        let share1 = protocol1.finish(&share_encoder);
        let plain_modulus = *context.first_context_data().unwrap().parms().plain_modulus();
        let combined_share = share0.into_iter().zip(share1).map(|(s0, s1)| {
            plain_modulus.reduce(s0 + s1)
        }).collect::<Vec<_>>();
        assert_eq!(values, combined_share[..4]);

    }

    #[test]
    pub fn test_shares_to_cipher() {

        use crate::create_bfv_decryptor_suite;
        use super::super::utils::BFVSimdShareEncoder;

        let (_params, context, encoder, _keygen, _encryptor, _decryptor)
            = create_bfv_decryptor_suite(4096, 25, vec![30, 30, 30]);

        let prng_seed = PRNGSeed([1; 64]);
        let mut p0 = Participant::new(3, 0, context.clone(), BlakeRNG::from_seed(prng_seed));
        let mut p1 = Participant::new(3, 1, context.clone(), BlakeRNG::from_seed(prng_seed));
        let mut p2 = Participant::new(3, 2, context.clone(), BlakeRNG::from_seed(prng_seed));

        // generate public key
        let mut protocol0 = p0.generate_public_key();
        let protocol1 = p1.generate_public_key();
        let protocol2 = p2.generate_public_key();
        let mut msg1 = Vec::new();
        let mut msg2 = Vec::new();
        protocol1.send(&mut msg1).unwrap();
        protocol2.send(&mut msg2).unwrap();
        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        protocol0.receive(2, &mut msg2.as_slice()).unwrap();

        // encrypt something
        let values0 = vec![1, 3, 5, 7];
        let values1 = vec![2, 4, 6, 8];
        let values2 = vec![3, 5, 7, 9];
        let share_encoder = BFVSimdShareEncoder::new(context.clone());
        let mut protocol0 = p0.shares_to_cipher(&values0, &share_encoder);
        let protocol1 = p1.shares_to_cipher(&values1, &share_encoder);
        let protocol2 = p2.shares_to_cipher(&values2, &share_encoder);
        let mut msg1 = Vec::new();
        let mut msg2 = Vec::new();
        protocol1.send(&mut msg1).unwrap();
        protocol2.send(&mut msg2).unwrap();
        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        protocol0.receive(2, &mut msg2.as_slice()).unwrap();
        let cipher = protocol0.finish();

        // decrypt
        let mut protocol0 = p0.decrypt(&cipher);
        let protocol1 = p1.decrypt(&cipher);
        let protocol2 = p2.decrypt(&cipher);
        let mut msg1 = Vec::new();
        let mut msg2 = Vec::new();
        protocol1.send(&mut msg1).unwrap();
        protocol2.send(&mut msg2).unwrap();
        protocol0.receive(1, &mut msg1.as_slice()).unwrap();
        protocol0.receive(2, &mut msg2.as_slice()).unwrap();
        let deciphered = protocol0.finish();
        let decoded = encoder.decode_new(&deciphered);
        assert_eq!(vec![6, 12, 18, 24], decoded[..4]);

    }

#[test]
    pub fn test_element_wise_vector_product(){
        use crate::create_bfv_decryptor_suite;

        let (_params, context, _encoder, _keygen, _encryptor, _decryptor)
            = create_bfv_decryptor_suite(8192, 25, vec![60, 40, 60]);

        let prng_seed = PRNGSeed([1; 64]);
        let mut p0 = Participant::new(3, 0, context.clone(), BlakeRNG::from_seed(prng_seed));
        let mut p1 = Participant::new(3, 1, context.clone(), BlakeRNG::from_seed(prng_seed));
        let mut p2 = Participant::new(3, 2, context.clone(), BlakeRNG::from_seed(prng_seed));
      

        
        let mut protocol0 = p0.element_wise_vector_product();
        let mut protocol1 = p1.element_wise_vector_product();
        let mut protocol2 = p2.element_wise_vector_product();

        let mut msg0 = Vec::new();
        let mut msg1 = Vec::new();
        let mut msg2 = Vec::new();


        protocol0.send_publickey_gen_step(&mut msg0).unwrap();
        protocol1.send_publickey_gen_step(&mut msg1).unwrap();
        protocol2.send_publickey_gen_step(&mut msg2).unwrap();


        protocol0.receive_publickey_gen_step(1, &mut msg1.as_slice()).unwrap();
        protocol0.receive_publickey_gen_step(2, &mut msg2.as_slice()).unwrap();

        protocol1.receive_publickey_gen_step(0, &mut msg0.as_slice()).unwrap();
        protocol1.receive_publickey_gen_step(2, &mut msg2.as_slice()).unwrap();

        protocol2.receive_publickey_gen_step(0, &mut msg0.as_slice()).unwrap();
        protocol2.receive_publickey_gen_step(1, &mut msg1.as_slice()).unwrap();


        let pk0 = protocol0.finish_publickey_gen_step();
        let pk1 = protocol1.finish_publickey_gen_step();
        let pk2 = protocol2.finish_publickey_gen_step();

        assert_eq!(pk0.data(), pk1.data());
        assert_eq!(pk1.data(), pk2.data());

/*
        // generate relin key

        let mut msg0 = Vec::new();
        let mut msg1 = Vec::new();
        let mut msg2 = Vec::new();
        protocol0.send_relinkeys_step1(&mut msg0).unwrap();
        protocol1.send_relinkeys_step1(&mut msg1).unwrap();
        protocol2.send_relinkeys_step1(&mut msg2).unwrap();

        protocol0.receive_relinkeys_step1(1, &mut msg1.as_slice()).unwrap();
        protocol0.receive_relinkeys_step1(2, &mut msg2.as_slice()).unwrap();


        protocol1.receive_relinkeys_step1(2, &mut msg2.as_slice()).unwrap();
        protocol1.receive_relinkeys_step1(0, &mut msg0.as_slice()).unwrap();

        protocol2.receive_relinkeys_step1(1, &mut msg1.as_slice()).unwrap();
        protocol2.receive_relinkeys_step1(0, &mut msg0.as_slice()).unwrap();

        protocol0.relinkeys_step2();
        protocol1.relinkeys_step2();
        protocol2.relinkeys_step2();

        let mut msg0 = Vec::new();
        let mut msg1 = Vec::new();
        let mut msg2 = Vec::new();

        protocol0.send_relinkeys_step2(&mut msg0).unwrap();
        protocol1.send_relinkeys_step2(&mut msg1).unwrap();
        protocol2.send_step2(&mut msg2).unwrap();


        protocol0.receive_step2(1, &mut msg1.as_slice()).unwrap();
        protocol0.receive_step2(2, &mut msg2.as_slice()).unwrap();


        protocol1.receive_step2(2, &mut msg2.as_slice()).unwrap();
        protocol1.receive_step2(0, &mut msg0.as_slice()).unwrap();

        protocol2.receive_step2(1, &mut msg1.as_slice()).unwrap();
        protocol2.receive_step2(0, &mut msg0.as_slice()).unwrap();


        let rlk0 = protocol0.finish();
        let rlk1 = protocol1.finish();
        let rlk2 = protocol2.finish();

        // check that both participants have the same relin key
        let iter0 = rlk0.as_kswitch_keys().data()[0].iter();
        let iter1 = rlk1.as_kswitch_keys().data()[0].iter();
        
        for (rlk0i, rlk1i) in iter0.zip(iter1) {
            assert_eq!(rlk0i.data(), rlk1i.data());
        }
        let iter1 = rlk1.as_kswitch_keys().data()[0].iter();
        let iter2 = rlk2.as_kswitch_keys().data()[0].iter();
        for (rlk2i, rlk1i) in iter2.zip(iter1) {
            assert_eq!(rlk2i.data(), rlk1i.data());
        }

*/



    }
}