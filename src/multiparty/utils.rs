use std::sync::Arc;
use rand_distr::Distribution;

use crate::{HeContext, BatchEncoder, Plaintext};
use super::participant::{ShareEncoder, ShareSampler};

pub struct BFVShareSampler {
    context: Arc<HeContext>
}

impl BFVShareSampler {
    pub fn new(context: Arc<HeContext>) -> Self {
        BFVShareSampler {
            context
        }
    }
}

impl ShareSampler for BFVShareSampler {
    type Share = Vec<u64>;

    fn sample(&self, prng: &mut crate::util::BlakeRNG) -> Self::Share {
        let context_data = self.context.first_context_data().unwrap();
        let parms = context_data.parms();
        let plain_modulus = parms.plain_modulus();
        let coeff_count = parms.poly_modulus_degree();
        let distribution = rand::distributions::Uniform::new(0, plain_modulus.value() - 1);
        
        (0..coeff_count).map(|_| distribution.sample(prng)).collect()
    }
}

pub struct BFVSimdShareEncoder {
    context: Arc<HeContext>,
    encoder: BatchEncoder,
}

impl BFVSimdShareEncoder {
    pub fn new(context: Arc<HeContext>) -> Self {
        let encoder = BatchEncoder::new(context.clone());
        BFVSimdShareEncoder {
            context,
            encoder
        }
    }
}

impl ShareEncoder for BFVSimdShareEncoder {
    type Share = Vec<u64>;

    fn encode(&self, share: &Self::Share) -> Plaintext {
        self.encoder.encode_new(share)
    }

    fn decode(&self, plaintext: &Plaintext) -> Self::Share {
        let mut out = self.encoder.decode_new(plaintext);
        let context_data = self.context.first_context_data().unwrap();
        let parms = context_data.parms();
        let coeff_count = parms.poly_modulus_degree();
        out.resize(coeff_count, 0);
        out
    }
}