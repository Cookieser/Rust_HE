use crate::BatchEncoder;
use super::{RnspHeContext, RnspPlaintext};
use crate::util::RNSBase;

pub struct RnspBatchEncoder {
    pub components: Vec<BatchEncoder>,
    pub rns_base: RNSBase,
}

impl RnspBatchEncoder {

    pub fn new(context: &RnspHeContext) -> Self {
        let components = context.components
            .iter()
            .map(|c| 
                BatchEncoder::new(c.clone())
            )
            .collect();
        let rns_base = RNSBase::new(&context.plain_modulus()).unwrap();
        Self { components, rns_base }
    }

    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    pub fn slot_count(&self) -> usize {
        debug_assert!(!self.is_empty());
        self.components[0].slot_count()
    }

    fn encode_internal_new(&self, values: &[u64], polynomial: bool) -> RnspPlaintext {
        debug_assert!(!self.is_empty());
        // decompose rns
        let mut rns_values = values.to_vec();
        rns_values.resize(self.slot_count() * self.rns_base.len(), 0);
        self.rns_decompose(&mut rns_values);
        // encode
        let components = self.components.iter()
            .zip(rns_values.chunks(self.slot_count()))
            .map(|(encoder, values)| {
                if !polynomial {
                    encoder.encode_new(values)
                } else {
                    encoder.encode_polynomial_new(values)
                }
            })
            .collect();
        RnspPlaintext::from_raw_parts(components)
    }

    /// Every chunk of `RNS component count` items of `value` is regarded
    /// as one input message value, in 64-bit radix, little-endian order.
    pub fn encode_new(&self, values: &[u64]) -> RnspPlaintext {
        self.encode_internal_new(values, false)
    }

    /// Every chunk of `RNS component count` items of `value` is regarded
    /// as one input message value, in 64-bit radix, little-endian order.
    pub fn encode_polynomial_new(&self, values: &[u64]) -> RnspPlaintext {
        self.encode_internal_new(values, true)
    }

    fn decode_internal_new(&self, plaintext: &RnspPlaintext, polynomial: bool) -> Vec<u64> {
        debug_assert_eq!(plaintext.components.len(), self.components.len());
        let mut values = Vec::with_capacity(self.slot_count() * self.rns_base.len());
        for (encoder, plaintext) in self.components.iter().zip(plaintext.components.iter()) {
            if !polynomial {
                values.extend_from_slice(encoder.decode_new(plaintext).as_slice());
            } else {
                let mut decoded_polynomial = encoder.decode_polynomial_new(plaintext);
                decoded_polynomial.resize(self.slot_count(), 0);
                values.extend_from_slice(decoded_polynomial.as_slice());
            }
        }
        // compose rns
        self.rns_compose(&mut values);
        values
    }

    pub fn decode_new(&self, plaintext: &RnspPlaintext) -> Vec<u64> {
        self.decode_internal_new(plaintext, false)
    }

    pub fn decode_polynomial_new(&self, plaintext: &RnspPlaintext) -> Vec<u64> {
        self.decode_internal_new(plaintext, true)
    }

    pub fn rns_decompose(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.slot_count() * self.rns_base.len());
        self.rns_base.decompose_array(values);
    }

    pub fn rns_compose(&self, values: &mut [u64]) {
        debug_assert_eq!(values.len(), self.slot_count() * self.rns_base.len());
        self.rns_base.compose_array(values);
    }

}