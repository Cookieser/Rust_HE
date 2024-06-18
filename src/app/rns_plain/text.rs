use crate::{Ciphertext, Plaintext, ExpandSeed};
use super::RnspParmsID;
use super::RnspHeContext;

#[derive(Clone, Default)]
pub struct RnspPlaintext {
    pub components: Vec<Plaintext>,
}

impl RnspPlaintext {

    #[inline]
    pub fn from_raw_parts(components: Vec<Plaintext>) -> Self {
        Self { components }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    #[inline]
    pub fn scale(&self) -> f64 {
        debug_assert!(!self.is_empty());
        self.components[0].scale()
    }

    #[inline]
    pub fn set_scale(&mut self, scale: f64) {
        debug_assert!(!self.is_empty());
        self.components.iter_mut().for_each(|c| c.set_scale(scale));
    }

    #[inline]
    pub fn resize(&mut self, coeff_count: usize) {
        debug_assert!(!self.is_empty());
        self.components.iter_mut().for_each(|c| c.resize(coeff_count));
    }

    #[inline]
    pub fn is_ntt_form(&self) -> bool {
        debug_assert!(!self.is_empty());
        self.components[0].is_ntt_form()
    }

    #[inline]
    pub fn reserve(&mut self, coeff_count: usize) {
        debug_assert!(!self.is_empty());
        self.components.iter_mut().for_each(|c| c.reserve(coeff_count));
    }

    #[inline]
    pub fn parms_id(&self) -> RnspParmsID {
        debug_assert!(!self.is_empty());
        RnspParmsID {
            components: self.components.iter().map(|c| *c.parms_id()).collect()
        }
    }

}

#[derive(Clone, Default)]
pub struct RnspCiphertext {
    pub components: Vec<Ciphertext>,
}

impl RnspCiphertext {

    #[inline]
    pub fn from_raw_parts(components: Vec<Ciphertext>) -> Self {
        Self { components }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    #[inline]
    pub fn scale(&self) -> f64 {
        debug_assert!(!self.is_empty());
        self.components[0].scale()
    }

    #[inline]
    pub fn set_scale(&mut self, scale: f64) {
        debug_assert!(!self.is_empty());
        self.components.iter_mut().for_each(|c| c.set_scale(scale));
    }

    #[inline]
    pub fn coeff_modulus_size(&self) -> usize {
        debug_assert!(!self.is_empty());
        self.components[0].coeff_modulus_size()
    }

    #[inline]
    pub fn parms_id(&self) -> RnspParmsID {
        debug_assert!(!self.is_empty());
        RnspParmsID {
            components: self.components.iter().map(|c| *c.parms_id()).collect()
        }
    }

}

pub trait RnspExpandSeed {
    fn contains_seed(&self) -> bool;
    fn expand_seed(self, context: &RnspHeContext) -> Self;
}

impl RnspExpandSeed for RnspCiphertext {
    fn contains_seed(&self) -> bool {
        debug_assert!(!self.is_empty());
        self.components[0].contains_seed()
    }
    fn expand_seed(self, context: &RnspHeContext) -> Self {
        debug_assert!(!self.is_empty());
        Self {
            components: self.components
                .into_iter().zip(context.components.iter())
                .map(|(c, context)| c.expand_seed(context))
                .collect()
        }
    }
}