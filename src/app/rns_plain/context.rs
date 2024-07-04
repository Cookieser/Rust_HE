use std::sync::Arc;
use crate::{SecurityLevel, HeContext, Modulus};
use super::RnspEncryptionParameters;

#[derive(Clone)]
pub struct RnspHeContext {
    pub components: Vec<Arc<HeContext>>,
}

impl RnspHeContext {

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    #[inline]
    pub fn parameters_set(&self) -> bool {
        debug_assert!(!self.is_empty());
        self.components.iter().all(|c| c.parameters_set())
    }

    #[inline]
    pub fn new(parms: RnspEncryptionParameters, expand_mod_chain: bool, sec_level: SecurityLevel) -> Self {
        let components = parms.to_encryption_parameters().map(|parms| {
            
            HeContext::new(parms, expand_mod_chain, sec_level)
        }).collect();
        Self { components }
    }

    #[inline]
    pub fn new_default(parms: RnspEncryptionParameters) -> Self {
        Self::new(parms, true, SecurityLevel::Tc128)
    }

    pub fn plain_modulus(&self) -> Vec<Modulus> {
        self.components.iter().map(|c| *c.first_context_data().unwrap().parms().plain_modulus()).collect()
    }

}