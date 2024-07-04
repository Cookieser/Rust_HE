use crate::{
    PublicKey, SecretKey, RelinKeys, GaloisKeys, KeyGenerator, ExpandSeed,
};
use super::{RnspHeContext, RnspExpandSeed};

#[derive(Clone, Default)]
pub struct RnspSecretKey {
    pub components: Vec<SecretKey>,
}

impl RnspSecretKey {
    pub fn from_raw_parts(components: Vec<SecretKey>) -> Self {
        Self { components }
    }
}

#[derive(Clone, Default)]
pub struct RnspPublicKey {
    pub components: Vec<PublicKey>,
}

impl RnspPublicKey {
    pub fn from_raw_parts(components: Vec<PublicKey>) -> Self {
        Self { components }
    }
}

impl RnspExpandSeed for RnspPublicKey {
    fn contains_seed(&self) -> bool {
        debug_assert!(!self.components.is_empty());
        self.components[0].contains_seed()
    }
    fn expand_seed(self, context: &RnspHeContext) -> Self {
        Self {
            components: self.components.into_iter()
                .zip(context.components.iter())
                .map(|(pk, context)| pk.expand_seed(context))
                .collect()
        }
    }
}

#[derive(Clone, Default)]
pub struct RnspRelinKeys {
    pub components: Vec<RelinKeys>,
}

impl RnspRelinKeys {
    pub fn from_raw_parts(components: Vec<RelinKeys>) -> Self {
        Self { components }
    }
}

impl RnspExpandSeed for RnspRelinKeys {
    fn contains_seed(&self) -> bool {
        debug_assert!(!self.components.is_empty());
        self.components[0].contains_seed()
    }
    fn expand_seed(self, context: &RnspHeContext) -> Self {
        Self {
            components: self.components.into_iter()
                .zip(context.components.iter())
                .map(|(rk, context)| rk.expand_seed(context))
                .collect()
        }
    }
}

#[derive(Clone, Default)]
pub struct RnspGaloisKeys {
    pub components: Vec<GaloisKeys>,
}

impl RnspGaloisKeys {
    pub fn from_raw_parts(components: Vec<GaloisKeys>) -> Self {
        Self { components }
    }
}

impl RnspExpandSeed for RnspGaloisKeys {
    fn contains_seed(&self) -> bool {
        debug_assert!(!self.components.is_empty());
        self.components[0].contains_seed()
    }
    fn expand_seed(self, context: &RnspHeContext) -> Self {
        Self {
            components: self.components.into_iter()
                .zip(context.components.iter())
                .map(|(rk, context)| rk.expand_seed(context))
                .collect()
        }
    }
}

pub struct RnspKeyGenerator {
    pub components: Vec<KeyGenerator>,
}

impl RnspKeyGenerator {

    pub fn new(context: &RnspHeContext) -> Self {
        let context = context.clone();
        let components = context.components.iter().map(|context| {
            KeyGenerator::new(context.clone())
        }).collect();
        Self {
            components,
        }
    }

    pub fn create_public_key(&self, save_seed: bool) -> RnspPublicKey {
        let components = self.components.iter().map(|kg| {
            kg.create_public_key(save_seed)
        }).collect();
        RnspPublicKey::from_raw_parts(components)
    }

    pub fn get_secret_key(&self) -> RnspSecretKey {
        let components = self.components.iter().map(|kg| {
            kg.secret_key().clone()
        }).collect();
        RnspSecretKey::from_raw_parts(components)
    }

    pub fn create_relin_keys(&self, save_seed: bool) -> RnspRelinKeys {
        let components = self.components.iter().map(|kg| {
            kg.create_relin_keys(save_seed)
        }).collect();
        RnspRelinKeys::from_raw_parts(components)
    }

    pub fn create_galois_keys(&self, save_seed: bool) -> RnspGaloisKeys {
        let components = self.components.iter().map(|kg| {
            kg.create_galois_keys(save_seed)
        }).collect();
        RnspGaloisKeys::from_raw_parts(components)
    }

}