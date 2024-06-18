use crate::{Encryptor, Decryptor};
use super::{
    RnspHeContext, 
    RnspPlaintext, RnspCiphertext, 
    RnspSecretKey, RnspPublicKey
};

pub struct RnspEncryptor {
    pub components: Vec<Encryptor>,
}

impl RnspEncryptor {

    pub fn from_raw_parts(components: Vec<Encryptor>) -> Self {
        Self { components }
    }
    
    pub fn new(context: &RnspHeContext) -> Self {
        let components = context.components
            .iter()
            .map(|c| 
                Encryptor::new(c.clone())
            )
            .collect();
        Self { components }
    }

    pub fn set_secret_key(self, secret_key: RnspSecretKey) -> Self {
        assert_eq!(self.components.len(), secret_key.components.len());
        let components = self.components
            .into_iter()
            .zip(secret_key.components)
            .map(|(encryptor, secret_key)| {
                encryptor.set_secret_key(secret_key)
            })
            .collect();
        Self { components }
    }

    pub fn set_public_key(self, public_key: RnspPublicKey) -> Self {
        assert_eq!(self.components.len(), public_key.components.len());
        let components = self.components
            .into_iter()
            .zip(public_key.components)
            .map(|(encryptor, public_key)| {
                encryptor.set_public_key(public_key)
            })
            .collect();
        Self { components }
    }

    pub fn encrypt(&self, plain: &RnspPlaintext, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), plain.components.len());
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(plain.components.iter().zip(destination.components.iter_mut())).for_each(|(encryptor, (plain, destination))| {
            encryptor.encrypt(plain, destination)
        });
    }

    pub fn encrypt_new(&self, plain: &RnspPlaintext) -> RnspCiphertext {
        assert_eq!(self.components.len(), plain.components.len());
        let components = self.components.iter().zip(plain.components.iter()).map(|(encryptor, plain)| {
            encryptor.encrypt_new(plain)
        }).collect();
        RnspCiphertext::from_raw_parts(components)
    }

    pub fn encrypt_symmetric(&self, plain: &RnspPlaintext, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), plain.components.len());
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(plain.components.iter().zip(destination.components.iter_mut())).for_each(|(encryptor, (plain, destination))| {
            encryptor.encrypt_symmetric(plain, destination)
        });
    }

    pub fn encrypt_symmetric_new(&self, plain: &RnspPlaintext) -> RnspCiphertext {
        assert_eq!(self.components.len(), plain.components.len());
        let components = self.components.iter().zip(plain.components.iter()).map(|(encryptor, plain)| {
            encryptor.encrypt_symmetric_new(plain)
        }).collect();
        RnspCiphertext::from_raw_parts(components)
    }
}

pub struct RnspDecryptor {
    pub components: Vec<Decryptor>,
}

impl RnspDecryptor {

    pub fn new(context: &RnspHeContext, secret_key: RnspSecretKey) -> Self {
        assert_eq!(context.components.len(), secret_key.components.len());
        let components = context.components.iter()
            .zip(secret_key.components)
            .map(|(context, secret_key)| {
                Decryptor::new(context.clone(), secret_key)
            })
            .collect();
        Self { components }
    }

    pub fn decrypt(&self, cipher: &RnspCiphertext, destination: &mut RnspPlaintext) {
        assert_eq!(self.components.len(), cipher.components.len());
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(cipher.components.iter().zip(destination.components.iter_mut())).for_each(|(decryptor, (cipher, destination))| {
            decryptor.decrypt(cipher, destination)
        });
    }

    pub fn decrypt_new(&self, cipher: &RnspCiphertext) -> RnspPlaintext {
        assert_eq!(self.components.len(), cipher.components.len());
        let components = self.components.iter().zip(cipher.components.iter()).map(|(decryptor, cipher)| {
            decryptor.decrypt_new(cipher)
        }).collect();
        RnspPlaintext::from_raw_parts(components)
    }

}