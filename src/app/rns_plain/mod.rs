//! Provides support for big RNS plaintext modulus
//! 
//! The interfaces should appear the same as in the vanilla, but with a prefix "Rnsp";
//! The documentation of those functions same as in vanilla is omitted. 
#![allow(missing_docs)]

mod text;
pub use text::{RnspCiphertext, RnspPlaintext, RnspExpandSeed};

mod encryption_parameters;
pub use encryption_parameters::{
    RnspEncryptionParameters, RnspParmsID,
};

mod context;
pub use context::RnspHeContext;

mod key;
pub use key::{
    RnspSecretKey, RnspPublicKey, RnspRelinKeys, RnspGaloisKeys,
    RnspKeyGenerator,
};

mod encryptor;
pub use encryptor::{RnspEncryptor, RnspDecryptor};

mod evaluator;
pub use evaluator::RnspEvaluator;

mod batch_encoder;
pub use batch_encoder::RnspBatchEncoder;

mod serialize;
pub use serialize::RnspSerializableWithHeContext;

pub mod renamed;
