#![warn(missing_docs)]
//! Heathcliff: A Rust implementation of BFV, CKKS and BGV homomorphic encryption schemes.
//! 
//! # Usage
//! 
//! - **Parameter selection and context setup**:
//! First an [EncryptionParameters] struct should be created, specifying the scheme type, polynomial modulus degree, coefficient moduli,
//! plain modulus (for BFV/BGV only), etc. Then
//! an [HE context](HeContext) could be created using [EncryptionParameters], and
//! then different utilities ([BatchEncoder], [CKKSEncoder], [KeyGenerator], [Encryptor], [Evaluator], [Decryptor])
//! could be created using the [HeContext]. They are all thread-safe.
//! 
//! - **Encoding and decoding**:
//! [BatchEncoder] is used in BFV and BGV schemes, encoding [u64] vectors into [Plaintext]s,
//! while [CKKSEncoder] is used in CKKS scheme, encoding [`num_complex<u64>`] vectors into [Plaintext]s.
//! Decoding utilities are provided as well.
//! 
//! - **Key generation and encryption/decryption**:
//! [PublicKey], [RelinKeys], [GaloisKeys] could be created using [KeyGenerator]. [Encryptor] could use [PublicKey]
//! to encrypt asymmetrically and [SecretKey] to encrypt symmetrically. [SecretKey] could be retrieved from the [KeyGenerator].
//! [Decryptor] uses [SecretKey] to decrypt.
//! 
//! - **HE evaluation**:
//! [Evaluator] provides homomorphic operations on [Ciphertext]s and [Plaintext]s, including addition, multiplication, 
//! relinearization, rotation, etc.
//! 
//! - **Serialization**:
//! [Serializable] and [SerializableWithHeContext] traits are provided for serialization and deserialization.
//! [EncryptionParameters] could be serialized without [HeContext] to let another party create the same [HeContext].
//! Also, [Plaintext] and [SecretKey] could be directly serialized without providing an [HeContext], but the users
//! are not supposed to serialize them. [PublicKey], [RelinKeys], [GaloisKeys] and [Ciphertext] could be serialized into 
//! bytes and the user must provide an [HeContext] for serializing/deserializing. [Ciphertext] encrypted by symmetric encryption
//! and with `save_seed` set to true could save half the serialized size, compared to the case with `save_seed` set to false 
//! (in asymmetric encryption you cannot save the seed). Similarly, [PublicKey], [RelinKeys] and [GaloisKeys] created with `save_seed`
//! could also save the communication cost. However, be aware that these structs with the seed saved must be expanded ([ExpandSeed] trait)
//! before using (if they are not serialized). Deserialization automatically expands the seed, so there is no need to call [ExpandSeed::expand_seed]
//! for a receiver.
//! 
//! 
//! # Examples
//! 
//! ## Setup HE context using shortcut and do HE operation
//! ```
//! use heathcliff::*;
//! // Alice create its HE tools
//! let (params, context_a, encoder_a, keygen, encryptor, decryptor)
//!     = create_bfv_decryptor_suite(8192, 20, vec![60, 40, 60]);
//! // We do not use relinearization and rotation here.
//! let (public_key, _, _) = keygen.create_public_keys(false);
//! // Suppose `params` is sent to Bob
//! let (context_b, encoder_b, evaluator)
//!     = create_bfv_evaluator_suite_from_params(params);
//! // Alice encrypts two messages
//! let message1 = vec![1, 3, 5, 7];
//! let message2 = vec![2, 4, 6, 8];
//! let plain1 = encoder_a.encode_new(&message1);
//! let plain2 = encoder_a.encode_new(&message2);
//! let cipher1 = encryptor.encrypt_new(&plain1);
//! let cipher2 = encryptor.encrypt_new(&plain2);
//! // Suppose the ciphertexts are sent to Bob
//! let cipher3 = evaluator.add_new(&cipher1, &cipher2);
//! // Suppose the result is sent back to Alice
//! let plain3 = decryptor.decrypt_new(&cipher3);
//! let message3 = encoder_a.decode_new(&plain3);
//! assert_eq!(&message3[..4], &vec![3, 7, 11, 15]);
//! assert_eq!(&message3[4..], &vec![0; 8192 - 4]);
//! ```
//! 
//! ## Setup HE tools manually
//! 
//! ```rust
//! use heathcliff::*;
//! 
//! // Setup parameters
//! let poly_modulus_degree = 8192;
//! let parms = EncryptionParameters::new(SchemeType::BFV)
//!     .set_poly_modulus_degree(poly_modulus_degree)
//!     .set_coeff_modulus(&CoeffModulus::create(poly_modulus_degree, vec![60, 40, 60]))
//!     .set_plain_modulus(&PlainModulus::batching(poly_modulus_degree, 20));
//! 
//! // Setup HE context
//! let context = HeContext::new(parms, true, SecurityLevel::Tc128);
//! 
//! // Setup utility tools
//! let encoder = BatchEncoder::new(context.clone());
//! let keygen = KeyGenerator::new(context.clone());
//! let (public_key, _, _) = keygen.create_public_keys(false);
//! let encryptor = Encryptor::new(context.clone()).set_public_key(public_key);
//! let evaluator = Evaluator::new(context.clone());
//! let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
//! ```
//! 
//! ## Serialization and deserialization
//! 
//! ```rust
//! use heathcliff::*;
//! 
//! fn serialize<T: Serializable>(obj: &T) -> Vec<u8> {
//!    let mut buf = Vec::new(); buf.reserve(obj.serialized_size());
//!    obj.serialize(&mut buf).unwrap();
//!    buf
//! }
//! 
//! fn deserialize<T: Serializable>(buf: &[u8]) -> T {
//!    let mut stream = buf;
//!    T::deserialize(&mut stream).unwrap()
//! }
//! 
//! fn serialize_he<T: SerializableWithHeContext>(obj: &T, context: &HeContext) -> Vec<u8> {
//!    let mut buf = Vec::new(); buf.reserve(obj.serialized_size(context));
//!    obj.serialize(context, &mut buf).unwrap();
//!    buf
//! }
//! 
//! fn deserialize_he<T: SerializableWithHeContext>(buf: &[u8], context: &HeContext) -> T {
//!    let mut stream = buf;
//!    T::deserialize(context, &mut stream).unwrap()
//! }
//! 
//! // Setup HE context for Alice
//! let (params, alice_context, alice_encoder, alice_keygen, alice_encryptor, alice_decryptor)
//!     = create_bfv_decryptor_suite(8192, 20, vec![60, 40, 60]);
//! let public_key = alice_keygen.create_public_key(true);
//! 
//! // Send HE params and public key
//! let he_params_bytes = serialize(&params);
//! let public_key_bytes = serialize_he(&public_key, &alice_context);
//! 
//! // Setup HE context for Bob
//! let (bob_context, bob_encoder, bob_evaluator)
//!     = create_bfv_evaluator_suite_from_params(
//!         deserialize(&he_params_bytes), 
//!     );
//! let bob_encryptor = Encryptor::new(bob_context.clone())
//!     .set_public_key(deserialize_he(&public_key_bytes, &bob_context));
//! 
//! // Bob send asymmetrically encrypted message to Alice
//! let message = vec![1, 3, 5, 7];
//! let plain = bob_encoder.encode_new(&message); // Bob encode
//! let cipher = bob_encryptor.encrypt_new(&plain); // Bob asymmetrically encrypt
//! let cipher_bytes = serialize_he(&cipher, &bob_context); // Bob serialize
//! let deciphered = alice_decryptor.decrypt_new(&deserialize_he(&cipher_bytes, &alice_context)); // Alice deserialize and decrypt
//! let deciphered_message = alice_encoder.decode_new(&deciphered); // Alice decode
//! assert_eq!(&deciphered_message[..4], &vec![1, 3, 5, 7]);
//! assert_eq!(&deciphered_message[4..], &vec![0; 8192 - 4]);
//! 
//! // Alice send symmetrically encrypted message to Bob
//! let message = vec![2, 4, 6, 8];
//! let plain = bob_encoder.encode_new(&message); // Alice encode
//! let cipher = alice_encryptor.encrypt_symmetric_new(&plain); // Alice symmetrically encrypt
//! let cipher_bytes = serialize_he(&cipher, &alice_context); // Alice serialize
//! let mut cipher = deserialize_he(&cipher_bytes, &bob_context); // Bob deserialize
//! bob_evaluator.square_inplace(&mut cipher); // Bob homomorphically square
//! let cipher_bytes = serialize_he(&cipher, &bob_context); // Bob serialize
//! let cipher = deserialize_he(&cipher_bytes, &alice_context); // Alice deserialize
//! let deciphered = alice_decryptor.decrypt_new(&cipher); // Alice decrypt
//! let deciphered_message = alice_encoder.decode_new(&deciphered); // Alice decode
//! assert_eq!(&deciphered_message[..4], &vec![4, 16, 36, 64]);
//! assert_eq!(&deciphered_message[4..], &vec![0; 8192 - 4]);
//! ```

#![allow(
    clippy::identity_op, clippy::erasing_op,
    clippy::redundant_field_names,
    clippy::too_many_arguments,
    clippy::needless_range_loop,
    clippy::unnecessary_unwrap,
    clippy::let_and_return,
    clippy::unused_enumerate_index
)]

pub mod util;
mod modulus;
pub(crate) mod encryption_parameters;
mod context;
mod batch_encoder;
mod text;
mod key;
mod valcheck;
mod ckks_encoder;
mod encryptor;
mod evaluator;
mod shortcut;
pub mod multiparty; // TODO: Remove "pub mod" but use "pub use".

#[deprecated]
mod serialize_serde;

mod serialize;

pub mod app;

pub(crate) use util::polysmallmod as polymod;
// pub(crate) use util::{BlakeRNGFactory, BlakeRNG};

pub use modulus::{
    Modulus,
    CoeffModulus,
    PlainModulus,
};
pub use encryption_parameters::{
    EncryptionParameters,
    EncryptionParameterQualifiers,
    SecurityLevel,
    SchemeType,
    ParmsID,
    PARMS_ID_ZERO,
};
pub use text::{
    Plaintext, Ciphertext, ExpandSeed
};
pub use key::{
    SecretKey,
    PublicKey,
    GaloisKeys,
    RelinKeys,
    KSwitchKeys,
    KeyGenerator
};
pub use context::{
    HeContext,
    ContextData,
};
pub use valcheck::ValCheck;
pub use ckks_encoder::CKKSEncoder;
pub use encryptor::{
    Encryptor, 
    Decryptor
};
pub use batch_encoder::BatchEncoder;
pub use evaluator::Evaluator;
pub use util::he_standard_params;
pub use serialize::{Serializable, SerializableWithHeContext, PolynomialSerializer};
pub use shortcut::*;
pub mod perf_utils;