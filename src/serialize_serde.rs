use serde::{Serialize, Deserialize, Deserializer, Serializer, de::{self, Visitor}, ser::SerializeStruct};
use crate::{
    Modulus, Ciphertext, EncryptionParameters, ParmsID, ExpandSeed
};

impl Serialize for Modulus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer 
    {
        serializer.serialize_u64(self.value())
    }
}

impl<'de> Deserialize<'de> for Modulus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> 
    {
        struct U64Visitor;
        impl<'de> Visitor<'de> for U64Visitor {
            type Value = u64;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("u64")
            }
            fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E>
            where E: de::Error, {
                Ok(v)
            }
        }
        let value = deserializer.deserialize_u64(U64Visitor)?; 
        Ok(Modulus::new(value))
    }
}

impl Serialize for EncryptionParameters {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer 
    {
        let mut s = serializer.serialize_struct("EncryptionParameters", 4)?;
        s.serialize_field("scheme", &self.scheme())?;
        s.serialize_field("poly_modulus_degree", &self.poly_modulus_degree())?;
        s.serialize_field("coeff_modulus", self.coeff_modulus())?;
        s.serialize_field("plain_modulus", self.plain_modulus())?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for EncryptionParameters {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> 
    {
        struct EncryptionParametersVisitor;
        impl<'de> Visitor<'de> for EncryptionParametersVisitor {
            type Value = EncryptionParameters;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct EncryptionParameters")
            }
            
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where A: de::SeqAccess<'de>, 
            {
                let scheme = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let poly_modulus_degree = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let coeff_modulus = seq.next_element::<Vec<Modulus>>()?.ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let plain_modulus = seq.next_element::<Modulus>()?.ok_or_else(|| de::Error::invalid_length(3, &self))?;
                Ok(
                    EncryptionParameters::new(scheme)
                        .set_poly_modulus_degree(poly_modulus_degree)
                        .set_coeff_modulus(&coeff_modulus)
                        .set_plain_modulus(&plain_modulus)
                )
            }

        }
        deserializer.deserialize_struct(
            "EncryptionParameters", 
            &["scheme", "poly_modulus_degree", "plain_modulus", "coeff_modulus"], 
            EncryptionParametersVisitor
        )
    }
}

impl Serialize for Ciphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer 
    {
        let mut s = serializer.serialize_struct("Ciphertext", 8)?;
        s.serialize_field("size", &self.size())?;
        s.serialize_field("coeff_modulus_size", &self.coeff_modulus_size())?;
        s.serialize_field("poly_modulus_degree", &self.poly_modulus_degree())?;
        s.serialize_field("parms_id", self.parms_id())?;
        s.serialize_field("scale", &self.scale())?;
        s.serialize_field("correction_factor", &self.correction_factor())?;
        s.serialize_field("is_ntt_form", &self.is_ntt_form())?;
        let data_len = if self.contains_seed() {
            self.poly(0).len() + 1 + (std::mem::size_of::<crate::util::PRNGSeed>() + 7) / 8
        } else {
            self.data().len()
        };
        s.serialize_field("data", &self.data()[0..data_len])?;
        s.end()
    }    
}

impl<'de> Deserialize<'de> for Ciphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> 
    {
        struct CiphertextVisitor;
        impl<'de> Visitor<'de> for CiphertextVisitor {
            type Value = Ciphertext;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct EncryptionParameters")
            }
            
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where A: de::SeqAccess<'de>, 
            {
                let size = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(0, &self))?;
                let coeff_modulus_size = seq.next_element()?.ok_or_else(|| de::Error::invalid_length(1, &self))?;
                let poly_modulus_degree = seq.next_element::<usize>()?.ok_or_else(|| de::Error::invalid_length(2, &self))?;
                let parms_id = seq.next_element::<ParmsID>()?.ok_or_else(|| de::Error::invalid_length(3, &self))?;
                let scale = seq.next_element::<f64>()?.ok_or_else(|| de::Error::invalid_length(4, &self))?;
                let correction_factor = seq.next_element::<u64>()?.ok_or_else(|| de::Error::invalid_length(5, &self))?;
                let is_ntt_form = seq.next_element::<bool>()?.ok_or_else(|| de::Error::invalid_length(6, &self))?;
                let mut data_array = seq.next_element::<Vec<u64>>()?.ok_or_else(|| de::Error::invalid_length(7, &self))?;
                data_array.resize(size * coeff_modulus_size * poly_modulus_degree, 0);
                let ciphertext = Ciphertext::from_members(
                    size, coeff_modulus_size, poly_modulus_degree, data_array,
                    parms_id, scale, correction_factor, is_ntt_form
                );
                Ok(ciphertext)
            }

        }
        deserializer.deserialize_struct(
            "Ciphertext", 
            &[
                "size", "coeff_modulus_size", "poly_modulus_degree", "parms_id",
                "scale", "correction_factor", "is_ntt_form", "data"
            ], 
            CiphertextVisitor
        )
    }
}

/*
mod tests {

    use num_complex;
    use rand::Rng;

    use crate::{
        CoeffModulus, Decryptor, Encryptor, CKKSEncoder, KeyGenerator, HeContext, BatchEncoder,
        SecurityLevel, SchemeType, ExpandSeed, PlainModulus, PublicKey, SecretKey, RelinKeys, GaloisKeys, evaluator::Evaluator, Plaintext,
    };

    use super::*;

    fn serialize<T: Serialize>(obj: &T) -> Vec<u8> {
        bincode::serialize(obj).unwrap()
    }

    fn deserialize<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> T {
        bincode::deserialize(bytes).unwrap()
    }

    fn get_random_vector(size: usize, modulus: u64) -> Vec<u64> {
        let mut rng = rand::thread_rng();
        let mut v = vec![0; size];
        for i in 0..size {
            v[i] = rng.gen::<u64>() % modulus;
        }
        v
    }

    #[test]
    fn test_modulus() {
        let modulus = Modulus::new(17);
        let bytes = serialize(&modulus);
        let recovered: Modulus = deserialize(&bytes);
        assert_eq!(modulus, recovered);
    }

    #[test]
    fn test_encryption_parameters() {
        let ep = EncryptionParameters::new(crate::SchemeType::CKKS)
            .set_poly_modulus_degree(64)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![40, 40]));
        let bytes = serialize(&ep);
        let recovered: EncryptionParameters = deserialize(&bytes);
        assert_eq!(ep.poly_modulus_degree(), recovered.poly_modulus_degree());
        assert_eq!(ep.coeff_modulus(), recovered.coeff_modulus());
        assert_eq!(ep.plain_modulus(), recovered.plain_modulus());
        assert_eq!(ep.scheme(), recovered.scheme());
        assert_eq!(ep.parms_id(), recovered.parms_id());
        
        let ep = EncryptionParameters::new(crate::SchemeType::BFV)
            .set_poly_modulus_degree(64)
            .set_plain_modulus(&Modulus::new(255))
            .set_coeff_modulus(&CoeffModulus::create(64, vec![40, 40]));
        let bytes = serialize(&ep);
        let recovered: EncryptionParameters = deserialize(&bytes);
        assert_eq!(ep.poly_modulus_degree(), recovered.poly_modulus_degree());
        assert_eq!(ep.coeff_modulus(), recovered.coeff_modulus());
        assert_eq!(ep.plain_modulus(), recovered.plain_modulus());
        assert_eq!(ep.scheme(), recovered.scheme());
        assert_eq!(ep.parms_id(), recovered.parms_id());
    }

    #[test]
    fn test_plaintext() {
        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(64)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![40, 40, 40]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let encoder = CKKSEncoder::new(context.clone());

        let scale = (1<<16) as f64;
        let message = get_random_vector(encoder.slots(), 1<<30)
            .into_iter().map(|x| Complex::new(x as f64, 0.0)).collect::<Vec<_>>();
        let plain = encoder.encode_c64_array_new(&message, None, scale);
        let plain_bytes = serialize(&plain);
        let plain: Plaintext = deserialize(&plain_bytes);
        let decoded = encoder.decode_new(&plain);
        for i in 0..message.len() {
            assert!((message[i].re - decoded[i].re).abs() < 0.5);
        }
    }

    #[test]
    fn test_ciphertext() {
        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(64)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![40, 40, 40]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let pk = keygen.create_public_key(false);
        let encryptor = Encryptor::new(context.clone()).set_public_key(pk).set_secret_key(keygen.secret_key().clone());
        let mut decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let encoder = CKKSEncoder::new(context.clone());

        let scale = (1<<16) as f64;
        let message = get_random_vector(encoder.slots(), 1<<30)
            .into_iter().map(|x| Complex::new(x as f64, 0.0)).collect::<Vec<_>>();
        let plain = encoder.encode_c64_array_new(&message, None, scale);
        let cipher = encryptor.encrypt_symmetric_new(&plain);
        let cipher_bytes = serialize(&cipher);
        let symmetric_cipher_length = cipher_bytes.len();
        let cipher: Ciphertext = deserialize(&cipher_bytes);
        assert!(cipher.contains_seed());
        let cipher = cipher.expand_seed(&context);
        assert!(!cipher.contains_seed());
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        for i in 0..message.len() {
            assert!((message[i].re - decoded[i].re).abs() < 0.5);
        }

        let cipher = encryptor.encrypt_new(&plain);
        let cipher_bytes = serialize(&cipher);
        let asymmetric_cipher_length = cipher_bytes.len();
        let cipher: Ciphertext = deserialize(&cipher_bytes);
        assert!(!cipher.contains_seed());
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        for i in 0..message.len() {
            assert!((message[i].re - decoded[i].re).abs() < 0.5);
        }

        assert!(symmetric_cipher_length < asymmetric_cipher_length);

    }

    #[test]
    fn test_keys() {
        
        let alice_parms = EncryptionParameters::new(SchemeType::BFV)
            .set_poly_modulus_degree(64)
            .set_plain_modulus(&PlainModulus::batching(64, 20))
            .set_coeff_modulus(&CoeffModulus::create(64, vec![40, 40, 40]));
        let trans_parms = serialize(&alice_parms);
        let alice_context = HeContext::new(alice_parms, true, SecurityLevel::None);
        let mut alice_keygen = KeyGenerator::new(alice_context.clone());

        let bob_parms: EncryptionParameters = deserialize(&trans_parms);
        let bob_context = HeContext::new(bob_parms, true, SecurityLevel::None);

        let mut alice_context_data = alice_context.key_context_data().unwrap();
        let mut bob_context_data = bob_context.key_context_data().unwrap();
        loop {
            assert_eq!(alice_context_data.parms_id(), bob_context_data.parms_id());
            let an = alice_context_data.next_context_data();
            let bn = bob_context_data.next_context_data();
            if an.is_none() {
                assert!(bn.is_none());
                break;
            }
            alice_context_data = an.unwrap();
            bob_context_data = bn.unwrap();
        }

        let alice_pk = alice_keygen.create_public_key(true);
        let trans_pk = serialize(&alice_pk);
        let alice_pk = alice_pk.expand_seed(&alice_context);

        let alice_encryptor = Encryptor::new(alice_context.clone()).set_public_key(alice_pk).set_secret_key(alice_keygen.secret_key().clone());
        let mut alice_decryptor = Decryptor::new(alice_context.clone(), alice_keygen.secret_key().clone());
        
        let trans_sk = serialize(alice_keygen.secret_key());
        let bob_pk = deserialize::<PublicKey>(&trans_pk).expand_seed(&bob_context);
        let bob_sk = deserialize::<SecretKey>(&trans_sk);

        let bob_encryptor = Encryptor::new(bob_context.clone()).set_public_key(bob_pk).set_secret_key(bob_sk.clone());
        let mut bob_decryptor = Decryptor::new(bob_context.clone(), bob_sk.clone());

        let alice_encoder = BatchEncoder::new(alice_context.clone());
        let bob_encoder = BatchEncoder::new(bob_context.clone());

        fn random_u64_vector(context: &HeContext) -> Vec<u64> {
            let context_data = context.first_context_data().unwrap();
            let parms = context_data.parms();
            let mut vec = vec![0u64; parms.poly_modulus_degree()];
            let modulus = parms.plain_modulus().value();
            for i in 0..vec.len() {
                vec[i] = rand::random::<u64>() % modulus;
            }
            vec
        }

        fn bfv_encrypt(message: &Vec<u64>, encoder: &BatchEncoder, encryptor: &Encryptor) -> Ciphertext {
            let plain = encoder.encode_new(message);
            let ciphertext = encryptor.encrypt_new(&plain);
            ciphertext
        }

        fn bfv_encrypt_symmetric(message: &Vec<u64>, encoder: &BatchEncoder, encryptor: &Encryptor) -> Ciphertext {
            let plain = encoder.encode_new(message);
            let ciphertext = encryptor.encrypt_symmetric_new(&plain);
            ciphertext
        }

        fn bfv_decrypt(ciphertext: &Ciphertext, encoder: &BatchEncoder, decryptor: &mut Decryptor) -> Vec<u64> {
            let plain = decryptor.decrypt_new(ciphertext);
            encoder.decode_new(&plain)
        }

        // Alice encrypt, Bob decrypt (test seckey serialize)
        let message = random_u64_vector(&alice_context);
        let cipher = bfv_encrypt(&message, &alice_encoder, &alice_encryptor);
        let cipher_bytes = serialize(&cipher);
        let deserialized = deserialize::<Ciphertext>(&cipher_bytes);
        let decrypted = bfv_decrypt(&deserialized, &bob_encoder, &mut bob_decryptor);
        assert_eq!(decrypted, message);

        let message = random_u64_vector(&alice_context);
        let cipher = bfv_encrypt_symmetric(&message, &alice_encoder, &alice_encryptor);
        let cipher_bytes = serialize(&cipher);
        let deserialized = deserialize::<Ciphertext>(&cipher_bytes).expand_seed(&bob_context);
        let decrypted = bfv_decrypt(&deserialized, &bob_encoder, &mut bob_decryptor);
        assert_eq!(decrypted, message);

        // Bob encrypt, Alice decrypt (test pubkey serialize)
        let message = random_u64_vector(&bob_context);
        let cipher = bfv_encrypt(&message, &bob_encoder, &bob_encryptor);
        let cipher_bytes = serialize(&cipher);
        let deserialized = deserialize::<Ciphertext>(&cipher_bytes);
        let decrypted = bfv_decrypt(&deserialized, &alice_encoder, &mut alice_decryptor);
        assert_eq!(decrypted, message);

        let message = random_u64_vector(&bob_context);
        let cipher = bfv_encrypt_symmetric(&message, &bob_encoder, &bob_encryptor);
        let cipher_bytes = serialize(&cipher);
        let deserialized = deserialize::<Ciphertext>(&cipher_bytes).expand_seed(&alice_context);
        let decrypted = bfv_decrypt(&deserialized, &alice_encoder, &mut alice_decryptor);
        assert_eq!(decrypted, message);

        // Multiplication + Relinearization (test relinkey serialize)
        let bob_evaluator = Evaluator::new(bob_context.clone());
        let alice_relin_keys = alice_keygen.create_relin_keys(true);
        let trans_relin_keys = serialize(&alice_relin_keys);
        let bob_relin_keys = deserialize::<RelinKeys>(&trans_relin_keys).expand_seed(&bob_context);
        let message1 = random_u64_vector(&alice_context);
        let message2 = random_u64_vector(&alice_context);
        let cipher1 = bfv_encrypt_symmetric(&message1, &alice_encoder, &alice_encryptor);
        let cipher2 = bfv_encrypt_symmetric(&message2, &alice_encoder, &alice_encryptor);
        let cipher1_bytes = serialize(&cipher1);
        let cipher2_bytes = serialize(&cipher2);
        let cipher1 = deserialize::<Ciphertext>(&cipher1_bytes).expand_seed(&bob_context);
        let cipher2 = deserialize::<Ciphertext>(&cipher2_bytes).expand_seed(&bob_context);
        let mut multiplied = bob_evaluator.multiply_new(&cipher1, &cipher2);
        bob_evaluator.relinearize_inplace(&mut multiplied, &bob_relin_keys);
        let multiplied_bytes = serialize(&multiplied);
        let multiplied = deserialize(&multiplied_bytes);
        let decrypted = bfv_decrypt(&multiplied, &alice_encoder, &mut alice_decryptor);
        let plain_modulus = alice_context.first_context_data().unwrap().parms().plain_modulus().value();
        let message_multiplied = message1.iter().zip(message2.iter())
            .map(|(x, y)| x * y % plain_modulus).collect::<Vec<_>>();
        assert_eq!(decrypted, message_multiplied);

        // Rotation (test galoiskeys serialize)
        fn rotate_columns(m: Vec<u64>) -> Vec<u64> {
            let n = m.len() / 2;
            let mut ret = m[n..].to_vec();
            ret.extend_from_slice(&m[0..n]);
            ret
        }
        let alice_galois_keys = alice_keygen.create_galois_keys(true);
        let trans_galois_keys = serialize(&alice_galois_keys);
        let bob_galois_keys = deserialize::<GaloisKeys>(&trans_galois_keys).expand_seed(&bob_context);
        let message = random_u64_vector(&alice_context);
        let cipher = bfv_encrypt_symmetric(&message, &alice_encoder, &alice_encryptor);
        let cipher_bytes = serialize(&cipher);
        let mut cipher = deserialize::<Ciphertext>(&cipher_bytes).expand_seed(&bob_context);
        bob_evaluator.rotate_columns_inplace(&mut cipher, &bob_galois_keys);
        let rotated_bytes = serialize(&cipher);
        let cipher = deserialize(&rotated_bytes);
        let decrypted = bfv_decrypt(&cipher, &alice_encoder, &mut alice_decryptor);
        let message_rotated = rotate_columns(message.clone());
        assert_eq!(decrypted, message_rotated);
    }

}
*/