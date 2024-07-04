use std::io::{Read, Write, Result};

use crate::{
    Plaintext, 
    Ciphertext, 
    SecretKey, 
    PublicKey, 
    HeContext, 
    Modulus, EncryptionParameters, SchemeType, ParmsID, ExpandSeed, RelinKeys, KSwitchKeys, GaloisKeys, PARMS_ID_ZERO,
};

/// Provide serialization and deserialization methods for
/// HE objects without context information.
pub trait Serializable {
    /// Serialize the object into a stream.
    fn serialize<T: Write>(&self, stream: &mut T) -> Result<usize>;
    /// Deserialize the object from a stream.
    fn deserialize<T: Read>(stream: &mut T) -> Result<Self> where Self: Sized;
    /// Get the size (bytes) of the object if serialized.
    fn serialized_size(&self) -> usize;
}

/// Provide serialization and deserialization methods for
/// HE objects relative to an HE context.
pub trait SerializableWithHeContext {
    /// Serialize the object into a stream.
    fn serialize<T: Write>(&self, context: &HeContext, stream: &mut T) -> Result<usize>;
    /// Deserialize the object from a stream.
    fn deserialize<T: Read>(context: &HeContext, stream: &mut T) -> Result<Self> where Self: Sized;
    /// Get the size (bytes) of the object if serialized.
    fn serialized_size(&self, context: &HeContext) -> usize;
}

impl Serializable for u64 {
    fn serialize<T: Write>(&self, stream: &mut T) -> Result<usize> {
        stream.write(&self.to_le_bytes())
    }
    fn deserialize<T: Read>(stream: &mut T) -> Result<Self> {
        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf).unwrap();
        Ok(u64::from_le_bytes(buf))
    }
    fn serialized_size(&self) -> usize {
        std::mem::size_of::<u64>()
    }
}

impl Serializable for usize {
    fn serialize<T: Write>(&self, stream: &mut T) -> Result<usize> {
        stream.write(&self.to_le_bytes())
    }
    fn deserialize<T: Read>(stream: &mut T) -> Result<Self> {
        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf).unwrap();
        Ok(usize::from_le_bytes(buf))
    }
    fn serialized_size(&self) -> usize {
        std::mem::size_of::<usize>()
    }
}

impl Serializable for u8 {
    #[inline]
    fn serialize<T: Write>(&self, stream: &mut T) -> Result<usize> {
        stream.write(&[*self])
    }
    #[inline]
    fn deserialize<T: Read>(stream: &mut T) -> Result<Self> {
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).unwrap();
        Ok(buf[0])
    }
    fn serialized_size(&self) -> usize {
        std::mem::size_of::<u8>()
    }
}

impl Serializable for bool {
    fn serialize<T: Write>(&self, stream: &mut T) -> Result<usize> {
        let value = if *self { 1u8 } else { 0u8 };
        value.serialize(stream)
    }
    fn deserialize<T: Read>(stream: &mut T) -> Result<Self> {
        let value = u8::deserialize(stream)?;
        Ok(value == 1)
    }
    fn serialized_size(&self) -> usize {
        std::mem::size_of::<u8>()
    }
}

impl Serializable for f64 {
    fn serialize<T: Write>(&self, stream: &mut T) -> Result<usize> {
        let value = self.to_bits();
        value.serialize(stream)
    }
    fn deserialize<T: Read>(stream: &mut T) -> Result<Self> {
        let value = u64::deserialize(stream)?;
        Ok(f64::from_bits(value))
    }
    fn serialized_size(&self) -> usize {
        std::mem::size_of::<u64>()
    }
}

impl Serializable for Modulus {

    fn serialize<T: Write> (&self, stream: &mut T) -> Result<usize> {
        let value = self.value();
        value.serialize(stream)
    }

    fn deserialize<T: Read> (stream: &mut T) -> Result<Modulus> {
        let value = u64::deserialize(stream)?;
        Ok(Modulus::new(value))
    }

    fn serialized_size(&self) -> usize {
        std::mem::size_of::<u64>()
    }

}

impl<I: Serializable> Serializable for Vec<I> {

    fn serialize<T: Write> (&self, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        bytes_written += self.len().serialize(stream)?;
        for modulus in self {
            bytes_written += modulus.serialize(stream)?;
        }
        Ok(bytes_written)
    }

    fn deserialize<T: Read> (stream: &mut T) -> Result<Vec<I>> {
        let len = usize::deserialize(stream)?;
        let mut ret = Vec::with_capacity(len);
        for _ in 0..len {
            let modulus = I::deserialize(stream)?;
            ret.push(modulus);
        }
        Ok(ret)
    }

    fn serialized_size(&self) -> usize {
        let mut size = std::mem::size_of::<usize>();
        for modulus in self {
            size += modulus.serialized_size();
        }
        size
    }

}

impl Serializable for SchemeType {

    fn serialize<T: Write> (&self, stream: &mut T) -> Result<usize> {
        let value = *self as u8;
        value.serialize(stream)
    }

    fn deserialize<T: Read> (stream: &mut T) -> Result<SchemeType> {
        let value = u8::deserialize(stream)?;
        Ok(SchemeType::from(value))
    }

    fn serialized_size(&self) -> usize {
        std::mem::size_of::<u8>()
    }

}

impl Serializable for EncryptionParameters {

    fn serialize<T: Write> (&self, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        bytes_written += self.scheme().serialize(stream)?;
        bytes_written += self.poly_modulus_degree().serialize(stream)?;
        bytes_written += self.coeff_modulus().serialize(stream)?;
        match self.scheme() {
            SchemeType::BFV | SchemeType::BGV => {
                bytes_written += self.plain_modulus().serialize(stream)?;
            },
            _ => {}
        }
        bytes_written += self.use_special_prime_for_encryption().serialize(stream)?;
        Ok(bytes_written)
    }

    fn deserialize<T: Read> (stream: &mut T) -> Result<EncryptionParameters> {
        let scheme = SchemeType::deserialize(stream)?;
        let poly_modulus_degree = usize::deserialize(stream)?;
        let coeff_modulus = Vec::<Modulus>::deserialize(stream)?;
        let plain_modulus = match scheme {
            SchemeType::BFV | SchemeType::BGV => {
                Some(Modulus::deserialize(stream)?)
            },
            _ => None
        };
        let use_special_prime_for_encryption = bool::deserialize(stream)?;
        match scheme {
            SchemeType::BFV | SchemeType::BGV => {
                let ret = EncryptionParameters::new(scheme)
                    .set_poly_modulus_degree(poly_modulus_degree)
                    .set_coeff_modulus(&coeff_modulus)
                    .set_plain_modulus(&plain_modulus.unwrap())
                    .set_use_special_prime_for_encryption(use_special_prime_for_encryption);
                Ok(ret)
            },
            SchemeType::CKKS => {
                let ret = EncryptionParameters::new(scheme)
                    .set_poly_modulus_degree(poly_modulus_degree)
                    .set_coeff_modulus(&coeff_modulus)
                    .set_use_special_prime_for_encryption(use_special_prime_for_encryption);
                Ok(ret)
            }
            _ => {
                Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid scheme type"))
            }
        }
    }

    fn serialized_size(&self) -> usize {
        let mut size = std::mem::size_of::<u8>();
        size += std::mem::size_of::<usize>();
        size += self.coeff_modulus().serialized_size();
        match self.scheme() {
            SchemeType::BFV | SchemeType::BGV => {
                size += self.plain_modulus().serialized_size();
            },
            _ => {}
        }
        size += self.use_special_prime_for_encryption().serialized_size();
        size
    }

}

impl Serializable for ParmsID {

    fn serialize<T: Write> (&self, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        for byte in self {
            bytes_written += byte.serialize(stream)?;
        }
        Ok(bytes_written)
    }

    fn deserialize<T: Read> (stream: &mut T) -> Result<ParmsID> {
        let mut data = [0u64; 4];
        for byte in &mut data {
            *byte = u64::deserialize(stream)?;
        }
        Ok(data)
    }

    fn serialized_size(&self) -> usize {
        std::mem::size_of::<ParmsID>()
    }

}

impl Serializable for Plaintext {
    
    /// This should never be invoked, because you can directly send message
    /// instead of a plaintext. This is not optimized.
    fn serialize<T: Write> (&self, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        bytes_written += self.parms_id().serialize(stream)?;
        bytes_written += self.data().serialize(stream)?;
        bytes_written += self.scale().serialize(stream)?;
        Ok(bytes_written)
    }

    /// This should never be invoked, because you can directly send message
    /// instead of a plaintext.
    fn deserialize<T: Read> (stream: &mut T) -> Result<Plaintext> {
        let parms_id = ParmsID::deserialize(stream)?;
        let data = Vec::<u64>::deserialize(stream)?;
        let scale = f64::deserialize(stream)?;
        let mut ret = Plaintext::new();
        ret.set_parms_id(parms_id);
        ret.set_coeff_count(data.len());
        *ret.data_mut() = data;
        ret.set_scale(scale);
        Ok(ret)
    }

    fn serialized_size(&self) -> usize {
        let mut size = std::mem::size_of::<ParmsID>();
        size += self.data().serialized_size();
        size += self.scale().serialized_size();
        size
    }

}

fn get_u64_limit(value: u64) -> usize {
    use crate::util;
    let bits = util::get_significant_bit_count(value);
    (bits + 7) / 8
}

#[inline]
fn write_u64_limited<T: Write>(stream: &mut T, value: u64, limit: usize) -> Result<usize> {
    let mut bytes_written = 0;
    let mut value = value;
    for _ in 0..limit {
        let byte = (value & 0xFF) as u8;
        bytes_written += byte.serialize(stream)?;
        value >>= 8;
    }
    assert_eq!(value, 0);
    Ok(bytes_written)
}

#[inline]
fn read_u64_limited<T: Read>(stream: &mut T, limit: usize) -> Result<u64> {
    let mut value = 0u64;
    for i in 0..limit {
        let byte = u8::deserialize(stream)?;
        value |= (byte as u64) << (8 * i);
    }
    Ok(value)
}

impl Ciphertext {

    /// Serializes the ciphertext to a stream, but do not use
    /// optimization over modulus sizes.
    pub fn serialize_full<T: Write> (&self, context: &HeContext, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        let context_data = context.get_context_data(self.parms_id()).unwrap();
        let scheme = context_data.parms().scheme();
        // Make sure the coeff_modulus_size and poly_modulus_degree is correct
        if self.coeff_modulus_size() != context_data.parms().coeff_modulus().len() 
            || self.poly_modulus_degree() != context_data.parms().poly_modulus_degree() 
        {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid ciphertext"));
        }
        // Parms id
        bytes_written += self.parms_id().serialize(stream)?;
        // Size
        bytes_written += self.size().serialize(stream)?;
        // Is ntt form
        bytes_written += self.is_ntt_form().serialize(stream)?;
        // Scheme related terms
        match scheme {
            SchemeType::BFV => {}, // No extra field
            SchemeType::CKKS => {
                bytes_written += self.scale().serialize(stream)?;
            },
            SchemeType::BGV => {
                bytes_written += self.correction_factor().serialize(stream)?;
            }
            _ => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid scheme type"))
            }
        }

        // Data
        let data_len = if self.contains_seed() {
            self.poly(0).len() + 1 + (std::mem::size_of::<crate::util::PRNGSeed>() + 7) / 8
        } else {
            self.data().len()
        };
        bytes_written += data_len.serialize(stream)?;
        for data in self.data()[..data_len].iter() {
            bytes_written += data.serialize(stream)?;
        }

        Ok(bytes_written)
    }

    /// Deserializes the ciphertext from a stream, but do not use
    /// optimization over modulus sizes.
    pub fn deserialize_full<T: Read> (context: &HeContext, stream: &mut T) -> Result<Ciphertext> {
        let parms_id = ParmsID::deserialize(stream)?;
        let context_data = context.get_context_data(&parms_id).unwrap();
        let scheme = context_data.parms().scheme();
        let size = usize::deserialize(stream)?;
        let is_ntt_form = bool::deserialize(stream)?;
        let scale = match scheme {
            SchemeType::CKKS => {
                Some(f64::deserialize(stream)?)
            },
            _ => None
        };
        let correction_factor = match scheme {
            SchemeType::BGV => {
                Some(u64::deserialize(stream)?)
            },
            _ => None
        };
        let data_len = usize::deserialize(stream)?;
        let coeff_modulus_size = context_data.parms().coeff_modulus().len();
        let poly_modulus_degree = context_data.parms().poly_modulus_degree();
        let mut data = vec![0u64; coeff_modulus_size * size * poly_modulus_degree];
        for i in 0..data_len {
            data[i] = u64::deserialize(stream)?;
        }
        let mut ret = Ciphertext::from_members(
            size, 
            coeff_modulus_size,
            poly_modulus_degree,
            data,
            parms_id,
            scale.unwrap_or(1.0),
            correction_factor.unwrap_or(1),
            is_ntt_form,
        );
        if ret.contains_seed() {
            ret = ret.expand_seed(context);
        }
        Ok(ret)
    }

    /// Get the size (bytes) of the ciphertext, if serialized by
    /// [Ciphertext::serialize_full].
    pub fn serialized_full_size(&self, context: &HeContext) -> usize {
        let mut size = 0;
        let context_data = context.get_context_data(self.parms_id()).unwrap();
        let scheme = context_data.parms().scheme();
        // Parms id
        size += self.parms_id().serialized_size();
        // Size
        size += self.size().serialized_size();
        // Is ntt form
        size += self.is_ntt_form().serialized_size();
        // Scheme related terms
        match scheme {
            SchemeType::BFV => {}, // No extra field
            SchemeType::CKKS => {
                size += self.scale().serialized_size();
            },
            SchemeType::BGV => {
                size += self.correction_factor().serialized_size();
            }
            _ => {}
        }
        // Data
        let data_len = if self.contains_seed() {
            self.poly(0).len() + 1 + (std::mem::size_of::<crate::util::PRNGSeed>() + 7) / 8
        } else {
            self.data().len()
        };
        size += data_len.serialized_size();
        size += data_len * std::mem::size_of::<u64>();
        size
    }

}

impl Ciphertext {
    
    /// Serialize only a part of the terms of the corresponding plaintext polynomial.
    /// Only applicable when the ciphertext contains exactly 2 polynomials.
    pub fn serialize_terms<T: Write> (&self, context: &HeContext, terms: &[usize], stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        let context_data = context.get_context_data(self.parms_id()).unwrap();
        let scheme = context_data.parms().scheme();
        // Make sure the coeff_modulus_size and poly_modulus_degree is correct
        if self.coeff_modulus_size() != context_data.parms().coeff_modulus().len() 
            || self.poly_modulus_degree() != context_data.parms().poly_modulus_degree() 
        {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid ciphertext"));
        }
        // Parms id
        bytes_written += self.parms_id().serialize(stream)?;
        // Size
        bytes_written += self.size().serialize(stream)?;
        // Is ntt form
        bytes_written += self.is_ntt_form().serialize(stream)?;
        // Scheme related terms
        match scheme {
            SchemeType::BFV => {}, // No extra field
            SchemeType::CKKS => {
                bytes_written += self.scale().serialize(stream)?;
            },
            SchemeType::BGV => {
                bytes_written += self.correction_factor().serialize(stream)?;
            }
            _ => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid scheme type"))
            }
        }

        // Data
        let contains_seed = self.contains_seed();
        bytes_written += contains_seed.serialize(stream)?;
        let modulus = context_data.parms().coeff_modulus();
        let limits = modulus.iter().map(|x| get_u64_limit(x.value())).collect::<Vec<_>>();
        let upper = if contains_seed {1} else {self.size()};
        let mut copied_component;
        for i in 0..upper {
            for j in 0..modulus.len() {
                let mut component = self.poly_component(i, j);
                if i == 0 {
                    if self.is_ntt_form() {
                        copied_component = component.to_vec();
                        crate::util::polysmallmod::intt(&mut copied_component, &context_data.small_ntt_tables()[j]);
                        component = &copied_component;
                    }
                    for &term_index in terms.iter() {
                        bytes_written += write_u64_limited(stream, component[term_index], limits[j])?;
                    }
                } else {
                    for k in component.iter() {
                        bytes_written += write_u64_limited(stream, *k, limits[j])?;
                    }
                }
            }
        }
        if contains_seed {
            let extra = (std::mem::size_of::<crate::util::PRNGSeed>() + 7) / 8;
            for k in self.poly(1)[1..1+extra].iter() {
                bytes_written += (*k).serialize(stream)?;
            }
        }

        Ok(bytes_written)
    }

    /// See [Ciphertext::serialize_terms].
    pub fn deserialize_terms<T: Read>(context: &HeContext, terms: &[usize], stream: &mut T) -> Result<Ciphertext> {
        let parms_id = ParmsID::deserialize(stream)?;
        let context_data = context.get_context_data(&parms_id).unwrap();
        let scheme = context_data.parms().scheme();
        let size = usize::deserialize(stream)?;
        let is_ntt_form = bool::deserialize(stream)?;
        let scale = match scheme {
            SchemeType::CKKS => {
                Some(f64::deserialize(stream)?)
            },
            _ => None
        };
        let correction_factor = match scheme {
            SchemeType::BGV => {
                Some(u64::deserialize(stream)?)
            },
            _ => None
        };
        let coeff_modulus_size = context_data.parms().coeff_modulus().len();
        let poly_modulus_degree = context_data.parms().poly_modulus_degree();
        let mut data = vec![0u64; coeff_modulus_size * size * poly_modulus_degree];
        
        let contains_seed = bool::deserialize(stream)?;
        let modulus = context_data.parms().coeff_modulus();
        let limits = modulus.iter().map(|x| get_u64_limit(x.value())).collect::<Vec<_>>();
        let upper = if contains_seed {1} else {size};
        for i in 0..upper {
            let poly = &mut data[i * coeff_modulus_size * poly_modulus_degree..(i+1) * coeff_modulus_size * poly_modulus_degree];
            for (j, component) in poly.chunks_mut(poly_modulus_degree).enumerate() {
                if i == 0 {
                    for &term_index in terms {
                        component[term_index] = read_u64_limited(stream, limits[j])?;
                    }
                    if is_ntt_form {
                        crate::util::polysmallmod::ntt(component, &context_data.small_ntt_tables()[j]);
                    }
                } else {
                    for k in component.iter_mut() {
                        *k = read_u64_limited(stream, limits[j])?;
                    }
                }
            }
        }
        if contains_seed {
            let extra = (std::mem::size_of::<crate::util::PRNGSeed>() + 7) / 8;
            let poly = &mut data[coeff_modulus_size * poly_modulus_degree..2 * coeff_modulus_size * poly_modulus_degree];
            for k in poly[1..1+extra].iter_mut() {
                *k = u64::deserialize(stream)?;
            }
            poly[0] = crate::text::CIPHERTEXT_SEED_FLAG;
        }

        let mut ret = Ciphertext::from_members(
            size, 
            coeff_modulus_size,
            poly_modulus_degree,
            data,
            parms_id,
            scale.unwrap_or(1.0),
            correction_factor.unwrap_or(1),
            is_ntt_form,
        );
        if ret.contains_seed() {
            ret = ret.expand_seed(context);
        }
        Ok(ret)
    }

    /// Size in bytes if [Ciphertext::serialize_terms] is called.
    pub fn serialized_terms_size(&self, context: &HeContext, terms_count: usize) -> usize {
        let mut size = 0;
        let context_data = context.get_context_data(self.parms_id()).unwrap();
        let scheme = context_data.parms().scheme();
        // Parms id
        size += self.parms_id().serialized_size();
        // Size
        size += self.size().serialized_size();
        // Is ntt form
        size += self.is_ntt_form().serialized_size();
        // Scheme related terms
        match scheme {
            SchemeType::BFV => {}, // No extra field
            SchemeType::CKKS => {
                size += self.scale().serialized_size();
            },
            SchemeType::BGV => {
                size += self.correction_factor().serialized_size();
            }
            _ => {}
        }
        size += 1; // contains_seed
        let context_data = context.get_context_data(self.parms_id()).unwrap();
        let modulus = context_data.parms().coeff_modulus();
        let poly_modulus_degree = context_data.parms().poly_modulus_degree();
        let limits = modulus.iter().map(|x| get_u64_limit(x.value())).collect::<Vec<_>>();
        let upper = if self.contains_seed() {1} else {self.size()};
        for j in 0..modulus.len() {
            size += (terms_count + (upper - 1) * poly_modulus_degree) * limits[j];
        }
        if self.contains_seed() {
            let extra = (std::mem::size_of::<crate::util::PRNGSeed>() + 7) / 8;
            size += extra * std::mem::size_of::<u64>();
        }
        size
    }

}

impl SerializableWithHeContext for Ciphertext {

    fn serialize<T: Write> (&self, context: &HeContext, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        let context_data = context.get_context_data(self.parms_id()).unwrap();
        let scheme = context_data.parms().scheme();
        // Make sure the coeff_modulus_size and poly_modulus_degree is correct
        if self.coeff_modulus_size() != context_data.parms().coeff_modulus().len() 
            || self.poly_modulus_degree() != context_data.parms().poly_modulus_degree() 
        {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid ciphertext"));
        }
        // Parms id
        bytes_written += self.parms_id().serialize(stream)?;
        // Size
        bytes_written += self.size().serialize(stream)?;
        // Is ntt form
        bytes_written += self.is_ntt_form().serialize(stream)?;
        // Scheme related terms
        match scheme {
            SchemeType::BFV => {}, // No extra field
            SchemeType::CKKS => {
                bytes_written += self.scale().serialize(stream)?;
            },
            SchemeType::BGV => {
                bytes_written += self.correction_factor().serialize(stream)?;
            }
            _ => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid scheme type"))
            }
        }

        // Data
        let contains_seed = self.contains_seed();
        bytes_written += contains_seed.serialize(stream)?;
        let modulus = context_data.parms().coeff_modulus();
        let limits = modulus.iter().map(|x| get_u64_limit(x.value())).collect::<Vec<_>>();
        let upper = if contains_seed {1} else {self.size()};
        for i in 0..upper {
            for j in 0..modulus.len() {
                let component = self.poly_component(i, j);
                for k in component.iter() {
                    bytes_written += write_u64_limited(stream, *k, limits[j])?;
                }
            }
        }
        if contains_seed {
            let extra = (std::mem::size_of::<crate::util::PRNGSeed>() + 7) / 8;
            for k in self.poly(1)[1..1+extra].iter() {
                bytes_written += (*k).serialize(stream)?;
            }
        }

        Ok(bytes_written)
    }

    fn deserialize<T: Read>(context: &HeContext, stream: &mut T) -> Result<Ciphertext> {
        let parms_id = ParmsID::deserialize(stream)?;
        let context_data = context.get_context_data(&parms_id).unwrap();
        let scheme = context_data.parms().scheme();
        let size = usize::deserialize(stream)?;
        let is_ntt_form = bool::deserialize(stream)?;
        let scale = match scheme {
            SchemeType::CKKS => {
                Some(f64::deserialize(stream)?)
            },
            _ => None
        };
        let correction_factor = match scheme {
            SchemeType::BGV => {
                Some(u64::deserialize(stream)?)
            },
            _ => None
        };
        let coeff_modulus_size = context_data.parms().coeff_modulus().len();
        let poly_modulus_degree = context_data.parms().poly_modulus_degree();
        let mut data = vec![0u64; coeff_modulus_size * size * poly_modulus_degree];
        
        let contains_seed = bool::deserialize(stream)?;
        let modulus = context_data.parms().coeff_modulus();
        let limits = modulus.iter().map(|x| get_u64_limit(x.value())).collect::<Vec<_>>();
        let upper = if contains_seed {1} else {size};
        for i in 0..upper {
            let poly = &mut data[i * coeff_modulus_size * poly_modulus_degree..(i+1) * coeff_modulus_size * poly_modulus_degree];
            for (j, component) in poly.chunks_mut(poly_modulus_degree).enumerate() {
                for k in component.iter_mut() {
                    *k = read_u64_limited(stream, limits[j])?;
                }
            }
        }
        if contains_seed {
            let extra = (std::mem::size_of::<crate::util::PRNGSeed>() + 7) / 8;
            let poly = &mut data[coeff_modulus_size * poly_modulus_degree..2 * coeff_modulus_size * poly_modulus_degree];
            for k in poly[1..1+extra].iter_mut() {
                *k = u64::deserialize(stream)?;
            }
            poly[0] = crate::text::CIPHERTEXT_SEED_FLAG;
        }

        let mut ret = Ciphertext::from_members(
            size, 
            coeff_modulus_size,
            poly_modulus_degree,
            data,
            parms_id,
            scale.unwrap_or(1.0),
            correction_factor.unwrap_or(1),
            is_ntt_form,
        );
        if ret.contains_seed() {
            ret = ret.expand_seed(context);
        }
        Ok(ret)
    }

    fn serialized_size(&self, context: &HeContext) -> usize {
        let mut size = 0;
        let context_data = context.get_context_data(self.parms_id()).unwrap();
        let scheme = context_data.parms().scheme();
        // Parms id
        size += self.parms_id().serialized_size();
        // Size
        size += self.size().serialized_size();
        // Is ntt form
        size += self.is_ntt_form().serialized_size();
        // Scheme related terms
        match scheme {
            SchemeType::BFV => {}, // No extra field
            SchemeType::CKKS => {
                size += self.scale().serialized_size();
            },
            SchemeType::BGV => {
                size += self.correction_factor().serialized_size();
            }
            _ => {}
        }
        size += 1; // contains_seed
        let context_data = context.get_context_data(self.parms_id()).unwrap();
        let modulus = context_data.parms().coeff_modulus();
        let poly_modulus_degree = context_data.parms().poly_modulus_degree();
        let limits = modulus.iter().map(|x| get_u64_limit(x.value())).collect::<Vec<_>>();
        let upper = if self.contains_seed() {1} else {self.size()};
        for j in 0..modulus.len() {
            size += upper * poly_modulus_degree * limits[j];
        }
        if self.contains_seed() {
            let extra = (std::mem::size_of::<crate::util::PRNGSeed>() + 7) / 8;
            size += extra * std::mem::size_of::<u64>();
        }
        size
    }

}

impl Serializable for SecretKey {

    /// This should never be invoked, because you can directly send message
    /// instead of a plaintext. This is not optimized.
    fn serialize<T: Write>(&self, stream: &mut T) -> Result<usize> {
        self.as_plaintext().serialize(stream)
    }

    /// This should never be invoked, because you can directly send message
    /// instead of a plaintext. This is not optimized.
    fn deserialize<T: Read>(stream: &mut T) -> Result<SecretKey> {
        let plaintext = Plaintext::deserialize(stream)?;
        Ok(SecretKey::new(plaintext))
    }

    fn serialized_size(&self) -> usize {
        self.as_plaintext().serialized_size()
    }

}

impl SerializableWithHeContext for PublicKey {

    fn serialize<T: Write>(&self, context: &HeContext, stream: &mut T) -> Result<usize> {
        self.as_ciphertext().serialize(context, stream)
    }

    fn deserialize<T: Read>(context: &HeContext, stream: &mut T) -> Result<PublicKey> {
        let ciphertext = Ciphertext::deserialize(context, stream)?;
        Ok(PublicKey::new(ciphertext))
    }

    fn serialized_size(&self, context: &HeContext) -> usize {
        self.as_ciphertext().serialized_size(context)
    }

}

impl<I: SerializableWithHeContext> SerializableWithHeContext for Vec<I> {

    fn serialize<T: Write>(&self, context: &HeContext, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        bytes_written += self.len().serialize(stream)?;
        for item in self.iter() {
            bytes_written += item.serialize(context, stream)?;
        }
        Ok(bytes_written)
    }

    fn deserialize<T: Read>(context: &HeContext, stream: &mut T) -> Result<Vec<I>> {
        let len = usize::deserialize(stream)?;
        let mut ret = Vec::with_capacity(len);
        for _ in 0..len {
            ret.push(I::deserialize(context, stream)?);
        }
        Ok(ret)
    }

    fn serialized_size(&self, context: &HeContext) -> usize {
        let mut size = 0;
        size += self.len().serialized_size();
        for item in self.iter() {
            size += item.serialized_size(context);
        }
        size
    }

}

impl SerializableWithHeContext for KSwitchKeys {

    fn serialize<T: Write>(&self, context: &HeContext, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        bytes_written += self.parms_id().serialize(stream)?;
        bytes_written += self.keys().serialize(context, stream)?;
        Ok(bytes_written)
    }

    fn deserialize<T: Read>(context: &HeContext, stream: &mut T) -> Result<KSwitchKeys> {
        let parms_id = ParmsID::deserialize(stream)?;
        let keys = Vec::<Vec<PublicKey>>::deserialize(context, stream)?;
        Ok(KSwitchKeys::from_members(parms_id, keys))
    }

    fn serialized_size(&self, context: &HeContext) -> usize {
        let mut size = 0;
        size += self.parms_id().serialized_size();
        size += self.keys().serialized_size(context);
        size
    }

}

impl SerializableWithHeContext for RelinKeys {

    fn serialize<T: Write>(&self, context: &HeContext, stream: &mut T) -> Result<usize> {
        self.as_kswitch_keys().serialize(context, stream)
    }

    fn deserialize<T: Read>(context: &HeContext, stream: &mut T) -> Result<RelinKeys> {
        let kswitch_keys = KSwitchKeys::deserialize(context, stream)?;
        Ok(RelinKeys::new(kswitch_keys))
    }

    fn serialized_size(&self, context: &HeContext) -> usize {
        self.as_kswitch_keys().serialized_size(context)
    }

}

impl SerializableWithHeContext for GaloisKeys {

    fn serialize<T: Write>(&self, context: &HeContext, stream: &mut T) -> Result<usize> {
        self.as_kswitch_keys().serialize(context, stream)
    }

    fn deserialize<T: Read>(context: &HeContext, stream: &mut T) -> Result<GaloisKeys> {
        let kswitch_keys = KSwitchKeys::deserialize(context, stream)?;
        Ok(GaloisKeys::new(kswitch_keys))
    }

    fn serialized_size(&self, context: &HeContext) -> usize {
        self.as_kswitch_keys().serialized_size(context)
    }

}

/// Provide optimized serialization of a single polynomial,
/// whether in the ciphertext or the plaintext.
/// 
/// One can get the polynomial of a ciphertext with [Ciphertext::poly].
/// For the plaintext, itself is a polynomial. If it is not in the NTT form (BFV/BGV),
/// ParmsID is zero, else it is the ParmsID of a corresponding ciphertext.
pub struct PolynomialSerializer {}

impl PolynomialSerializer {

    /// Serialize a polynomial.
    pub fn serialize_polynomial<T: Write>(context: &HeContext, stream: &mut T, data: &[u64], parms_id: ParmsID) -> Result<usize> {

        let mut bytes_written = 0;
        bytes_written += parms_id.serialize(stream)?;

        if parms_id != PARMS_ID_ZERO {
            let context_data = context.get_context_data(&parms_id).unwrap();
            // Make sure the coeff_modulus_size and poly_modulus_degree is correct
            if data.len() != context_data.parms().coeff_modulus().len()* context_data.parms().poly_modulus_degree() {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid ciphertext"));
            }
            let modulus = context_data.parms().coeff_modulus();
            let limits = modulus.iter().map(|x| get_u64_limit(x.value())).collect::<Vec<_>>();
            let poly_degree = context_data.parms().poly_modulus_degree();

            for j in 0..modulus.len() {
                let component = &data[j * poly_degree..(j+1) * poly_degree];
                for k in component.iter() {
                    bytes_written += write_u64_limited(stream, *k, limits[j])?;
                }
            }
        } else {
            let first_context_data = context.first_context_data().unwrap();
            let modulus = first_context_data.parms().plain_modulus();
            let limit = get_u64_limit(modulus.value());
            let poly_degree = first_context_data.parms().poly_modulus_degree();

            for i in 0..poly_degree {
                if i < data.len() {
                    bytes_written += write_u64_limited(stream, data[i], limit)?;
                } else {
                    bytes_written += write_u64_limited(stream, 0, limit)?;
                }
            }
        }

        Ok(bytes_written)

    }

    /// Deserialize a polynomial. It could be put back
    /// in the corresponding place of a ciphertext or a plaintext.
    pub fn deserialize_polynomial<T: Read>(context: &HeContext, stream: &mut T) -> Result<Vec<u64>> {
        let parms_id = ParmsID::deserialize(stream)?;

        if parms_id != PARMS_ID_ZERO {

            let context_data = context.get_context_data(&parms_id).unwrap();
            
            let coeff_modulus_size = context_data.parms().coeff_modulus().len();
            let poly_modulus_degree = context_data.parms().poly_modulus_degree();
            let mut data = vec![0u64; coeff_modulus_size * poly_modulus_degree];
            
            let modulus = context_data.parms().coeff_modulus();
            let limits = modulus.iter().map(|x| get_u64_limit(x.value())).collect::<Vec<_>>();

            for (j, component) in data.chunks_mut(poly_modulus_degree).enumerate() {
                for k in component.iter_mut() {
                    *k = read_u64_limited(stream, limits[j])?;
                }
            }

            Ok(data)

        } else {

            let context_data = context.first_context_data().unwrap();
            let poly_modulus_degree = context_data.parms().poly_modulus_degree();
            let mut data = vec![0u64; poly_modulus_degree];
            
            let modulus = context_data.parms().plain_modulus();
            let limit = get_u64_limit(modulus.value());

            for k in data.iter_mut() {
                *k = read_u64_limited(stream, limit)?;
            }

            Ok(data)

        }

    }

    /// Size in bytes if [PolynomialSerializer::serialize_polynomial] is called.
    pub fn serialized_polynomial_size(&self, context: &HeContext, parms_id: ParmsID) -> usize {
        let mut size = 0;
        
        size += parms_id.serialized_size();
        
        if parms_id != PARMS_ID_ZERO {
            let context_data = context.get_context_data(&parms_id).unwrap();
            let modulus = context_data.parms().coeff_modulus();
            let poly_modulus_degree = context_data.parms().poly_modulus_degree();
            let limits = modulus.iter().map(|x| get_u64_limit(x.value())).collect::<Vec<_>>();
            for j in 0..modulus.len() {
                size += poly_modulus_degree * limits[j];
            }
        } else {
            let context_data = context.first_context_data().unwrap();
            let modulus = context_data.parms().plain_modulus();
            let poly_modulus_degree = context_data.parms().poly_modulus_degree();
            let limit = get_u64_limit(modulus.value());
            size += poly_modulus_degree * limit;
        }
        size
    }

}

#[cfg(test)]
mod tests {
    use num_complex::Complex;
    use rand::Rng;

    use super::*;
    use crate::{HeContext, CoeffModulus, SecurityLevel, CKKSEncoder, KeyGenerator, Encryptor, Decryptor, PlainModulus, BatchEncoder, Evaluator};

    #[test]
    fn test_modulus() -> Result<()> {
        let modulus = Modulus::new(123456789);
        // Create a stream to write to
        let mut stream = Vec::new();
        // Write the modulus to the stream
        let bytes_len = modulus.serialize(&mut stream)?;
        assert_eq!(bytes_len, modulus.serialized_size());
        assert_eq!(stream.len(), modulus.serialized_size());
        // Create a stream to read from
        let mut stream = stream.as_slice();
        // Read the modulus from the stream
        let modulus2 = Modulus::deserialize(&mut stream)?;
        // Check that the modulus is the same
        assert_eq!(modulus, modulus2);
        Ok(())
    }
    
    #[test]
    fn test_encryption_parameters() {
        let ep = EncryptionParameters::new(crate::SchemeType::CKKS)
            .set_poly_modulus_degree(64)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![40, 40]));
        let mut stream = Vec::new();
        let bytes_len = ep.serialize(&mut stream).unwrap();
        assert_eq!(bytes_len, ep.serialized_size());
        assert_eq!(stream.len(), ep.serialized_size());
        let mut stream = stream.as_slice();
        let recovered: EncryptionParameters = EncryptionParameters::deserialize(&mut stream).unwrap();
        assert_eq!(ep.poly_modulus_degree(), recovered.poly_modulus_degree());
        assert_eq!(ep.coeff_modulus(), recovered.coeff_modulus());
        assert_eq!(ep.plain_modulus(), recovered.plain_modulus());
        assert_eq!(ep.scheme(), recovered.scheme());
        assert_eq!(ep.parms_id(), recovered.parms_id());
        let ep = EncryptionParameters::new(crate::SchemeType::BFV)
            .set_poly_modulus_degree(64)
            .set_plain_modulus(&Modulus::new(255))
            .set_coeff_modulus(&CoeffModulus::create(64, vec![40, 40]));
        let mut stream = Vec::new();
        let bytes_len = ep.serialize(&mut stream).unwrap();
        assert_eq!(bytes_len, ep.serialized_size());
        assert_eq!(stream.len(), ep.serialized_size());
        let mut stream = stream.as_slice();
        let recovered: EncryptionParameters = EncryptionParameters::deserialize(&mut stream).unwrap();
        assert_eq!(ep.poly_modulus_degree(), recovered.poly_modulus_degree());
        assert_eq!(ep.coeff_modulus(), recovered.coeff_modulus());
        assert_eq!(ep.plain_modulus(), recovered.plain_modulus());
        assert_eq!(ep.scheme(), recovered.scheme());
        assert_eq!(ep.parms_id(), recovered.parms_id());
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
        
        let mut stream = Vec::new();
        let bytes_len = plain.serialize(&mut stream).unwrap();
        assert_eq!(bytes_len, plain.serialized_size());
        assert_eq!(stream.len(), plain.serialized_size());

        let mut stream = stream.as_slice();
        let plain: Plaintext = Plaintext::deserialize(&mut stream).unwrap();
        let decoded = encoder.decode_new(&plain);
        for i in 0..message.len() {
            assert!((message[i].re - decoded[i].re).abs() < 0.5);
        }
    }


    fn serialize_simple<T: Serializable>(obj: &T) -> Vec<u8> {
        let mut stream = Vec::new();
        let bytes_len = obj.serialize(&mut stream).unwrap();
        assert_eq!(bytes_len, obj.serialized_size());
        assert_eq!(stream.len(), obj.serialized_size());
        stream
    }

    fn deserialize_simple<T: Serializable>(stream: &[u8]) -> T {
        let mut stream = stream;
        T::deserialize(&mut stream).unwrap()
    }

    fn serialize<T: SerializableWithHeContext>(obj: &T, context: &HeContext) -> Vec<u8> {
        let mut stream = Vec::new();
        let bytes_len = obj.serialize(context, &mut stream).unwrap();
        assert_eq!(bytes_len, obj.serialized_size(context));
        assert_eq!(stream.len(), obj.serialized_size(context));
        stream
    }

    fn deserialize<T: SerializableWithHeContext>(stream: &[u8], context: &HeContext) -> T {
        let mut stream = stream;
        T::deserialize(context, &mut stream).unwrap()
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
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let encoder = CKKSEncoder::new(context.clone());

        let scale = (1<<16) as f64;
        let message = get_random_vector(encoder.slots(), 1<<30)
            .into_iter().map(|x| Complex::new(x as f64, 0.0)).collect::<Vec<_>>();
        let plain = encoder.encode_c64_array_new(&message, None, scale);
        let cipher = encryptor.encrypt_symmetric_new(&plain);
        let cipher_bytes = serialize(&cipher, &context);
        let symmetric_cipher_length = cipher_bytes.len();
        let cipher: Ciphertext = deserialize(&cipher_bytes, &context);
        assert!(!cipher.contains_seed());
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        for i in 0..message.len() {
            assert!((message[i].re - decoded[i].re).abs() < 0.5);
        }

        let cipher = encryptor.encrypt_new(&plain);
        let cipher_bytes = serialize(&cipher, &context);
        let asymmetric_cipher_length = cipher_bytes.len();
        let cipher: Ciphertext = deserialize(&cipher_bytes, &context);
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
        let trans_parms = serialize_simple(&alice_parms);
        let alice_context = HeContext::new(alice_parms, true, SecurityLevel::None);
        let alice_keygen = KeyGenerator::new(alice_context.clone());

        let bob_parms: EncryptionParameters = deserialize_simple(&trans_parms);
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
        let trans_pk = serialize(&alice_pk, &alice_context);
        let alice_pk = alice_pk.expand_seed(&alice_context);

        let alice_encryptor = Encryptor::new(alice_context.clone()).set_public_key(alice_pk).set_secret_key(alice_keygen.secret_key().clone());
        let mut alice_decryptor = Decryptor::new(alice_context.clone(), alice_keygen.secret_key().clone());
        
        let trans_sk = serialize_simple(alice_keygen.secret_key());
        let bob_pk = deserialize::<PublicKey>(&trans_pk, &bob_context);
        let bob_sk = deserialize_simple::<SecretKey>(&trans_sk);

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

        fn bfv_encrypt(message: &[u64], encoder: &BatchEncoder, encryptor: &Encryptor) -> Ciphertext {
            let plain = encoder.encode_new(message);
            
            encryptor.encrypt_new(&plain)
        }

        fn bfv_encrypt_symmetric(message: &[u64], encoder: &BatchEncoder, encryptor: &Encryptor) -> Ciphertext {
            let plain = encoder.encode_new(message);
            
            encryptor.encrypt_symmetric_new(&plain)
        }

        fn bfv_decrypt(ciphertext: &Ciphertext, encoder: &BatchEncoder, decryptor: &mut Decryptor) -> Vec<u64> {
            let plain = decryptor.decrypt_new(ciphertext);
            encoder.decode_new(&plain)
        }

        // Alice encrypt, Bob decrypt (test seckey serialize)
        let message = random_u64_vector(&alice_context);
        let cipher = bfv_encrypt(&message, &alice_encoder, &alice_encryptor);
        let cipher_bytes = serialize(&cipher, &alice_context);
        let deserialized = deserialize::<Ciphertext>(&cipher_bytes, &bob_context);
        let decrypted = bfv_decrypt(&deserialized, &bob_encoder, &mut bob_decryptor);
        assert_eq!(decrypted, message);

        let message = random_u64_vector(&alice_context);
        let cipher = bfv_encrypt_symmetric(&message, &alice_encoder, &alice_encryptor);
        let cipher_bytes = serialize(&cipher, &alice_context);
        let deserialized = deserialize::<Ciphertext>(&cipher_bytes, &bob_context);
        let decrypted = bfv_decrypt(&deserialized, &bob_encoder, &mut bob_decryptor);
        assert_eq!(decrypted, message);

        // Bob encrypt, Alice decrypt (test pubkey serialize)
        let message = random_u64_vector(&bob_context);
        let cipher = bfv_encrypt(&message, &bob_encoder, &bob_encryptor);
        let cipher_bytes = serialize(&cipher, &alice_context);
        let deserialized = deserialize::<Ciphertext>(&cipher_bytes, &bob_context);
        let decrypted = bfv_decrypt(&deserialized, &alice_encoder, &mut alice_decryptor);
        assert_eq!(decrypted, message);

        let message = random_u64_vector(&bob_context);
        let cipher = bfv_encrypt_symmetric(&message, &bob_encoder, &bob_encryptor);
        let cipher_bytes = serialize(&cipher, &alice_context);
        let deserialized = deserialize::<Ciphertext>(&cipher_bytes, &bob_context);
        let decrypted = bfv_decrypt(&deserialized, &alice_encoder, &mut alice_decryptor);
        assert_eq!(decrypted, message);

        // Multiplication + Relinearization (test relinkey serialize)
        let bob_evaluator = Evaluator::new(bob_context.clone());
        let alice_relin_keys = alice_keygen.create_relin_keys(true);
        let trans_relin_keys = serialize(&alice_relin_keys, &alice_context);
        let bob_relin_keys = deserialize::<RelinKeys>(&trans_relin_keys, &bob_context);
        let message1 = random_u64_vector(&alice_context);
        let message2 = random_u64_vector(&alice_context);
        let cipher1 = bfv_encrypt_symmetric(&message1, &alice_encoder, &alice_encryptor);
        let cipher2 = bfv_encrypt_symmetric(&message2, &alice_encoder, &alice_encryptor);
        let cipher1_bytes = serialize(&cipher1, &alice_context);
        let cipher2_bytes = serialize(&cipher2, &alice_context);
        let cipher1 = deserialize::<Ciphertext>(&cipher1_bytes, &bob_context);
        let cipher2 = deserialize::<Ciphertext>(&cipher2_bytes, &bob_context);
        let mut multiplied = bob_evaluator.multiply_new(&cipher1, &cipher2);
        bob_evaluator.relinearize_inplace(&mut multiplied, &bob_relin_keys);
        let multiplied_bytes = serialize(&multiplied, &alice_context);
        let multiplied = deserialize(&multiplied_bytes, &bob_context);
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
        let trans_galois_keys = serialize(&alice_galois_keys, &alice_context);
        let bob_galois_keys = deserialize::<GaloisKeys>(&trans_galois_keys, &bob_context);
        let message = random_u64_vector(&alice_context);
        let cipher = bfv_encrypt_symmetric(&message, &alice_encoder, &alice_encryptor);
        let cipher_bytes = serialize(&cipher, &alice_context);
        let mut cipher = deserialize::<Ciphertext>(&cipher_bytes, &bob_context);
        bob_evaluator.rotate_columns_inplace(&mut cipher, &bob_galois_keys);
        let rotated_bytes = serialize(&cipher, &alice_context);
        let cipher = deserialize(&rotated_bytes, &bob_context);
        let decrypted = bfv_decrypt(&cipher, &alice_encoder, &mut alice_decryptor);
        let message_rotated = rotate_columns(message.clone());
        assert_eq!(decrypted, message_rotated);
    }

    #[test]
    fn test_ciphertext_optimized() {

        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(64)
            .set_coeff_modulus(&CoeffModulus::create(64, vec![30, 30, 30]));
        let context = HeContext::new(parms, false, SecurityLevel::None);
        let keygen = KeyGenerator::new(context.clone());
        let pk = keygen.create_public_key(false);
        let encryptor = Encryptor::new(context.clone()).set_public_key(pk).set_secret_key(keygen.secret_key().clone());
        let decryptor = Decryptor::new(context.clone(), keygen.secret_key().clone());
        let encoder = CKKSEncoder::new(context.clone());

        let scale = (1<<16) as f64;
        let message = get_random_vector(encoder.slots(), 1<<30)
            .into_iter().map(|x| Complex::new(x as f64, 0.0)).collect::<Vec<_>>();
        let plain = encoder.encode_c64_array_new(&message, None, scale);
        let cipher = encryptor.encrypt_new(&plain);
        let mut stream = Vec::new();
        let full_cipher_length = cipher.serialize_full(&context, &mut stream).unwrap();
        assert_eq!(full_cipher_length, stream.len());
        assert_eq!(full_cipher_length, cipher.serialized_full_size(&context));
        let mut stream = stream.as_slice();

        let cipher: Ciphertext = Ciphertext::deserialize_full(&context, &mut stream).unwrap();
        assert!(!cipher.contains_seed());
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        for i in 0..message.len() {
            assert!((message[i].re - decoded[i].re).abs() < 0.5);
        }

        let cipher = encryptor.encrypt_new(&plain);
        let cipher_bytes = serialize(&cipher, &context);
        let optimized_cipher_length = cipher_bytes.len();
        let cipher: Ciphertext = deserialize(&cipher_bytes, &context);
        assert!(!cipher.contains_seed());
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        for i in 0..message.len() {
            assert!((message[i].re - decoded[i].re).abs() < 0.5);
        }

        assert!(full_cipher_length > optimized_cipher_length);
        assert!(full_cipher_length as f64 / optimized_cipher_length as f64 > 1.8);

        let scale = (1<<16) as f64;
        let message = get_random_vector(encoder.slots(), 1<<30)
            .into_iter().map(|x| Complex::new(x as f64, 0.0)).collect::<Vec<_>>();
        let plain = encoder.encode_c64_array_new(&message, None, scale);
        let cipher = encryptor.encrypt_symmetric_new(&plain);
        let mut stream = Vec::new();
        let full_cipher_length = cipher.serialize_full(&context, &mut stream).unwrap();
        assert_eq!(full_cipher_length, stream.len());
        assert_eq!(full_cipher_length, cipher.serialized_full_size(&context));
        let mut stream = stream.as_slice();

        let cipher: Ciphertext = Ciphertext::deserialize_full(&context, &mut stream).unwrap();
        assert!(!cipher.contains_seed());
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        for i in 0..message.len() {
            assert!((message[i].re - decoded[i].re).abs() < 0.5);
        }

        let cipher = encryptor.encrypt_symmetric_new(&plain);
        let cipher_bytes = serialize(&cipher, &context);
        let optimized_cipher_length = cipher_bytes.len();
        let cipher: Ciphertext = deserialize(&cipher_bytes, &context);
        assert!(!cipher.contains_seed());
        let decrypted = decryptor.decrypt_new(&cipher);
        let decoded = encoder.decode_new(&decrypted);
        for i in 0..message.len() {
            assert!((message[i].re - decoded[i].re).abs() < 0.5);
        }

        assert!(full_cipher_length > optimized_cipher_length);
        assert!(full_cipher_length as f64 / optimized_cipher_length as f64 > 1.8);

    }


    #[test]
    fn test_ciphertext_terms_optimized() {
        use crate::{create_ckks_decryptor_suite, Evaluator};
        let (_params, context, encoder, _keygen, encryptor, decryptor)
            = create_ckks_decryptor_suite(8192, vec![60, 60, 60]);
        let evaluator = Evaluator::new(context.clone());
        let scale = (1u64<<40) as f64;
        let x = vec![1.0, 2.0, 3.0];
        let y = vec![4.0, 5.0, 6.0];
        let x_encoded = encoder.encode_f64_polynomial_new(&x, None, scale);
        let y_encoded = encoder.encode_f64_polynomial_new(&y, None, scale);
        let x_decoded = encoder.decode_polynomial_new(&x_encoded);
        x.iter().zip(x_decoded.iter()).for_each(|(a, b)| {
            let tmp = (a - b).abs();
            assert!(tmp < 0.5);
        });
        let x_encrypted = encryptor.encrypt_new(&x_encoded);
        let y_encrypted = encryptor.encrypt_new(&y_encoded);
        let result = evaluator.multiply_new(&x_encrypted, &y_encrypted);
        let terms = [0, 2, 3];
        let mut result_serialized = vec![];
        result.serialize_terms(&context, &terms, &mut result_serialized).unwrap();
        assert_eq!(result_serialized.len(), result.serialized_terms_size(&context, terms.len()));
        assert!(result_serialized.len() < result.serialized_size(&context));
        let result = Ciphertext::deserialize_terms(&context, &terms, &mut result_serialized.as_slice()).unwrap();
        let result_decrypted = decryptor.decrypt_new(&result);
        let result = encoder.decode_polynomial_new(&result_decrypted);
        let expected = [4.0, 13.0, 28.0, 27.0, 18.0];
        result.iter().zip(expected.iter()).enumerate().for_each(|(i, (a, b))| {
            let tmp = (a - b).abs();
            if terms.contains(&i) {
                assert!(tmp < 0.5);
            } else {
                assert!(tmp > 0.5);
            }
        });
        
        use crate::create_bfv_decryptor_suite;
        let (_params, context, encoder, _keygen, encryptor, decryptor)
            = create_bfv_decryptor_suite(8192, 30, vec![60, 60, 60]);
        let evaluator = Evaluator::new(context.clone());
        let x = vec![1, 2, 3];
        let y = vec![4, 5, 6];
        let x_encoded = encoder.encode_polynomial_new(&x);
        let y_encoded = encoder.encode_polynomial_new(&y);
        let x_decoded = encoder.decode_polynomial_new(&x_encoded);
        x.iter().zip(x_decoded.iter()).for_each(|(a, b)| {
            assert_eq!(a, b);
        });
        let x_encrypted = encryptor.encrypt_new(&x_encoded);
        let y_encrypted = encryptor.encrypt_new(&y_encoded);
        let result = evaluator.multiply_new(&x_encrypted, &y_encrypted);
        let result_decrypted = decryptor.decrypt_new(&result);
        let result = encoder.decode_polynomial_new(&result_decrypted);
        let expected = [4, 13, 28, 27, 18];
        result.into_iter().zip(expected.iter()).for_each(|(a, &b)| {
            assert_eq!(a, b);
        });

        let result = evaluator.multiply_plain_new(&x_encrypted, &y_encoded);
        let mut result_serialized = vec![];
        result.serialize_terms(&context, &terms, &mut result_serialized).unwrap();
        assert_eq!(result_serialized.len(), result.serialized_terms_size(&context, terms.len()));
        assert!(result_serialized.len() < result.serialized_size(&context));
        let result = Ciphertext::deserialize_terms(&context, &terms, &mut result_serialized.as_slice()).unwrap();
        let result_decrypted = decryptor.decrypt_new(&result);
        let result = encoder.decode_polynomial_new(&result_decrypted);
        result.iter().zip(expected.iter()).enumerate().for_each(|(i, (a, b))| {
            if terms.contains(&i) {
                assert_eq!(a, b);
            } else {
                assert_ne!(a, b);
            }
        });
    }

}