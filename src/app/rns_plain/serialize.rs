use std::io::{Read, Write, Result};
use super::{
    RnspHeContext, RnspCiphertext,
    RnspPublicKey, RnspGaloisKeys, RnspRelinKeys,
};
use crate::{
    Serializable, SerializableWithHeContext, 
    Ciphertext, PublicKey, GaloisKeys, RelinKeys,
};

pub trait RnspSerializableWithHeContext {
    /// Serialize the object into a stream.
    fn serialize<T: Write>(&self, context: &RnspHeContext, stream: &mut T) -> Result<usize>;
    /// Deserialize the object from a stream.
    fn deserialize<T: Read>(context: &RnspHeContext, stream: &mut T) -> Result<Self> where Self: Sized;
    /// Get the size (bytes) of the object if serialized.
    fn serialized_size(&self, context: &RnspHeContext) -> usize;
}

impl RnspCiphertext {

    pub fn serialize_full<T: Write>(&self, context: &RnspHeContext, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        for (c, context) in self.components.iter().zip(context.components.iter()) {
            bytes_written += c.serialize(context, stream)?;
        }
        Ok(bytes_written)
    }

    pub fn deserialize_full<T: Read>(context: &RnspHeContext, stream: &mut T) -> Result<Self> {
        let components = context.components.iter().map(|context| {
            Ciphertext::deserialize(context, stream)
        }).collect::<Result<Vec<_>>>()?;
        Ok(Self::from_raw_parts(components))
    }

    pub fn serialized_full_size(&self, context: &RnspHeContext) -> usize {
        self.components.iter().zip(context.components.iter()).map(|(c, context)| {
            c.serialized_size(context)
        }).sum()
    }

    pub fn serialize_terms<T: Write>(&self, context: &RnspHeContext, terms: &[usize], stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        for (c, context) in self.components.iter().zip(context.components.iter()) {
            bytes_written += c.serialize_terms(context, terms, stream)?;
        }
        Ok(bytes_written)
    }

    pub fn deserialize_terms<T: Read>(context: &RnspHeContext, terms: &[usize], stream: &mut T) -> Result<Self> {
        let components = context.components.iter().map(|context| {
            Ciphertext::deserialize_terms(context, terms, stream)
        }).collect::<Result<Vec<_>>>()?;
        Ok(Self::from_raw_parts(components))
    }

    pub fn serialized_terms_size(&self, context: &RnspHeContext, terms_count: usize) -> usize {
        self.components.iter().zip(context.components.iter()).map(|(c, context)| {
            c.serialized_terms_size(context, terms_count)
        }).sum()
    }

}

impl RnspSerializableWithHeContext for RnspCiphertext {

    fn serialize<T: Write>(&self, context: &RnspHeContext, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        for (c, context) in self.components.iter().zip(context.components.iter()) {
            bytes_written += c.serialize(context, stream)?;
        }
        Ok(bytes_written)
    }

    fn deserialize<T: Read>(context: &RnspHeContext, stream: &mut T) -> Result<Self> where Self: Sized {
        let components = context.components.iter().map(|context| {
            Ciphertext::deserialize(context, stream)
        }).collect::<Result<Vec<_>>>()?;
        Ok(Self::from_raw_parts(components))
    }

    fn serialized_size(&self, context: &RnspHeContext) -> usize {
        self.components.iter().zip(context.components.iter()).map(|(c, context)| {
            c.serialized_size(context)
        }).sum()
    }

}

impl RnspSerializableWithHeContext for RnspPublicKey {

    fn serialize<T: Write>(&self, context: &RnspHeContext, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        for (c, context) in self.components.iter().zip(context.components.iter()) {
            bytes_written += c.serialize(context, stream)?;
        }
        Ok(bytes_written)
    }

    fn deserialize<T: Read>(context: &RnspHeContext, stream: &mut T) -> Result<Self> where Self: Sized {
        let components = context.components.iter().map(|context| {
            PublicKey::deserialize(context, stream)
        }).collect::<Result<Vec<_>>>()?;
        Ok(Self::from_raw_parts(components))
    }

    fn serialized_size(&self, context: &RnspHeContext) -> usize {
        self.components.iter().zip(context.components.iter()).map(|(c, context)| {
            c.serialized_size(context)
        }).sum()
    }

}


impl RnspSerializableWithHeContext for RnspRelinKeys {

    fn serialize<T: Write>(&self, context: &RnspHeContext, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        for (c, context) in self.components.iter().zip(context.components.iter()) {
            bytes_written += c.serialize(context, stream)?;
        }
        Ok(bytes_written)
    }

    fn deserialize<T: Read>(context: &RnspHeContext, stream: &mut T) -> Result<Self> where Self: Sized {
        let components = context.components.iter().map(|context| {
            RelinKeys::deserialize(context, stream)
        }).collect::<Result<Vec<_>>>()?;
        Ok(Self::from_raw_parts(components))
    }

    fn serialized_size(&self, context: &RnspHeContext) -> usize {
        self.components.iter().zip(context.components.iter()).map(|(c, context)| {
            c.serialized_size(context)
        }).sum()
    }

}


impl RnspSerializableWithHeContext for RnspGaloisKeys {

    fn serialize<T: Write>(&self, context: &RnspHeContext, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        for (c, context) in self.components.iter().zip(context.components.iter()) {
            bytes_written += c.serialize(context, stream)?;
        }
        Ok(bytes_written)
    }

    fn deserialize<T: Read>(context: &RnspHeContext, stream: &mut T) -> Result<Self> where Self: Sized {
        let components = context.components.iter().map(|context| {
            GaloisKeys::deserialize(context, stream)
        }).collect::<Result<Vec<_>>>()?;
        Ok(Self::from_raw_parts(components))
    }

    fn serialized_size(&self, context: &RnspHeContext) -> usize {
        self.components.iter().zip(context.components.iter()).map(|(c, context)| {
            c.serialized_size(context)
        }).sum()
    }

}

impl<I: RnspSerializableWithHeContext> RnspSerializableWithHeContext for Vec<I> {

    fn serialize<T: Write>(&self, context: &RnspHeContext, stream: &mut T) -> Result<usize> {
        let mut bytes_written = 0;
        bytes_written += self.len().serialize(stream)?;
        for item in self.iter() {
            bytes_written += item.serialize(context, stream)?;
        }
        Ok(bytes_written)
    }

    fn deserialize<T: Read>(context: &RnspHeContext, stream: &mut T) -> Result<Vec<I>> {
        let len = usize::deserialize(stream)?;
        let mut ret = Vec::with_capacity(len);
        for _ in 0..len {
            ret.push(I::deserialize(context, stream)?);
        }
        Ok(ret)
    }

    fn serialized_size(&self, context: &RnspHeContext) -> usize {
        let mut size = 0;
        size += self.len().serialized_size();
        for item in self.iter() {
            size += item.serialized_size(context);
        }
        size
    }

}