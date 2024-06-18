
use crate::{
    HeContext,
    Encryptor, Decryptor, Evaluator, 
    Serializable, SerializableWithHeContext, ExpandSeed,
};
use super::cipher2d::{Cipher2d, Plain2d};

/// Represent encoded matrices of inputs, weights or outputs.
#[derive(Clone)]
pub struct Plain3d {
    #[allow(missing_docs)]
    pub data: Vec<Plain2d>,
}

/// Represent encrypted matrices of inputs, weights or outputs.
#[derive(Clone)]
pub struct Cipher3d {
    #[allow(missing_docs)]
    pub data: Vec<Cipher2d>,
}

impl Plain3d {
    /// constructor
    pub fn new_2ds(data: Vec<Plain2d>) -> Self {
        Plain3d {data}
    }
    /// Encrypt the 3d matrix. Wrapper of [Encryptor::encrypt_new].
    pub fn encrypt(&self, encryptor: &Encryptor) -> Cipher3d {
        Cipher3d {
            data: self.data.iter().map(|x| x.encrypt(encryptor)).collect::<Vec<_>>()
        }
    }
    /// Encrypt the 3d matrix with symmetric encryption. Wrapper of [Encryptor::encrypt_symmetric_new].
    pub fn encrypt_symmetric(&self, encryptor: &Encryptor) -> Cipher3d {
        Cipher3d {
            data: self.data.iter().map(|x| x.encrypt_symmetric(encryptor)).collect::<Vec<_>>()
        }
    }
    /// Returns the first dimension of the matrix.
    pub fn len(&self) -> usize {
        self.data.len()
    }
    /// Is empty?
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl std::ops::Index<usize> for Plain3d {
    type Output = Plain2d;
    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl std::ops::IndexMut<usize> for Plain3d {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl Serializable for Plain3d {
    fn serialize<T: std::io::Write>(&self, stream: &mut T) -> std::io::Result<usize> {
        let n = self.data.len();
        let mut bytes_written = n.serialize(stream)?;
        for cipher in &self.data {
            bytes_written += cipher.serialize(stream)?;
        }
        Ok(bytes_written)
    }
    fn deserialize<T: std::io::Read>(stream: &mut T) -> std::io::Result<Self> where Self: Sized {
        let n = usize::deserialize(stream)?;
        let mut data = Vec::with_capacity(n);
        for _ in 0..n {
            data.push(Plain2d::deserialize(stream)?);
        }
        Ok(Plain3d {data})
    }
    fn serialized_size(&self) -> usize {
        let n = self.data.len();
        let mut bytes = n.serialized_size();
        for cipher in &self.data {
            bytes += cipher.serialized_size();
        }
        bytes
    }
}

impl ExpandSeed for Cipher3d {
    fn contains_seed(&self) -> bool {
        self.data.iter().all(|x| x.contains_seed())
    }
    fn expand_seed(self, context: &HeContext) -> Self {
        let data = self.data.into_iter().map(|x|
            if x.contains_seed() {
                x.expand_seed(context)
            } else {
                x
            }
        ).collect();
        Self {data}
    }
}

impl SerializableWithHeContext for Cipher3d {
    fn serialize<T: std::io::Write>(&self, context: &HeContext, stream: &mut T) -> std::io::Result<usize> {
        let n = self.data.len();
        let mut bytes_written = n.serialize(stream)?;
        for cipher in &self.data {
            bytes_written += cipher.serialize(context, stream)?;
        }
        Ok(bytes_written)
    }
    fn deserialize<T: std::io::Read>(context: &HeContext, stream: &mut T) -> std::io::Result<Self> where Self: Sized {
        let n = usize::deserialize(stream)?;
        let mut data = Vec::with_capacity(n);
        for _ in 0..n {
            data.push(Cipher2d::deserialize(context, stream)?);
        }
        Ok(Cipher3d {data})
    }
    fn serialized_size(&self, context: &HeContext) -> usize {
        let n = self.data.len();
        let mut bytes = n.serialized_size();
        for cipher in &self.data {
            bytes += cipher.serialized_size(context);
        }
        bytes
    }
}

impl Cipher3d {
    /// constructor
    pub fn new_2ds(data: Vec<Cipher2d>) -> Self {
        Cipher3d {data}
    }
    /// Serialize the Cipher2ds with only the terms specified in `terms`.
    pub fn serialize_terms<T: std::io::Write>(&self, context: &HeContext, terms: &[usize], stream: &mut T) -> std::io::Result<usize> {
        let n = self.data.len();
        let mut bytes_written = n.serialize(stream)?;
        if n == 0 {return Ok(bytes_written);}
        for cipher in &self.data {
            bytes_written += cipher.serialize_terms(context, terms, stream)?;
        }
        Ok(bytes_written)
    }
    /// See [Cipher3d::serialize_terms].
    pub fn deserialize_terms<T: std::io::Read>(context: &HeContext, terms: &[usize], stream: &mut T) -> std::io::Result<Self> where Self: Sized {
        let n = usize::deserialize(stream)?;
        let mut data = Vec::with_capacity(n);
        for _i in 0..n {
            data.push(Cipher2d::deserialize_terms(context, terms, stream)?);
        }
        Ok(Cipher3d {data})
    }
    /// Size in bytes if [Cipher3d::serialize_terms] is called.
    pub fn serialized_terms_size(&self, context: &HeContext, terms_count: usize) -> usize {
        let n = self.data.len();
        let mut bytes = n.serialized_size();
        for cipher in &self.data {
            bytes += cipher.serialized_terms_size(context, terms_count);
        }
        bytes
    }
    /// Returns the length of the first dimension.
    pub fn len(&self) -> usize {
        self.data.len()
    }
    /// Is empty?
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Cipher3d {
    /// Decrypt the 3d matrix. Wrapper of [Decryptor::decrypt_new].
    pub fn decrypt(&self, decryptor: &Decryptor) -> Plain3d {
        Plain3d {
            data: self.data.iter().map(|x| x.decrypt(decryptor)).collect::<Vec<_>>()
        }
    }
    /// Add two 3d matrices. Wrapper of [Evaluator::add_inplace].
    pub fn add_inplace(&mut self, evaluator: &Evaluator, rhs: &Cipher3d) {
        assert_eq!(rhs.data.len(), self.data.len());
        if self.data.is_empty() {return;}
        for (item, rhs_item) in self.data.iter_mut().zip(rhs.data.iter()) {
            item.add_inplace(evaluator, rhs_item);
        }
    }
    /// Add two 3d matrices, the other is Plain2d. Wrapper of [Evaluator::add_plain_inplace].
    pub fn add_plain_inplace(&mut self, evaluator: &Evaluator, rhs: &Plain3d) {
        assert_eq!(rhs.data.len(), self.data.len());
        if self.data.is_empty() {return;}
        for (item, rhs_item) in self.data.iter_mut().zip(rhs.data.iter()) {
            item.add_plain_inplace(evaluator, rhs_item);
        }
    }
    /// Rescale. Must be CKKS Cipher2ds. Wrapper of [Evaluator::rescale_to_next_inplace].
    pub fn rescale_to_next_inplace(&mut self, evaluator: &Evaluator) {
        if self.data.is_empty() {return;}
        for item in &mut self.data {
            item.rescale_to_next_inplace(evaluator);
        }
    }
}

impl std::ops::Index<usize> for Cipher3d {
    type Output = Cipher2d;
    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl std::ops::IndexMut<usize> for Cipher3d {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}
