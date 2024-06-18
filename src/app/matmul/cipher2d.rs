
use crate::{
    Ciphertext, Decryptor, Encryptor, Evaluator, ExpandSeed, HeContext, Plaintext, Serializable, SerializableWithHeContext
};
use super::cipher1d::{Cipher1d, Plain1d};

/// Represent encoded matrices of inputs, weights or outputs.
#[derive(Clone)]
pub struct Plain2d {
    #[allow(missing_docs)]
    pub data: Vec<Plain1d>,
}

/// Represent encrypted matrices of inputs, weights or outputs.
#[derive(Clone)]
pub struct Cipher2d {
    #[allow(missing_docs)]
    pub data: Vec<Cipher1d>,
}

impl IntoIterator for Plain2d {
    type Item = Plain1d;
    type IntoIter = std::vec::IntoIter<Plain1d>;
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl IntoIterator for Cipher2d {
    type Item = Cipher1d;
    type IntoIter = std::vec::IntoIter<Cipher1d>;
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl Plain2d {
    /// constructor
    pub fn new_1ds(data: Vec<Plain1d>) -> Self {
        Plain2d {data}
    }
    /// constructor
    pub fn new(data: Vec<Vec<Plaintext>>) -> Self {
        Plain2d {
            data: data.into_iter().map(Plain1d::new).collect::<Vec<_>>()
        }
    }
    /// Encrypt the 2d matrix. Wrapper of [Encryptor::encrypt_new].
    pub fn encrypt(&self, encryptor: &Encryptor) -> Cipher2d {
        Cipher2d {
            data: self.data.iter().map(|x| x.encrypt(encryptor)).collect::<Vec<_>>()
        }
    }
    /// Encrypt the 2d matrix with symmetric encryption. Wrapper of [Encryptor::encrypt_symmetric_new].
    pub fn encrypt_symmetric(&self, encryptor: &Encryptor) -> Cipher2d {
        Cipher2d {
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
    /// Iterator
    pub fn iter(&self) -> std::slice::Iter<Plain1d> {
        self.data.iter()
    }
    /// Iterator
    pub fn iter_mut(&mut self) -> std::slice::IterMut<Plain1d> {
        self.data.iter_mut()
    }
}

impl std::ops::Index<usize> for Plain2d {
    type Output = Plain1d;
    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl std::ops::IndexMut<usize> for Plain2d {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl Serializable for Plain2d {
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
            data.push(Plain1d::deserialize(stream)?);
        }
        Ok(Plain2d {data})
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

impl ExpandSeed for Cipher2d {
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

impl SerializableWithHeContext for Cipher2d {
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
            data.push(Cipher1d::deserialize(context, stream)?);
        }
        Ok(Cipher2d {data})
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

impl Cipher2d {
    /// constructor
    pub fn new_1ds(data: Vec<Cipher1d>) -> Self {
        Cipher2d {data}
    }
    /// constructor
    pub fn new(data: Vec<Vec<Ciphertext>>) -> Self {
        Cipher2d {
            data: data.into_iter().map(Cipher1d::new).collect::<Vec<_>>()
        }
    }
    /// Serialize the Cipher1ds with only the terms specified in `terms`.
    pub fn serialize_terms<T: std::io::Write>(&self, context: &HeContext, terms: &[usize], stream: &mut T) -> std::io::Result<usize> {
        let n = self.data.len();
        let mut bytes_written = n.serialize(stream)?;
        if n == 0 {return Ok(bytes_written);}
        for cipher in &self.data {
            bytes_written += cipher.serialize_terms(context, terms, stream)?;
        }
        Ok(bytes_written)
    }
    /// See [Cipher2d::serialize_terms].
    pub fn deserialize_terms<T: std::io::Read>(context: &HeContext, terms: &[usize], stream: &mut T) -> std::io::Result<Self> where Self: Sized {
        let n = usize::deserialize(stream)?;
        let mut data = Vec::with_capacity(n);
        for _i in 0..n {
            data.push(Cipher1d::deserialize_terms(context, terms, stream)?);
        }
        Ok(Cipher2d {data})
    }
    /// Size in bytes if [Cipher2d::serialize_terms] is called.
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
    /// Iterator
    pub fn iter(&self) -> std::slice::Iter<Cipher1d> {
        self.data.iter()
    }
    /// Iterator
    pub fn iter_mut(&mut self) -> std::slice::IterMut<Cipher1d> {
        self.data.iter_mut()
    }
}

impl Cipher2d {
    /// Decrypt the 2d matrix. Wrapper of [Decryptor::decrypt_new].
    pub fn decrypt(&self, decryptor: &Decryptor) -> Plain2d {
        Plain2d {
            data: self.data.iter().map(|x| x.decrypt(decryptor)).collect::<Vec<_>>()
        }
    }
    /// Add two 2d matrices. Wrapper of [Evaluator::add_inplace].
    pub fn add_inplace(&mut self, evaluator: &Evaluator, rhs: &Cipher2d) {
        assert_eq!(rhs.data.len(), self.data.len());
        if self.data.is_empty() {return;}
        for (item, rhs_item) in self.data.iter_mut().zip(rhs.data.iter()) {
            item.add_inplace(evaluator, rhs_item);
        }
    }
    /// Add two 2d matrices, the other is Plain1d. Wrapper of [Evaluator::add_plain_inplace].
    pub fn add_plain_inplace(&mut self, evaluator: &Evaluator, rhs: &Plain2d) {
        assert_eq!(rhs.data.len(), self.data.len());
        if self.data.is_empty() {return;}
        for (item, rhs_item) in self.data.iter_mut().zip(rhs.data.iter()) {
            item.add_plain_inplace(evaluator, rhs_item);
        }
    }
    /// Rescale. Must be CKKS Cipher1ds. Wrapper of [Evaluator::rescale_to_next_inplace].
    pub fn rescale_to_next_inplace(&mut self, evaluator: &Evaluator) {
        if self.data.is_empty() {return;}
        for item in &mut self.data {
            item.rescale_to_next_inplace(evaluator);
        }
    }
}

impl std::ops::Index<usize> for Cipher2d {
    type Output = Cipher1d;
    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl std::ops::IndexMut<usize> for Cipher2d {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}
