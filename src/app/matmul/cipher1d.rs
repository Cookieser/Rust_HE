
use crate::{
    HeContext,
    Plaintext, Ciphertext,
    Encryptor, Decryptor, Evaluator, 
    Serializable, SerializableWithHeContext, ExpandSeed,
};

/// Represent encoded matrices of inputs, weights or outputs.
#[derive(Clone)]
pub struct Plain1d {
    #[allow(missing_docs)]
    pub data: Vec<Plaintext>,
}

/// Represent encrypted matrices of inputs, weights or outputs.
#[derive(Clone)]
pub struct Cipher1d {
    #[allow(missing_docs)]
    pub data: Vec<Ciphertext>,
}

impl IntoIterator for Plain1d {
    type Item = Plaintext;
    type IntoIter = std::vec::IntoIter<Plaintext>;
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl IntoIterator for Cipher1d {
    type Item = Ciphertext;
    type IntoIter = std::vec::IntoIter<Ciphertext>;
    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl Plain1d {
    /// constructor
    pub fn new(data: Vec<Plaintext>) -> Self {
        Plain1d {data}
    }
    /// Encrypt the 1d matrix. Wrapper of [Encryptor::encrypt_new].
    pub fn encrypt(&self, encryptor: &Encryptor) -> Cipher1d {
        Cipher1d {
            data: self.data.iter().map(|x| encryptor.encrypt_new(x)).collect::<Vec<_>>()
        }
    }
    /// Encrypt the 1d matrix with symmetric encryption. Wrapper of [Encryptor::encrypt_symmetric_new].
    pub fn encrypt_symmetric(&self, encryptor: &Encryptor) -> Cipher1d {
        Cipher1d {
            data: self.data.iter().map(|x| encryptor.encrypt_symmetric_new(x)).collect::<Vec<_>>()
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
    pub fn iter(&self) -> std::slice::Iter<Plaintext> {
        self.data.iter()
    }
    /// Iterator
    pub fn iter_mut(&mut self) -> std::slice::IterMut<Plaintext> {
        self.data.iter_mut()
    }
}

impl std::ops::Index<usize> for Plain1d {
    type Output = Plaintext;
    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl std::ops::IndexMut<usize> for Plain1d {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl Serializable for Plain1d {
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
            data.push(Plaintext::deserialize(stream)?);
        }
        Ok(Plain1d {data})
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

impl ExpandSeed for Cipher1d {
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

impl SerializableWithHeContext for Cipher1d {
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
            data.push(Ciphertext::deserialize(context, stream)?);
        }
        Ok(Cipher1d {data})
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

impl Cipher1d {
    /// constructor
    pub fn new(data: Vec<Ciphertext>) -> Self {
        Cipher1d {data}
    }
    /// Serialize the ciphertexts with only the terms specified in `terms`.
    pub fn serialize_terms<T: std::io::Write>(&self, context: &HeContext, terms: &[usize], stream: &mut T) -> std::io::Result<usize> {
        let n = self.data.len();
        let mut bytes_written = n.serialize(stream)?;
        if n == 0 {return Ok(bytes_written);}
        for cipher in &self.data {
            bytes_written += cipher.serialize_terms(context, terms, stream)?;
        }
        Ok(bytes_written)
    }
    /// See [Cipher1d::serialize_terms].
    pub fn deserialize_terms<T: std::io::Read>(context: &HeContext, terms: &[usize], stream: &mut T) -> std::io::Result<Self> where Self: Sized {
        let n = usize::deserialize(stream)?;
        let mut data = Vec::with_capacity(n);
        for _i in 0..n {
            data.push(Ciphertext::deserialize_terms(context, terms, stream)?);
        }
        Ok(Cipher1d {data})
    }
    /// Size in bytes if [Cipher1d::serialize_terms] is called.
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
    pub fn iter(&self) -> std::slice::Iter<Ciphertext> {
        self.data.iter()
    }
    /// Iterator
    pub fn iter_mut(&mut self) -> std::slice::IterMut<Ciphertext> {
        self.data.iter_mut()
    }
}

impl Cipher1d {
    /// Decrypt the 1d matrix. Wrapper of [Decryptor::decrypt_new].
    pub fn decrypt(&self, decryptor: &Decryptor) -> Plain1d {
        Plain1d {
            data: self.data.iter().map(|x| decryptor.decrypt_new(x)).collect::<Vec<_>>()
        }
    }
    /// Add two 1d matrices. Wrapper of [Evaluator::add_inplace].
    pub fn add_inplace(&mut self, evaluator: &Evaluator, rhs: &Cipher1d) {
        assert_eq!(rhs.data.len(), self.data.len());
        if self.data.is_empty() {return;}
        for (item, rhs_item) in self.data.iter_mut().zip(rhs.data.iter()) {
            evaluator.add_inplace(item, rhs_item);
        }
    }
    /// Add two 1d matrices, the other is plaintext. Wrapper of [Evaluator::add_plain_inplace].
    pub fn add_plain_inplace(&mut self, evaluator: &Evaluator, rhs: &Plain1d) {
        assert_eq!(rhs.data.len(), self.data.len());
        if self.data.is_empty() {return;}
        for (item, rhs_item) in self.data.iter_mut().zip(rhs.data.iter()) {
            evaluator.add_plain_inplace(item, rhs_item);
        }
    }
    /// Rescale. Must be CKKS ciphertexts. Wrapper of [Evaluator::rescale_to_next_inplace].
    pub fn rescale_to_next_inplace(&mut self, evaluator: &Evaluator) {
        if self.data.is_empty() {return;}
        for item in &mut self.data {
            evaluator.rescale_to_next_inplace(item);
        }
    }
}

impl std::ops::Index<usize> for Cipher1d {
    type Output = Ciphertext;
    fn index(&self, index: usize) -> &Self::Output {
        &self.data[index]
    }
}

impl std::ops::IndexMut<usize> for Cipher1d {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl FromIterator<Plaintext> for Plain1d {
    fn from_iter<T: IntoIterator<Item=Plaintext>>(iter: T) -> Self {
        Plain1d {data: iter.into_iter().collect()}
    }
}

impl FromIterator<Ciphertext> for Cipher1d {
    fn from_iter<T: IntoIterator<Item=Ciphertext>>(iter: T) -> Self {
        Cipher1d {data: iter.into_iter().collect()}
    }
}