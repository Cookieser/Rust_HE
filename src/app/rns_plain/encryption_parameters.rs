use crate::{
    EncryptionParameters, 
    SchemeType, Modulus, ParmsID,
};

#[derive(Clone, Default)]
pub struct RnspEncryptionParameters {
    scheme: SchemeType,
    poly_modulus_degree: usize,
    coeff_modulus: Vec<Modulus>,
    plain_modulus: Vec<Modulus>,
}

#[derive(Clone)]
pub struct RnspParmsID {
    pub components: Vec<ParmsID>,
}

impl RnspEncryptionParameters {

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.plain_modulus.is_empty()
    }

    #[inline]
    pub fn scheme(&self) -> SchemeType {
        self.scheme
    }

    #[inline]
    pub fn poly_modulus_degree(&self) -> usize {
        self.poly_modulus_degree
    }

    #[inline]
    pub fn plain_modulus(&self) -> &Vec<Modulus> {
        &self.plain_modulus
    }

    #[inline]
    pub fn coeff_modulus(&self) -> &Vec<Modulus> {
        &self.coeff_modulus
    }

    pub fn new(scheme: SchemeType) -> Self {
        assert!(scheme == SchemeType::BFV || scheme == SchemeType::BGV, 
            "Currently only support BFV and BGV");
        Self {
            scheme,
            poly_modulus_degree: 0,
            coeff_modulus: Vec::new(),
            plain_modulus: Vec::new(),
        }
    }

    pub fn set_poly_modulus_degree(mut self, poly_modulus_degree: usize) -> Self {
        self.poly_modulus_degree = poly_modulus_degree;
        self
    }

    pub fn set_plain_modulus(mut self, plain_modulus: Vec<Modulus>) -> Self {
        self.plain_modulus = plain_modulus;
        self
    }

    pub fn set_coeff_modulus(mut self, coeff_modulus: Vec<Modulus>) -> Self {
        self.coeff_modulus = coeff_modulus;
        self
    }

    pub fn to_encryption_parameters(self) -> impl Iterator<Item=EncryptionParameters> {
        self.plain_modulus.into_iter().map(move |plain_modulus| {
            EncryptionParameters::new(self.scheme)
                .set_poly_modulus_degree(self.poly_modulus_degree)
                .set_plain_modulus(&plain_modulus)
                .set_coeff_modulus(&self.coeff_modulus.clone())
        })
    }

}

impl RnspParmsID {

    pub fn from_raw_parts(components: Vec<ParmsID>) -> Self {
        Self { components }
    }

}