
#[derive(Clone, Copy, PartialEq, Debug, serde::Serialize, serde::Deserialize)]

/// Describes the type of encryption scheme to be used.
#[derive(Default)]
pub enum SchemeType {
    /// Fallback. Not valid for encryption.
    #[default]
    None,
    /// Brakerski/Fan-Vercauteren Scheme.
    /// - The original paper: [Somewhat Practical Fully Homomorphic Encryption](https://eprint.iacr.org/2012/144)
    /// - BEHV RNS-BFV: [A Full RNS Variant of FV like Somewhat Homomorphic Encryption Schemes](https://eprint.iacr.org/2016/510)
    BFV,
    /// Cheon-Kim-Kim-Song Scheme.
    /// - The original paper: [Homomorphic Encryption for Arithmetic of Approximate Numbers](https://eprint.iacr.org/2016/421)
    /// - RNS-CKKS: [A Full RNS Variant of Approximate Homomorphic Encryption](https://eprint.iacr.org/2018/931)
    CKKS,
    /// Brakerski-Gentry-Vaikuntanathan Scheme.
    /// - The original paper: [(Leveled) Fully Homomorphic Encryption without Bootstrapping](https://eprint.iacr.org/2011/277)
    BGV
}

impl From<SchemeType> for u8 {
    fn from(val: SchemeType) -> Self {
        match val {
            SchemeType::None => 0,
            SchemeType::BFV => 1,
            SchemeType::CKKS => 2,
            SchemeType::BGV => 3
        }
    }
}

impl From<u8> for SchemeType {
    fn from(value: u8) -> Self {
        match value {
            0 => SchemeType::None,
            1 => SchemeType::BFV,
            2 => SchemeType::CKKS,
            3 => SchemeType::BGV,
            _ => panic!("[Invalid argument] Invalid scheme type.")
        }
    }
}



/// A unique identifier for a set (level) of encryption parameters.
pub type ParmsID = crate::util::hash::HashBlock;

/// The default zero ParmsID. Also used for non-NTT form plaintexts.
pub const PARMS_ID_ZERO: ParmsID = crate::util::hash::HASH_ZERO_BLOCK;

use crate::Modulus;
use crate::util;

/// A set of parameters defining the encryption scheme.
/// 
/// It includes [SchemeType], polynomial modulus degree, coefficient moduli chain
/// and for BFV/BGV, plain modulus.
#[derive(Default, Clone, Debug)]
pub struct EncryptionParameters {
    scheme: SchemeType,
    poly_modulus_degree: usize,
    coeff_modulus: Vec<Modulus>,
    // There is a UniformRandomGeneratorFactory in original C++-SEAL
    plain_modulus: Modulus,
    parms_id: ParmsID,
}

impl EncryptionParameters {

    /// What HE scheme do we use?
    pub fn scheme(&self) -> SchemeType {self.scheme}

    /// Polynomial modulus degree N. The HE scheme operates
    /// on the polynomial ring Z_q\[X\]/(X^N + 1).
    pub fn poly_modulus_degree(&self) -> usize {self.poly_modulus_degree}

    /// Coefficient moduli chain, defining the coefficient modulus q = q_0 * q_1 * ... * q_k.
    /// The HE scheme operates on the polynomial ring Z_q\[X\]/(X^N + 1).
    pub fn coeff_modulus(&self) -> &Vec<Modulus> {
        &self.coeff_modulus
    }

    /// Plain modulus t. For BFV/BGV, the plaintext space is Z_t\[X\]/(X^N + 1).
    pub fn plain_modulus(&self) -> &Modulus {
        &self.plain_modulus
    }

    /// The unique identifier for the encryption parameters.
    pub fn parms_id(&self) -> &ParmsID {
        &self.parms_id
    }

    /// Creates a new EncryptionParameters object with the specified scheme.
    /// Usually the user just set the params after creating an instance.
    /// ```rust
    /// # use heathcliff::*;
    /// let poly_modulus_degree = 8192;
    /// let parms = EncryptionParameters::new(SchemeType::BFV)
    ///     .set_poly_modulus_degree(poly_modulus_degree)
    ///     .set_coeff_modulus(&CoeffModulus::create(poly_modulus_degree, vec![60, 40, 40, 60]))
    ///     .set_plain_modulus(&PlainModulus::batching(poly_modulus_degree, 20));
    /// let context = HeContext::new(parms, true, SecurityLevel::Tc128);
    /// ```
    pub fn new(scheme: SchemeType) -> Self {
        let mut ret = EncryptionParameters {
            scheme,
            coeff_modulus: vec![],
            poly_modulus_degree: 0,
            plain_modulus: Modulus::new(0),
            parms_id: PARMS_ID_ZERO
        };
        ret.compute_parms_id();
        ret
    }

    /// See [EncryptionParameters::new] for an example.
    pub fn set_poly_modulus_degree(mut self, poly_modulus_degree: usize) -> Self {
        if let SchemeType::None = self.scheme {
            if poly_modulus_degree > 0 {
                panic!("[Logic error] Poly modulus degree is not supported for this scheme.");
            }
        }
        self.poly_modulus_degree = poly_modulus_degree;
        self.compute_parms_id();
        self
    }

    /// See [EncryptionParameters::new] for an example.
    pub fn set_coeff_modulus(mut self, coeff_modulus: &[Modulus]) -> Self {
        if let SchemeType::None = self.scheme {
            if !coeff_modulus.is_empty() {
                panic!("[Logic error] Coeff_modulus is not supported for this scheme.");
            }
        }
        if coeff_modulus.len() > util::HE_COEFF_MOD_COUNT_MAX || coeff_modulus.len() < util::HE_COEFF_MOD_COUNT_MIN {
            panic!("[Invalid argument] Coeff modulus is invalid.");
        }
        self.coeff_modulus = coeff_modulus.to_vec();
        self.compute_parms_id();
        self
    }

    /// See [EncryptionParameters::new] for an example.
    pub fn set_plain_modulus(mut self, plain_modulus: &Modulus) -> Self {
        match self.scheme {
            SchemeType::BFV | SchemeType::BGV => (),
            _ => {
                if !plain_modulus.is_zero() {
                    panic!("[Logic error] Plain modulus is not supported for this scheme.");
                }
            }
        }
        self.plain_modulus = *plain_modulus;
        self.compute_parms_id();
        self
    }

    /// See [EncryptionParameters::new] for an example. This is a shortcut for
    /// [EncryptionParameters::set_plain_modulus].
    pub fn set_plain_modulus_u64(self, plain_modulus: u64) -> Self {
        self.set_plain_modulus(&Modulus::new(plain_modulus))
    }

    fn compute_parms_id(&mut self) {
        let coeff_modulus_size = self.coeff_modulus.len();
        let total_u64_count =
            1 + // scheme
            1 + // poly_modulus_degree
            coeff_modulus_size + self.plain_modulus.u64_count();
        let mut param_data = vec![0; total_u64_count];
        let mut i = 0;
        param_data[i] = self.scheme as u64; i += 1;
        param_data[i] = self.poly_modulus_degree as u64; i += 1;
        self.coeff_modulus.iter().for_each(|x| {
            param_data[i] = x.value(); i += 1;
        });
        assert_eq!(self.plain_modulus.u64_count(), 1);
        param_data[i] = self.plain_modulus.value();
        util::hash::hash(&param_data, &mut self.parms_id);
        // Did we somehow manage to get a zero block as result? This is reserved for
        // plaintexts to indicate non-NTT-transformed form.
        if self.parms_id == PARMS_ID_ZERO {
            panic!("[Logic error] Parm_id cannot be zero.");
        }
    }

}

/// Represents a standard security level according to the HomomorphicEncryption.org
/// security standard. 
/// 
/// Normal users should not
/// have to specify the security level explicitly anywhere.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SecurityLevel {
    /// No security guaranteed.
    None = 0,
    /// 128-bit classical security.
    Tc128 = 128,
    /// 192-bit classical security.
    Tc192 = 192,
    /// 256-bit classical security.
    Tc256 = 256
}

impl Default for SecurityLevel {
    fn default() -> Self {Self::None}
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ErrorType {
    /** 
    constructed but not yet validated
    */
    None = -1,

    /**
    valid
    */
    Success = 0,

    /**
    scheme must be BFV or CKKS or BGV
    */
    InvalidScheme,
    
    /** 
    coeff_modulus's primes' count is not bounded by HE_COEFF_MOD_COUNT_MIN(MAX)
    */
    InvalidCoeffModulusSize, 
    
    /** 
    coeff_modulus's primes' bit counts are not bounded by HE_USER_MOD_BIT_COUNT_MIN(MAX)
    */
    InvalidCoeffModulusBitCount,

    /**
    coeff_modulus's primes are not congruent to 1 modulo (2 * poly_modulus_degree)
    */
    InvalidCoeffModulusNoNTT = 4,

    /**
    poly_modulus_degree is not bounded by HE_POLY_MOD_DEGREE_MIN(MAX)
    */
    InvalidPolyModulusDegree = 5,

    /**
    poly_modulus_degree is not a power of two
    */
    InvalidPolyModulusDegreeNonPowerOfTwo = 6,

    /**
    parameters are too large to fit in size_t type
    */
    InvalidParametersTooLarge = 7,

    /**
    parameters are not compliant with HomomorphicEncryption.org security standard
    */
    InvalidParametersInsecure = 8,

    /**
    RNSBase cannot be constructed
    */
    FailedCreatingRNSBase = 9,

    /**
    plain_modulus's bit count is not bounded by HE_PLAIN_MOD_BIT_COUNT_MIN(MAX)
    */
    InvalidPlainModulusBitCount = 10,

    /**
    plain_modulus is not coprime to coeff_modulus
    */
    InvalidPlainModulusCoprimality = 11,

    /**
    plain_modulus is not smaller than coeff_modulus
    */
    InvalidPlainModulusTooLarge = 12,

    /**
    plain_modulus is not zero
    */
    InvalidPlainModulusNonzero = 13,

    /**
    RNSTool cannot be constructed
    */
    FailedCreatingRNSTool = 14,
}

impl Default for ErrorType {
    fn default() -> Self {
        Self::None
    }
}


/// Stores a set of attributes (qualifiers) of a set of [EncryptionParameters].
/// 
/// These parameters are mainly used internally in various parts of the library,
/// e.g., to determine which algorithmic optimizations the current support. The
/// qualifiers are automatically created by the [crate::HeContext] class, silently passed
/// on to classes such as [crate::Encryptor], [crate::Evaluator], and [crate::Decryptor], and the only way to
/// change them is by changing the encryption parameters themselves. In other
/// words, a user will never have to create their own instance of this class, and
/// in most cases never have to worry about it at all.
#[derive(Default, Debug)]
pub struct EncryptionParameterQualifiers {
    /**
    The variable parameter_error is set to:
    - none, if parameters are not validated;
    - success, if parameters are considered valid by Microsoft SEAL;
    - other values, if parameters are validated and invalid.
    */
    pub parameter_error: ErrorType,
    /**
    Tells whether FFT can be used for polynomial multiplication. If the
    polynomial modulus is of the form X^N+1, where N is a power of two, then
    FFT can be used for fast multiplication of polynomials modulo the polynomial
    modulus. In this case the variable using_fft will be set to true. However,
    currently Microsoft SEAL requires this to be the case for the parameters
    to be valid. Therefore, parameters_set can only be true if using_fft is
    true.
    */
    pub using_fft: bool,
    /**
    Tells whether NTT can be used for polynomial multiplication. If the primes
    in the coefficient modulus are congruent to 1 modulo 2N, where X^N+1 is the
    polynomial modulus and N is a power of two, then the number-theoretic
    transform (NTT) can be used for fast multiplications of polynomials modulo
    the polynomial modulus and coefficient modulus. In this case the variable
    using_ntt will be set to true. However, currently Microsoft SEAL requires
    this to be the case for the parameters to be valid. Therefore, parameters_set
    can only be true if using_ntt is true.
    */
    pub using_ntt: bool,
    /**
    Tells whether batching is supported by the encryption parameters. If the
    plaintext modulus is congruent to 1 modulo 2N, where X^N+1 is the polynomial
    modulus and N is a power of two, then it is possible to use the BatchEncoder
    class to view plaintext elements as 2-by-(N/2) matrices of integers modulo
    the plaintext modulus. This is called batching, and allows the user to
    operate on the matrix elements (slots) in a SIMD fashion, and rotate the
    matrix rows and columns. When the computation is easily vectorizable, using
    batching can yield a huge performance boost. If the encryption parameters
    support batching, the variable using_batching is set to true.
    */
    pub using_batching: bool,

    /**
    Tells whether fast plain lift is supported by the encryption parameters.
    A certain performance optimization in multiplication of a ciphertext by
    a plaintext [crate::Evaluator::multiply_plain] and in transforming a plaintext
    element to NTT domain [crate::Evaluator::transform_to_ntt] can be used when the
    plaintext modulus is smaller than each prime in the coefficient modulus.
    In this case the variable using_fast_plain_lift is set to true.
    */
    pub using_fast_plain_lift: bool,
    /**
    Tells whether the coefficient modulus consists of a set of primes that
    are in decreasing order. If this is true, certain modular reductions in
    base conversion can be omitted, improving performance.
    */
    pub using_descending_modulus_chain: bool,
    /**
    Tells whether the encryption parameters are secure based on the standard
    parameters from HomomorphicEncryption.org security standard.
    */
    pub sec_level: SecurityLevel
}

impl EncryptionParameterQualifiers {

    /// Are the parameters correctly set to enable HE?
    #[inline]
    pub fn parameters_set(&self) -> bool {
        matches!(self.parameter_error, ErrorType::Success)
    }

}