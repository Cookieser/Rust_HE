use std::cmp::Ordering;

use crate::{
    util,
    SecurityLevel
};

/// Represent an integer modulus of up to 61 bits. 
/// 
/// An instance of the Modulus
/// class represents a non-negative integer modulus up to 61 bits. In particular,
/// the encryption parameter plain_modulus, and the primes in coeff_modulus, are
/// represented by instances of Modulus. The purpose of this class is to
/// perform and store the pre-computation required by Barrett reduction.
/// 
/// - See [EncryptionParameters](crate::EncryptionParameters) for a description of the encryption parameters.
#[derive(Debug, Eq, Clone, Copy, Default)]
pub struct Modulus {
    value: u64,
    const_ratio: [u64; 3],
    u64_count: usize,
    bit_count: usize,
    is_prime: bool,
}

impl Ord for Modulus {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}

impl PartialOrd for Modulus {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Modulus {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Modulus {

    /// Create a new Modulus instance with the given value.
    pub fn new(value: u64) -> Self {
        let mut ret = Modulus {
            value: 0,
            const_ratio: [0, 0, 0],
            u64_count: 0,
            bit_count: 0,
            is_prime: false
        };
        ret.set_value(value);
        ret
    }

    fn set_value(&mut self, new_value: u64) {
        if new_value == 0 {
            self.bit_count = 0;
            self.u64_count = 0;
            self.value = 0;
            self.const_ratio = [0; 3];
            self.is_prime = false;
        } else if (new_value >> util::HE_MOD_BIT_COUNT_MAX != 0) || (new_value == 1) {
            panic!("[Invalid argument] Value can be at most 61-bit and cannot be 1.");
        } else {
            self.value = new_value;
            self.bit_count = util::get_significant_bit_count(self.value);
            let mut numerator = [0, 0, 1]; 
            let mut quotient = [0, 0, 0];
            util::divide_u192_u64_inplace(&mut numerator, new_value, &mut quotient);
            self.const_ratio = [quotient[0], quotient[1], numerator[0]];
            self.u64_count = 1;
            self.is_prime = util::is_prime(self);
        }
    }

    /// Calculate the Barrett reduction.
    #[inline]
    pub fn reduce(&self, value: u64) -> u64 {
        util::barrett_reduce_u64(value, self)
    }

    /// Calculate the Barrett reduction on [u128].
    #[inline]
    pub fn reduce_u128(&self, value: u128) -> u64 {
        let value = [value as u64, (value >> 64) as u64];
        util::barrett_reduce_u128(&value, self)
    }

    /// Inner property.
    pub fn const_ratio(&self) -> &[u64; 3] {&self.const_ratio}
    /// The [u64] value.
    pub fn value(&self) -> u64 {self.value}
    /// Always 1.
    pub fn u64_count(&self) -> usize {1}
    /// Is the value a prime number?
    pub fn is_prime(&self) -> bool {self.is_prime}
    /// Is the value zero?
    pub fn is_zero(&self) -> bool {self.value == 0}
    /// How many bits are there in the modulus?
    pub fn bit_count(&self) -> usize {self.bit_count}


}

impl std::fmt::Display for Modulus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Modulus ({})", self.value)
    }
}

/// This class contains static methods for creating a coefficient modulus easily.
/// 
/// Note that while these functions take a [SecurityLevel] argument, all security
/// guarantees are lost if the output is used with encryption parameters with
/// a mismatching value for the poly_modulus_degree.
/// 
/// The default value [SecurityLevel::Tc128] provides a very high level of security
/// and is the default security level enforced when constructing
/// a [HeContext](crate::HeContext) object. Normal users should not have to specify the security
/// level explicitly anywhere.
pub struct CoeffModulus;

impl CoeffModulus {
    
    /// Returns the largest bit-length of the coefficient modulus, i.e., bit-length
    /// of the product of the primes in the coefficient modulus, that guarantees
    /// a given security level when using a given poly_modulus_degree, according
    /// to the HomomorphicEncryption.org security standard.
    pub fn max_bit_count(poly_modulus_degree: usize, sec_level: SecurityLevel) -> usize {
        match sec_level {
            SecurityLevel::None => i32::MAX as usize,
            SecurityLevel::Tc128 => util::he_standard_params::he_standard_params_128_tc(poly_modulus_degree),
            SecurityLevel::Tc192 => util::he_standard_params::he_standard_params_192_tc(poly_modulus_degree),
            SecurityLevel::Tc256 => util::he_standard_params::he_standard_params_256_tc(poly_modulus_degree),
        }
    }
    
    /// Returns a default coefficient modulus for the BFV scheme that guarantees
    /// a given security level when using a given poly_modulus_degree, according
    /// to the HomomorphicEncryption.org security standard. Note that all security
    /// guarantees are lost if the output is used with encryption parameters with
    /// a mismatching value for the poly_modulus_degree.
    /// 
    /// The coefficient modulus returned by this function will not perform well
    /// if used with the CKKS scheme.
    pub fn bfv_default(poly_modulus_degree: usize, sec_level: SecurityLevel) -> Vec<Modulus> {
        if Self::max_bit_count(poly_modulus_degree, sec_level) == 0 {
            panic!("[Invalid argument] Non-standard poly modulus degree.");
        }
        let moduli: Vec<u64> = match sec_level {

            SecurityLevel::None => panic!("[Invalid argument] Invalid security level."),

            SecurityLevel::Tc128 => match poly_modulus_degree {
                1024 => vec![0x7e00001],
                2048 => vec![0x3fffffff000001],
                4096 => vec![0xffffee001, 0xffffc4001, 0x1ffffe0001],
                8192 => vec![0x7fffffd8001, 0x7fffffc8001, 0xfffffffc001, 0xffffff6c001, 0xfffffebc001],
                16384 => vec![
                    0xfffffffd8001, 0xfffffffa0001, 0xfffffff00001, 0x1fffffff68001, 0x1fffffff50001,
                    0x1ffffffee8001, 0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001],
                32768 => vec![
                    0x7fffffffe90001, 0x7fffffffbf0001, 0x7fffffffbd0001, 0x7fffffffba0001, 0x7fffffffaa0001,
                    0x7fffffffa50001, 0x7fffffff9f0001, 0x7fffffff7e0001, 0x7fffffff770001, 0x7fffffff380001,
                    0x7fffffff330001, 0x7fffffff2d0001, 0x7fffffff170001, 0x7fffffff150001, 0x7ffffffef00001,
                    0xfffffffff70001],
                _ => panic!("Unreachable"),
            },

            SecurityLevel::Tc192 => match poly_modulus_degree {
                1024 => vec![0x7f001],
                2048 => vec![0x1ffffc0001],
                4096 => vec![0x1ffc001, 0x1fce001, 0x1fc0001],
                8192 => vec![0x3ffffac001, 0x3ffff54001, 0x3ffff48001, 0x3ffff28001],
                16384 => vec![
                    0x3ffffffdf0001, 0x3ffffffd48001, 0x3ffffffd20001, 0x3ffffffd18001, 0x3ffffffcd0001,
                    0x3ffffffc70001],
                32768 => vec![
                    0x3fffffffd60001, 0x3fffffffca0001, 0x3fffffff6d0001, 0x3fffffff5d0001, 0x3fffffff550001,
                    0x7fffffffe90001, 0x7fffffffbf0001, 0x7fffffffbd0001, 0x7fffffffba0001, 0x7fffffffaa0001,
                    0x7fffffffa50001],
                _ => panic!("Unreachable"),
            }

            SecurityLevel::Tc256 => match poly_modulus_degree {
                1024 => vec![0x3001],
                2048 => vec![0x1ffc0001],
                4096 => vec![0x3ffffffff040001],
                8192 => vec![0x7ffffec001, 0x7ffffb0001, 0xfffffdc001],
                16384 => vec![0x7ffffffc8001, 0x7ffffff00001, 0x7fffffe70001, 0xfffffffd8001, 0xfffffffa0001],
                32768 => vec![
                    0xffffffff00001, 0x1fffffffe30001, 0x1fffffffd80001, 0x1fffffffd10001, 0x1fffffffc50001,
                    0x1fffffffbf0001, 0x1fffffffb90001, 0x1fffffffb60001, 0x1fffffffa50001],
                _ => panic!("Unreachable"),
            }

        };
        moduli.into_iter().map(Modulus::new).collect()
    }

    /// Returns a custom coefficient modulus suitable for use with the specified
    /// poly_modulus_degree. The return value will be a vector consisting of
    /// Modulus elements representing distinct prime numbers such that:
    /// 1) have bit-lengths as given in the bit_sizes parameter (at most 60 bits) and
    /// 2) are congruent to 1 modulo 2*poly_modulus_degree.
    pub fn create(poly_modulus_degree: usize, bit_sizes: Vec<usize>) -> Vec<Modulus> {
        if !(util::HE_POLY_MOD_DEGREE_MIN..=util::HE_POLY_MOD_DEGREE_MAX).contains(&poly_modulus_degree) ||
            util::get_power_of_two(poly_modulus_degree as u64) < 0
        {
            panic!("[Invalid argument] Poly modulus degree is invalid.");
        }
        if bit_sizes.len() > util::HE_COEFF_MOD_COUNT_MAX {
            panic!("[Invalid argument] Bit sizes too many.");
        }
        if bit_sizes.len() < util::HE_COEFF_MOD_COUNT_MIN {
            panic!("[Invalid argument] Bit sizes are empty.");
        }
        if *(bit_sizes.iter().max().unwrap()) > util::HE_USER_MOD_BIT_COUNT_MAX {
            panic!("[Invalid argument] Bit sizes invalid.");
        }
        if *(bit_sizes.iter().min().unwrap()) < util::HE_USER_MOD_BIT_COUNT_MIN {
            panic!("[Invalid argument] Bit sizes invalid.");
        }
        let mut count_table = std::collections::HashMap::new();
        let mut prime_table = std::collections::HashMap::new();
        for size in &bit_sizes {
            if count_table.contains_key(size) {
                *(count_table.get_mut(size).unwrap()) += 1;
            } else {
                count_table.insert(*size, 1);
            }
        }
        let factor = 2 * poly_modulus_degree;
        for (k, v) in count_table {
            prime_table.insert(k, util::get_primes(factor as u64, k, v));
        }
        let mut result = vec![];
        for size in bit_sizes {
            let r = prime_table.get_mut(&size).unwrap();
            result.push(r.pop().unwrap());
        }
        result        
    }

    /// Returns a custom coefficient modulus suitable for use with the specified
    /// poly_modulus_degree. The return value will be a vector consisting of
    /// Modulus elements representing distinct prime numbers such that:
    /// 1) have bit-lengths as given in the bit_sizes parameter (at most 60 bits) and
    /// 2) are congruent to 1 modulo LCM(2*poly_modulus_degree, plain_modulus).
    #[deprecated = "This seem to have bugs. Use `create` instead, but make sure that plain modulus have different bit-length with the q-bits."]
    pub fn create_with_plain_modulus(poly_modulus_degree: usize, plain_modulus: &Modulus, bit_sizes: Vec<usize>) -> Vec<Modulus> {
        if !(util::HE_POLY_MOD_DEGREE_MIN..=util::HE_POLY_MOD_DEGREE_MAX).contains(&poly_modulus_degree) ||
            util::get_power_of_two(poly_modulus_degree as u64) < 0
        {
            panic!("[Invalid argument] Poly modulus degree is invalid.");
        }
        if bit_sizes.len() > util::HE_COEFF_MOD_COUNT_MAX {
            panic!("[Invalid argument] Bit sizes too many.");
        }
        if bit_sizes.len() < util::HE_COEFF_MOD_COUNT_MIN {
            panic!("[Invalid argument] Bit sizes are empty.");
        }
        if *(bit_sizes.iter().max().unwrap()) > util::HE_USER_MOD_BIT_COUNT_MAX {
            panic!("[Invalid argument] Bit sizes invalid.");
        }
        if *(bit_sizes.iter().min().unwrap()) < util::HE_USER_MOD_BIT_COUNT_MIN {
            panic!("[Invalid argument] Bit sizes invalid.");
        }
        let mut count_table = std::collections::HashMap::new();
        let mut prime_table = std::collections::HashMap::new();
        for size in &bit_sizes {
            if count_table.contains_key(size) {
                *(count_table.get_mut(size).unwrap()) += 1;
            } else {
                count_table.insert(*size, 1);
            }
        }
        let mut factor = 2 * poly_modulus_degree as u64;
        factor *= plain_modulus.value() / util::gcd(plain_modulus.value(), factor);
        for (k, v) in count_table {
            prime_table.insert(k, util::get_primes(factor, k, v));
        }
        let mut result = vec![];
        for size in bit_sizes {
            let r = prime_table.get_mut(&size).unwrap();
            result.push(r.pop().unwrap());
        }
        result        
    }

}

/// This class contains static methods for creating a plaintext modulus easily.
pub struct PlainModulus {}

impl PlainModulus {

    /// Creates a plaintext modulus supporting batching in BFV/BGV.
    pub fn batching(poly_modulus_degree: usize, bit_size: usize) -> Modulus {
        let r = CoeffModulus::create(poly_modulus_degree, vec![bit_size]);
        r.into_iter().next().unwrap()
    }

    /// Creates multiple plaintext moduli supporting batching in BFV/BGV.
    pub fn batching_multiple(poly_modulus_degree: usize, bit_sizes: Vec<usize>) -> Vec<Modulus> {
        CoeffModulus::create(poly_modulus_degree, bit_sizes)
    }  

}

#[cfg(test)]
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    pub fn test_create_modulus() {
        let closure =
        |modulus: u64, bit_count: usize, const_ratio: [u64; 3], is_prime: bool| {
            let m = Modulus::new(modulus);
            assert_eq!(m.value(), modulus);
            assert_eq!(m.bit_count(), bit_count);
            assert_eq!(m.const_ratio(), &const_ratio);
            assert_eq!(m.is_prime(), is_prime);
        };
        closure(0, 0, [0, 0, 0], false);
        closure(3, 2, [6148914691236517205, 6148914691236517205, 1], true);
        closure(0xF00000F00000F, 52, [1224979098644774929, 4369, 281470698520321], false);
        closure(0xF00000F000079, 52, [1224979096621368355, 4369, 1144844808538997], true);
    }

    
    #[test]
    pub fn test_compare_modulus() {
        let sm0 = Modulus::default();
        let sm2 = Modulus::new(2);
        let sm5 = Modulus::new(5);
        assert!(sm0 >= sm0);
        assert!(sm0 == sm0);
        assert!(sm0 <= sm0);
        assert!(sm0 >= sm0);
        assert!(sm0 <= sm0);

        assert!(sm5 >= sm5);
        assert!(sm5 == sm5);
        assert!(sm5 <= sm5);
        assert!(sm5 >= sm5);
        assert!(sm5 <= sm5);

        assert!(sm5 >= sm2);
        assert!(sm5 != sm2);
        assert!(sm5 > sm2);
        assert!(sm5 >= sm2);
        assert!(sm5 > sm2);
    }

    #[test]
    pub fn test_custom() {
        let cm = CoeffModulus::create(2, vec![3]);
        assert_eq!(1, cm.len());
        assert_eq!(5, cm[0].value());

        let cm = CoeffModulus::create(2, vec![3, 4]);
        assert_eq!(2, cm.len());
        assert_eq!(5, cm[0].value());
        assert_eq!(13, cm[1].value());

        let cm = CoeffModulus::create(2, vec![3, 5, 4, 5]);
        assert_eq!(4, cm.len());
        assert_eq!(5, cm[0].value());
        assert_eq!(17, cm[1].value());
        assert_eq!(13, cm[2].value());
        assert_eq!(29, cm[3].value());

        let cm = CoeffModulus::create(32, vec![30, 40, 30, 30, 40]);
        assert_eq!(5, cm.len());
        assert_eq!(30, util::get_significant_bit_count(cm[0].value()));
        assert_eq!(40, util::get_significant_bit_count(cm[1].value()));
        assert_eq!(30, util::get_significant_bit_count(cm[2].value()));
        assert_eq!(30, util::get_significant_bit_count(cm[3].value()));
        assert_eq!(40, util::get_significant_bit_count(cm[4].value()));
        assert_eq!(1, cm[0].value() % 64);
        assert_eq!(1, cm[1].value() % 64);
        assert_eq!(1, cm[2].value() % 64);
        assert_eq!(1, cm[3].value() % 64);
        assert_eq!(1, cm[4].value() % 64);

        let cm = CoeffModulus::create_with_plain_modulus(2, &Modulus::new(4), vec![3]);
        assert_eq!(1, cm.len());
        assert_eq!(5, cm[0].value());

        let cm = CoeffModulus::create_with_plain_modulus(2, &Modulus::new(4), vec![3, 4]);
        assert_eq!(2, cm.len());
        assert_eq!(5, cm[0].value());
        assert_eq!(13, cm[1].value());

        let cm = CoeffModulus::create_with_plain_modulus(2, &Modulus::new(4), vec![3, 5, 4, 5]);
        assert_eq!(4, cm.len());
        assert_eq!(5, cm[0].value());
        assert_eq!(17, cm[1].value());
        assert_eq!(13, cm[2].value());
        assert_eq!(29, cm[3].value());

        let cm = CoeffModulus::create_with_plain_modulus(32, &Modulus::new(64), vec![30, 40, 30, 30, 40]);
        assert_eq!(5, cm.len());
        assert_eq!(30, util::get_significant_bit_count(cm[0].value()));
        assert_eq!(40, util::get_significant_bit_count(cm[1].value()));
        assert_eq!(30, util::get_significant_bit_count(cm[2].value()));
        assert_eq!(30, util::get_significant_bit_count(cm[3].value()));
        assert_eq!(40, util::get_significant_bit_count(cm[4].value()));
        assert_eq!(1, cm[0].value() % 64);
        assert_eq!(1, cm[1].value() % 64);
        assert_eq!(1, cm[2].value() % 64);
        assert_eq!(1, cm[3].value() % 64);
        assert_eq!(1, cm[4].value() % 64);

        let cm = CoeffModulus::create_with_plain_modulus(1024, &Modulus::new(255), vec![22, 22]);
        assert_eq!(2, cm.len());
        assert_eq!(22, util::get_significant_bit_count(cm[0].value()));
        assert_eq!(22, util::get_significant_bit_count(cm[1].value()));
        assert_eq!(3133441, cm[0].value());
        assert_eq!(3655681, cm[1].value());
    }
}
