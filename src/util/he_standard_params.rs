//! Largest allowed bit counts for coeff_modulus based on the security estimates from
//! HomomorphicEncryption.org security standard. We samples the secret key
//! from a ternary {-1, 0, 1} distribution.

/// Ternary secret; 128 bits classical security
pub fn he_standard_params_128_tc(poly_modulus_degree: usize) -> usize {
    match poly_modulus_degree {
         1024 =>  27,
         2048 =>  54,
         4096 => 109,
         8192 => 218,
        16384 => 438,
        32768 => 881,
            _ => 0
    }
}

/// Ternary secret; 192 bits classical security
pub fn he_standard_params_192_tc(poly_modulus_degree: usize) -> usize {
    match poly_modulus_degree {
         1024 =>  19,
         2048 =>  37,
         4096 =>  75,
         8192 => 152,
        16384 => 305,
        32768 => 611,
            _ => 0
    }
}

/// Ternary secret; 256 bits classical security
pub fn he_standard_params_256_tc(poly_modulus_degree: usize) -> usize {
    match poly_modulus_degree {
         1024 =>  14,
         2048 =>  29,
         4096 =>  58,
         8192 => 118,
        16384 => 237,
        32768 => 476,
            _ => 0
    }
}

/// Ternary secret; 128 bits quantum security
pub fn he_standard_params_128_tq(poly_modulus_degree: usize) -> usize {
    match poly_modulus_degree {
         1024 =>  25,
         2048 =>  51,
         4096 => 101,
         8192 => 202,
        16384 => 411,
        32768 => 827,
            _ => 0
    }
}

/// Ternary secret; 192 bits quantum security
pub fn he_standard_params_192_tq(poly_modulus_degree: usize) -> usize {
    match poly_modulus_degree {
         1024 =>  17,
         2048 =>  35,
         4096 =>  70,
         8192 => 141,
        16384 => 284,
        32768 => 571,
            _ => 0
    }
}

/// Ternary secret; 256 bits quantum security
pub fn he_standard_params_256_tq(poly_modulus_degree: usize) -> usize {
    match poly_modulus_degree {
         1024 =>  13,
         2048 =>  27,
         4096 =>  54,
         8192 => 109,
        16384 => 220,
        32768 => 443,
            _ => 0
    }
}

/// Standard deviation for the centered binomial distribution, used in sampling noises.
pub const HE_HE_STANDARD_PARAMS_ERROR_STD_DEV: f64 = 3.2;