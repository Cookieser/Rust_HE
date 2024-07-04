use crate::{
    ContextData,
    Plaintext,
    util
};

#[allow(unused)]
/** Add plain without scaling invariant */
pub fn add_plain(plain: &Plaintext, context_data: &ContextData, destination: &mut [u64]) {
    let parms = context_data.parms();
    let coeff_modulus = parms.coeff_modulus();
    let plain_coeff_count = plain.coeff_count();
    let coeff_count = parms.poly_modulus_degree();
    let coeff_modulus_size = coeff_modulus.len();
    let plain_data = plain.data();
    for i in 0..coeff_modulus_size {
        for j in 0..plain_coeff_count {
            let m = coeff_modulus[i].reduce(plain_data[j]);
            destination[i * coeff_count + j] = util::add_u64_mod(destination[i * coeff_count + j], m, &coeff_modulus[i]);
        }
    }
} 

#[allow(unused)]
/** Sub plain without scaling invariant */
pub fn sub_plain(plain: &Plaintext, context_data: &ContextData, destination: &mut [u64]) {
    let parms = context_data.parms();
    let coeff_modulus = parms.coeff_modulus();
    let plain_coeff_count = plain.coeff_count();
    let coeff_count = parms.poly_modulus_degree();
    let coeff_modulus_size = coeff_modulus.len();
    let plain_data = plain.data();
    for i in 0..coeff_modulus_size {
        for j in 0..plain_coeff_count {
            let m = coeff_modulus[i].reduce(plain_data[j]);
            destination[i * coeff_count + j] = util::sub_u64_mod(destination[i * coeff_count + j], m, &coeff_modulus[i]);
        }
    }
} 

/** Multiply add plain with scaling invariant */
pub fn multiply_add_plain(plain: &Plaintext, context_data: &ContextData, destination: &mut [u64]) {
    let parms = context_data.parms();
    let coeff_modulus = parms.coeff_modulus();
    let plain_coeff_count = plain.coeff_count();
    let coeff_count = parms.poly_modulus_degree();
    let coeff_modulus_size = coeff_modulus.len();
    let plain_modulus = parms.plain_modulus();
    let coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
    let plain_upper_half_threshold = context_data.plain_upper_half_threshold();
    let q_mod_t = context_data.coeff_modulus_mod_plain_modulus();
    // Coefficients of plain m multiplied by coeff_modulus q, divided by plain_modulus t,
    // and rounded to the nearest integer (rounded up in case of a tie). Equivalent to
    // floor((q * m + floor((t+1) / 2)) / t).
    let plain_data = plain.data();
    let mut prod = [0, 0];
    let mut numerator = [0, 0];
    let mut fix = [0, 0];
    assert!(plain_coeff_count <= coeff_count);
    assert!(plain_coeff_count <= plain_data.len());
    for i in 0..plain_coeff_count {
        // Compute numerator = (q mod t) * m[i] + (t+1)/2
        util::multiply_u64_u64(plain_data[i], q_mod_t, &mut prod);
        let carry = util::add_u64(prod[0], plain_upper_half_threshold, &mut numerator[0]);
        numerator[1] = prod[1] + carry as u64;
        // Compute fix[0] = floor(numerator / t)
        util::divide_u128_u64_inplace(&mut numerator, plain_modulus.value(), &mut fix);
        // Add to ciphertext: floor(q / t) * m + increment
        for j in 0..coeff_modulus_size {
            let scaled_rounded_coeff = util::multiply_u64operand_add_u64_mod(plain_data[i], &coeff_div_plain_modulus[j], fix[0], &coeff_modulus[j]);
            destination[j * coeff_count + i] = util::add_u64_mod(destination[j * coeff_count + i], scaled_rounded_coeff, &coeff_modulus[j]);
        }
    }
}

/** Multiply sub plain with scaling invariant */
pub fn multiply_sub_plain(plain: &Plaintext, context_data: &ContextData, destination: &mut [u64]) {
    let parms = context_data.parms();
    let coeff_modulus = parms.coeff_modulus();
    let plain_coeff_count = plain.coeff_count();
    let coeff_count = parms.poly_modulus_degree();
    let coeff_modulus_size = coeff_modulus.len();
    let plain_modulus = parms.plain_modulus();
    let coeff_div_plain_modulus = context_data.coeff_div_plain_modulus();
    let plain_upper_half_threshold = context_data.plain_upper_half_threshold();
    let q_mod_t = context_data.coeff_modulus_mod_plain_modulus();
    // Coefficients of plain m multiplied by coeff_modulus q, divided by plain_modulus t,
    // and rounded to the nearest integer (rounded up in case of a tie). Equivalent to
    // floor((q * m + floor((t+1) / 2)) / t).
    let plain_data = plain.data();
    for i in 0..plain_coeff_count {
        // Compute numerator = (q mod t) * m[i] + (t+1)/2
        let mut prod = [0, 0];
        let mut numerator = [0, 0];
        util::multiply_u64_u64(plain_data[i], q_mod_t, &mut prod);
        let carry = util::add_u64(prod[0], plain_upper_half_threshold, &mut numerator[0]);
        numerator[1] = prod[1] + carry as u64;
        // Compute fix[0] = floor(numerator / t)
        let mut fix = [0, 0];
        util::divide_u128_u64_inplace(&mut numerator, plain_modulus.value(), &mut fix);
        // Add to ciphertext: floor(q / t) * m + increment
        for j in 0..coeff_modulus_size {
            let scaled_rounded_coeff = util::multiply_u64operand_add_u64_mod(plain_data[i], &coeff_div_plain_modulus[j], fix[0],& coeff_modulus[j]);
            destination[j * coeff_count + i] = util::sub_u64_mod(destination[j * coeff_count + i], scaled_rounded_coeff, &coeff_modulus[j]);
        }
    }
}