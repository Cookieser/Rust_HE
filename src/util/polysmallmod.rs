#![allow(unused)]

use crate::Modulus;
use crate::util;

use super::MultiplyU64ModOperand;
use super::NTTTables;

pub fn modulo(component: &[u64], modulus: &Modulus, result: &mut[u64]) {
    result.iter_mut().zip(component.iter()).for_each(|(r, &c)| *r = modulus.reduce(c));
}
#[inline]
pub fn modulo_p(poly: &[u64], degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        modulo(&poly[offset..offset+degree], &moduli[i], &mut result[offset..offset+degree]);
        offset += degree;
    }
}
#[inline]
pub fn modulo_ps(polys: &[u64], pcount: usize, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        modulo_p(&polys[offset..offset+d], degree, moduli, &mut result[offset..offset+d]);
        offset += d;
    }
}

pub fn negate(component: &[u64], modulus: &Modulus, result: &mut[u64]) {
    let modulus = modulus.value();
    component.iter().zip(result.iter_mut()).for_each(|(&c, r)| *r = if c != 0 {modulus - c} else {0});
}
#[inline]
pub fn negate_p(poly: &[u64], degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        negate(&poly[offset..offset+degree], &moduli[i], &mut result[offset..offset+degree]);
        offset += degree;
    }
}
#[inline]
pub fn negate_ps(polys: &[u64], pcount: usize, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        negate_p(&polys[offset..offset+d], degree, moduli, &mut result[offset..offset+d]);
        offset += d;
    }
}

pub fn negate_inplace(component: &mut [u64], modulus: &Modulus) {
    let modulus = modulus.value();
    component.iter_mut().for_each(|c| *c = if *c != 0 {modulus - *c} else {0});
}
#[inline]
pub fn negate_inplace_p(poly: &mut [u64], degree: usize, moduli: &[Modulus]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        negate_inplace(&mut poly[offset..offset+degree], &moduli[i]);
        offset += degree;
    }
}
#[inline]
pub fn negate_inplace_ps(polys: &mut [u64], pcount: usize, degree: usize, moduli: &[Modulus]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        negate_inplace_p(&mut polys[offset..offset+d], degree, moduli);
        offset += d;
    }
}

pub fn add(comp1: &[u64], comp2: &[u64], modulus: &Modulus, result: &mut[u64]) {
    let modulus = modulus.value();
    assert!(comp1.len() >= result.len() && comp2.len() >= result.len());
    for i in 0..result.len() {
        let c = comp1[i] + comp2[i];
        result[i] = if c >= modulus {c - modulus} else {c};
    }
}
#[inline]
pub fn add_p(poly1: &[u64], poly2: &[u64], degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        add(&poly1[offset..upper], &poly2[offset..upper], &moduli[i], &mut result[offset..upper]);
        offset = upper;
    }
}
#[inline]
pub fn add_ps(polys1: &[u64], polys2: &[u64], pcount: usize, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        add_p(&polys1[offset..upper], &polys2[offset..upper], degree, moduli, &mut result[offset..upper]);
        offset = upper;
    }
}

pub fn add_inplace(comp1: &mut [u64], comp2: &[u64], modulus: &Modulus) {
    let modulus = modulus.value();
    assert!(comp2.len() >= comp1.len());
    for i in 0..comp1.len() {
        let c = comp1[i] + comp2[i];
        comp1[i] = if c >= modulus {c - modulus} else {c};
    }
}
#[inline]
pub fn add_inplace_p(poly1: &mut [u64], poly2: &[u64], degree: usize, moduli: &[Modulus]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        add_inplace(&mut poly1[offset..upper], &poly2[offset..upper], &moduli[i]);
        offset = upper;
    }
}
#[inline]
pub fn add_inplace_ps(polys1: &mut [u64], polys2: &[u64], pcount: usize, degree: usize, moduli: &[Modulus]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        add_inplace_p(&mut polys1[offset..upper], &polys2[offset..upper], degree, moduli);
        offset = upper;
    }
}

pub fn sub(comp1: &[u64], comp2: &[u64], modulus: &Modulus, result: &mut[u64]) {
    let modulus = modulus.value();
    assert!(comp1.len() >= result.len() && comp2.len() >= result.len());
    for i in 0..result.len() {
        let mut temp_result = 0;
        let borrow = util::sub_u64(comp1[i], comp2[i], &mut temp_result) != 0;
        result[i] = if borrow {temp_result.wrapping_add(modulus)} else {temp_result};
    }
}
#[inline]
pub fn sub_p(poly1: &[u64], poly2: &[u64], degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        sub(&poly1[offset..upper], &poly2[offset..upper], &moduli[i], &mut result[offset..upper]);
        offset = upper;
    }
}
#[inline]
pub fn sub_ps(polys1: &[u64], polys2: &[u64], pcount: usize, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        sub_p(&polys1[offset..upper], &polys2[offset..upper], degree, moduli, &mut result[offset..upper]);
        offset = upper;
    }
}

pub fn sub_inplace(comp1: &mut [u64], comp2: &[u64], modulus: &Modulus) {
    let modulus = modulus.value();
    assert!(comp2.len() >= comp1.len());
    for i in 0..comp1.len() {
        let mut temp_result = 0;
        let borrow = util::sub_u64(comp1[i], comp2[i], &mut temp_result) != 0;
        comp1[i] = if borrow {temp_result.wrapping_add(modulus)} else {temp_result};
    }
}
#[inline]
pub fn sub_inplace_p(poly1: &mut [u64], poly2: &[u64], degree: usize, moduli: &[Modulus]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        sub_inplace(&mut poly1[offset..upper], &poly2[offset..upper], &moduli[i]);
        offset = upper;
    }
}
#[inline]
pub fn sub_inplace_ps(polys1: &mut [u64], polys2: &[u64], pcount: usize, degree: usize, moduli: &[Modulus]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        sub_inplace_p(&mut polys1[offset..upper], &polys2[offset..upper], degree, moduli);
        offset = upper;
    }
}


pub fn add_scalar(comp: &[u64], scalar: u64, modulus: &Modulus, result: &mut[u64]) {
    result.iter_mut().zip(comp.iter()).for_each(|(r, c)| *r = util::add_u64_mod(*c, scalar, modulus));
}
#[inline]
pub fn add_scalar_p(poly: &[u64], scalar: u64, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        add_scalar(&poly[offset..upper], scalar, &moduli[i], &mut result[offset..upper]);
        offset = upper;
    }
}
#[inline]
pub fn add_scalar_ps(polys: &[u64], scalar: u64, pcount: usize, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        add_scalar_p(&polys[offset..upper], scalar, degree, moduli, &mut result[offset..upper]);
        offset = upper;
    }
}

pub fn add_scalar_inplace(comp: &mut [u64], scalar: u64, modulus: &Modulus) {
    comp.iter_mut().for_each(|c| *c = util::add_u64_mod(*c, scalar, modulus));
}
#[inline]
pub fn add_scalar_inplace_p(poly: &mut [u64], scalar: u64, degree: usize, moduli: &[Modulus]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        add_scalar_inplace(&mut poly[offset..upper], scalar, &moduli[i]);
        offset = upper;
    }
}
#[inline]
pub fn add_scalar_inplace_ps(polys: &mut [u64], scalar: u64, pcount: usize, degree: usize, moduli: &[Modulus]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        add_scalar_inplace_p(&mut polys[offset..upper], scalar, degree, moduli);
        offset = upper;
    }
}

pub fn sub_scalar(comp: &[u64], scalar: u64, modulus: &Modulus, result: &mut[u64]) {
    result.iter_mut().zip(comp.iter()).for_each(|(r, c)| *r = util::sub_u64_mod(*c, scalar, modulus));
}
#[inline]
pub fn sub_scalar_p(poly: &[u64], scalar: u64, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        sub_scalar(&poly[offset..upper], scalar, &moduli[i], &mut result[offset..upper]);
        offset = upper;
    }
}
#[inline]
pub fn sub_scalar_ps(polys: &[u64], scalar: u64, pcount: usize, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        sub_scalar_p(&polys[offset..upper], scalar, degree, moduli, &mut result[offset..upper]);
        offset = upper;
    }
}

pub fn sub_scalar_inplace(comp: &mut [u64], scalar: u64, modulus: &Modulus) {
    comp.iter_mut().for_each(|c| *c = util::sub_u64_mod(*c, scalar, modulus));
}
#[inline]
pub fn sub_scalar_inplace_p(poly: &mut [u64], scalar: u64, degree: usize, moduli: &[Modulus]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        sub_scalar_inplace(&mut poly[offset..upper], scalar, &moduli[i]);
        offset = upper;
    }
}
#[inline]
pub fn sub_scalar_inplace_ps(polys: &mut [u64], scalar: u64, pcount: usize, degree: usize, moduli: &[Modulus]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        sub_scalar_inplace_p(&mut polys[offset..upper], scalar, degree, moduli);
        offset = upper;
    }
}

pub fn multiply_scalar(comp: &[u64], scalar: u64, modulus: &Modulus, result: &mut[u64]) {
    result.iter_mut().zip(comp.iter()).for_each(|(r, c)| *r = util::multiply_u64_mod(*c, scalar, modulus));
}
#[inline]
pub fn multiply_scalar_p(poly: &[u64], scalar: u64, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        multiply_scalar(&poly[offset..upper], scalar, &moduli[i], &mut result[offset..upper]);
        offset = upper;
    }
}
#[inline]
pub fn multiply_scalar_ps(polys: &[u64], scalar: u64, pcount: usize, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        multiply_scalar_p(&polys[offset..upper], scalar, degree, moduli, &mut result[offset..upper]);
        offset = upper;
    }
}

pub fn multiply_operand(comp: &[u64], scalar: &MultiplyU64ModOperand, modulus: &Modulus, result: &mut[u64]) {
    result.iter_mut().zip(comp.iter()).for_each(|(r, c)| *r = util::multiply_u64operand_mod(*c, scalar, modulus));
}
#[inline]
pub fn multiply_operand_p(poly: &[u64], scalar: &MultiplyU64ModOperand, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        multiply_operand(&poly[offset..upper], scalar, &moduli[i], &mut result[offset..upper]);
        offset = upper;
    }
}
#[inline]
pub fn multiply_operand_ps(polys: &[u64], scalar: &MultiplyU64ModOperand, pcount: usize, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        multiply_operand_p(&polys[offset..upper], scalar, degree, moduli, &mut result[offset..upper]);
        offset = upper;
    }
}

pub fn multiply_operand_inplace(comp: &mut [u64], scalar: &MultiplyU64ModOperand, modulus: &Modulus) {
    comp.iter_mut().for_each(|c| *c = util::multiply_u64operand_mod(*c, scalar, modulus));
}
#[inline]
pub fn multiply_operand_inplace_p(poly: &mut [u64], scalar: &MultiplyU64ModOperand, degree: usize, moduli: &[Modulus]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        multiply_operand_inplace(&mut poly[offset..upper], scalar, &moduli[i]);
        offset = upper;
    }
}
#[inline]
pub fn multiply_operand_inplace_ps(polys: &mut [u64], scalar: &MultiplyU64ModOperand, pcount: usize, degree: usize, moduli: &[Modulus]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        multiply_operand_inplace_p(&mut polys[offset..upper], scalar, degree, moduli);
        offset = upper;
    }
}

#[inline]
pub fn multiply_scalar_inplace(comp: &mut [u64], scalar: u64, modulus: &Modulus) {
    comp.iter_mut().for_each(|c| *c = util::multiply_u64_mod(*c, scalar, modulus));
}
#[inline]
pub fn multiply_scalar_inplace_p(poly: &mut [u64], scalar: u64, degree: usize, moduli: &[Modulus]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        multiply_scalar_inplace(&mut poly[offset..upper], scalar, &moduli[i]);
        offset = upper;
    }
}
pub fn multiply_scalar_inplace_ps(polys: &mut [u64], scalar: u64, pcount: usize, degree: usize, moduli: &[Modulus]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        multiply_scalar_inplace_p(&mut polys[offset..upper], scalar, degree, moduli);
        offset = upper;
    }
}

pub fn dyadic_product(comp1: &[u64], comp2: &[u64], modulus: &Modulus, result: &mut[u64]) {
    let modulus_value = modulus.value();
    let cr0 = modulus.const_ratio()[0];
    let cr1 = modulus.const_ratio()[1];
    let mut z = [0, 0]; 
    let mut tmp1 = 0; 
    let mut tmp2 = [0, 0]; 
    let mut tmp3;
    let mut carry = 0;
    for i in 0..result.len() {
        // Reduces z using base 2^64 Barrett reduction
        util::multiply_u64_u64(comp1[i], comp2[i], &mut z);
        // Multiply input and const_ratio
        // Round 1
        util::multiply_u64_high_word(z[0], cr0, &mut carry);
        util::multiply_u64_u64(z[0], cr1, &mut tmp2);
        tmp3 = tmp2[1] + util::add_u64(tmp2[0], carry, &mut tmp1) as u64;
        // Round 2
        util::multiply_u64_u64(z[1], cr0, &mut tmp2);
        carry = tmp2[1] + util::add_u64(tmp1, tmp2[0], &mut tmp1) as u64;
        // This is all we care about
        tmp1 = z[1].wrapping_mul(cr1).wrapping_add(tmp3).wrapping_add(carry);
        // Barrett subtraction
        tmp3 = z[0].wrapping_sub(tmp1.wrapping_mul(modulus_value));
        // Claim: One more subtraction is enough
        result[i] = if tmp3 >= modulus_value {tmp3 - modulus_value} else {tmp3};
    }
}
#[inline]
pub fn dyadic_product_p(poly1: &[u64], poly2: &[u64], degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        dyadic_product(&poly1[offset..upper], &poly2[offset..upper], &moduli[i], &mut result[offset..upper]);
        offset = upper;
    }
}
#[inline]
pub fn dyadic_product_ps(polys1: &[u64], polys2: &[u64], pcount: usize, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        dyadic_product_p(&polys1[offset..upper], &polys2[offset..upper], degree, moduli, &mut result[offset..upper]);
        offset = upper;
    }
}

#[inline]
pub fn dyadic_product_inplace(comp1: &mut[u64], comp2: &[u64], modulus: &Modulus) {
    let modulus_value = modulus.value();
    let cr0 = modulus.const_ratio()[0];
    let cr1 = modulus.const_ratio()[1];
    let mut z = [0, 0]; 
    let mut tmp1 = 0; 
    let mut tmp2 = [0, 0]; 
    let mut tmp3;
    let mut carry = 0;
    for i in 0..comp1.len() {
        // Reduces z using base 2^64 Barrett reduction
        util::multiply_u64_u64(comp1[i], comp2[i], &mut z);
        // Multiply input and const_ratio
        // Round 1
        util::multiply_u64_high_word(z[0], cr0, &mut carry);
        util::multiply_u64_u64(z[0], cr1, &mut tmp2);
        tmp3 = tmp2[1] + util::add_u64(tmp2[0], carry, &mut tmp1) as u64;
        // Round 2
        util::multiply_u64_u64(z[1], cr0, &mut tmp2);
        carry = tmp2[1] + util::add_u64(tmp1, tmp2[0], &mut tmp1) as u64;
        // This is all we care about
        tmp1 = z[1].wrapping_mul(cr1).wrapping_add(tmp3).wrapping_add(carry);
        // Barrett subtraction
        tmp3 = z[0].wrapping_sub(tmp1.wrapping_mul(modulus_value));
        // Claim: One more subtraction is enough
        comp1[i] = if tmp3 >= modulus_value {tmp3 - modulus_value} else {tmp3};
    }
}
#[inline]
pub fn dyadic_product_inplace_p(poly1: &mut[u64], poly2: &[u64], degree: usize, moduli: &[Modulus]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        let upper = offset + degree;
        dyadic_product_inplace(&mut poly1[offset..upper], &poly2[offset..upper], &moduli[i]);
        offset = upper;
    }
}
#[inline]
pub fn dyadic_product_inplace_ps(polys1: &mut[u64], polys2: &[u64], pcount: usize, degree: usize, moduli: &[Modulus]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        let upper = offset + d;
        dyadic_product_inplace_p(&mut polys1[offset..upper], &polys2[offset..upper], degree, moduli);
        offset = upper;
    }
}

// pub fn poly_infty_norm(comp: &[u64], modulus: &Modulus) -> u64 {
//     // Construct negative threshold (first negative modulus value) to compute absolute values of coeffs.
//     let threshold = (modulus.value() + 1) >> 1;
//     // Mod out the poly coefficients and choose a symmetric representative from
//     // [-modulus,modulus). Keep track of the max.
//     let mut result = 0;
//     comp.iter().for_each(|&x| {
//         let mut poly_coeff = util::barrett_reduce_u64(x, modulus);
//         if poly_coeff >= threshold {
//             poly_coeff = modulus.value() - poly_coeff;
//         }
//         if poly_coeff > result {result = poly_coeff;}
//     });
//     result
// }

pub fn negacyclic_shift(component: &[u64], shift: usize, modulus: &Modulus, result: &mut[u64]) {
    if shift == 0 {
        util::set_uint(component, result.len(), result);
        return;
    }
    let mut index_raw = shift;
    let coeff_count = result.len();
    let coeff_count_mod_mask = coeff_count - 1;
    let modulus_value = modulus.value();
    for i in 0..coeff_count {
        let index = index_raw & coeff_count_mod_mask;
        if component[i] == 0 || (index_raw & coeff_count) == 0 {
            result[index] = component[i];
        } else {
            result[index] = modulus_value - component[i]; 
        }
        index_raw += 1;
    }
}
#[inline]
pub fn negacyclic_shift_p(poly: &[u64], shift: usize, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        negacyclic_shift(&poly[offset..offset+degree], shift, &moduli[i], &mut result[offset..offset+degree]);
        offset += degree;
    }
}
#[inline]
pub fn negacyclic_shift_ps(polys: &[u64], shift: usize, pcount: usize, degree: usize, moduli: &[Modulus], result: &mut[u64]) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        negacyclic_shift_p(&polys[offset..offset+d], shift, degree, moduli, &mut result[offset..offset+d]);
        offset += d;
    }
}


pub fn negacyclic_multiply_mononomial(
    component: &[u64], 
    mono_coeff: u64, mono_exponent: usize, 
    modulus: &Modulus, result: &mut[u64]
) {
    // FIXME: Frequent allocation
    let mut temp = vec![0; result.len()];
    multiply_scalar(component, mono_coeff, modulus, &mut temp);
    negacyclic_shift(&temp, mono_exponent, modulus, result);
}
#[inline]
pub fn negacyclic_multiply_mononomial_p(
    poly: &[u64], 
    mono_coeff: u64, mono_exponent: usize, 
    degree: usize, moduli: &[Modulus], result: &mut[u64]
) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        negacyclic_multiply_mononomial(&poly[offset..offset+degree], 
            mono_coeff, mono_exponent, 
            &moduli[i], &mut result[offset..offset+degree]);
        offset += degree;
    }
}
#[inline]
pub fn negacyclic_multiply_mononomial_ps(
    polys: &[u64], 
    mono_coeff: u64, mono_exponent: usize, 
    pcount: usize, degree: usize, moduli: &[Modulus], 
    result: &mut[u64]
) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        negacyclic_multiply_mononomial_p(&polys[offset..offset+d], 
            mono_coeff, mono_exponent, 
            degree, moduli, &mut result[offset..offset+d]);
        offset += d;
    }
}

#[inline]
pub fn negacyclic_multiply_mononomials_p(
    poly: &[u64], 
    mono_coeff: &[u64], mono_exponent: usize, 
    degree: usize, moduli: &[Modulus], result: &mut[u64]
) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        negacyclic_multiply_mononomial(&poly[offset..offset+degree], 
            mono_coeff[i], mono_exponent, 
            &moduli[i], &mut result[offset..offset+degree]);
        offset += degree;
    }
}
#[inline]
pub fn negacyclic_multiply_mononomials_ps(
    polys: &[u64], 
    mono_coeff: &[u64], mono_exponent: usize, 
    pcount: usize, degree: usize, moduli: &[Modulus], 
    result: &mut[u64]
) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        negacyclic_multiply_mononomials_p(&polys[offset..offset+d], 
            mono_coeff, mono_exponent, 
            degree, moduli, &mut result[offset..offset+d]);
        offset += d;
    }
}

pub fn negacyclic_multiply_mononomial_inplace(
    component: &mut [u64], 
    mono_coeff: u64, mono_exponent: usize, 
    modulus: &Modulus
) {
    // FIXME: Frequent allocation
    let mut temp = vec![0; component.len()];
    multiply_scalar(component, mono_coeff, modulus, &mut temp);
    negacyclic_shift(&temp, mono_exponent, modulus, component);
}
#[inline]
pub fn negacyclic_multiply_mononomial_inplace_p(
    poly: &mut [u64], 
    mono_coeff: u64, mono_exponent: usize, 
    degree: usize, moduli: &[Modulus]
) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        negacyclic_multiply_mononomial_inplace(&mut poly[offset..offset+degree], 
            mono_coeff, mono_exponent, 
            &moduli[i]);
        offset += degree;
    }
}
#[inline]
pub fn negacyclic_multiply_mononomial_inplace_ps(
    polys: &mut [u64], 
    mono_coeff: u64, mono_exponent: usize, 
    pcount: usize, degree: usize, moduli: &[Modulus]
) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        negacyclic_multiply_mononomial_inplace_p(&mut polys[offset..offset+d], 
            mono_coeff, mono_exponent, 
            degree, moduli);
        offset += d;
    }
}

#[inline]
pub fn negacyclic_multiply_mononomials_inplace_p(
    poly: &mut [u64], 
    mono_coeff: &[u64], mono_exponent: usize, 
    degree: usize, moduli: &[Modulus]
) {
    let mut offset = 0;
    for i in 0..moduli.len() {
        negacyclic_multiply_mononomial_inplace(&mut poly[offset..offset+degree], 
            mono_coeff[i], mono_exponent, 
            &moduli[i]);
        offset += degree;
    }
}
#[inline]
pub fn negacyclic_multiply_mononomials_inplace_ps(
    polys: &mut [u64], 
    mono_coeff: &[u64], mono_exponent: usize, 
    pcount: usize, degree: usize, moduli: &[Modulus], 
) {
    let d = degree * moduli.len();
    let mut offset = 0;
    for i in 0..pcount {
        negacyclic_multiply_mononomials_inplace_p(&mut polys[offset..offset+d], 
            mono_coeff, mono_exponent, 
            degree, moduli);
        offset += d;
    }
}


#[inline]
pub fn ntt_lazy(component: &mut [u64], tables: &NTTTables) {
    tables.ntt_negacyclic_harvey_lazy(component);
}
#[inline]
pub fn ntt_lazy_p(poly: &mut [u64], degree: usize, tables: &[NTTTables]) {
    let mut offset = 0;
    for i in 0..tables.len() {
        ntt_lazy(&mut poly[offset..offset+degree], &tables[i]);
        offset += degree;
    }
}
#[inline]
pub fn ntt_lazy_ps(polys: &mut [u64], pcount: usize, degree: usize, tables: &[NTTTables]) {
    let d = degree * tables.len();
    let mut offset = 0;
    for i in 0..pcount {
        ntt_lazy_p(&mut polys[offset..offset+d], degree, tables);
        offset += d;
    }
}

#[inline]
pub fn ntt(component: &mut [u64], tables: &NTTTables) {
    tables.ntt_negacyclic_harvey(component);
}
#[inline]
pub fn ntt_p(poly: &mut [u64], degree: usize, tables: &[NTTTables]) {
    let mut offset = 0;
    for i in 0..tables.len() {
        ntt(&mut poly[offset..offset+degree], &tables[i]);
        offset += degree;
    }
}
#[inline]
pub fn ntt_ps(polys: &mut [u64], pcount: usize, degree: usize, tables: &[NTTTables]) {
    let d = degree * tables.len();
    let mut offset = 0;
    for i in 0..pcount {
        ntt_p(&mut polys[offset..offset+d], degree, tables);
        offset += d;
    }
}

#[inline]
pub fn intt_lazy(component: &mut [u64], tables: &NTTTables) {
    tables.inverse_ntt_negacyclic_harvey_lazy(component);
}
#[inline]
pub fn intt_lazy_p(poly: &mut [u64], degree: usize, tables: &[NTTTables]) {
    let mut offset = 0;
    for i in 0..tables.len() {
        intt_lazy(&mut poly[offset..offset+degree], &tables[i]);
        offset += degree;
    }
}
#[inline]
pub fn intt_lazy_ps(polys: &mut [u64], pcount: usize, degree: usize, tables: &[NTTTables]) {
    let d = degree * tables.len();
    let mut offset = 0;
    for i in 0..pcount {
        intt_lazy_p(&mut polys[offset..offset+d], degree, tables);
        offset += d;
    }
}

pub fn intt(component: &mut [u64], tables: &NTTTables) {
    tables.inverse_ntt_negacyclic_harvey(component);
}
#[inline]
pub fn intt_p(poly: &mut [u64], degree: usize, tables: &[NTTTables]) {
    let mut offset = 0;
    for i in 0..tables.len() {
        intt(&mut poly[offset..offset+degree], &tables[i]);
        offset += degree;
    }
}
#[inline]
pub fn intt_ps(polys: &mut [u64], pcount: usize, degree: usize, tables: &[NTTTables]) {
    let d = degree * tables.len();
    let mut offset = 0;
    for i in 0..pcount {
        intt_p(&mut polys[offset..offset+d], degree, tables);
        offset += d;
    }
}