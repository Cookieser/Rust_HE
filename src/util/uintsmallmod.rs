#![allow(unused)]

use crate::modulus::Modulus;
use crate::util;

use super::try_invert_u64_mod_u64;

/** `operand` must be at most (2 * modulus - 2) */
#[inline]
pub fn increment_u64_mod(mut operand: u64, modulus: &Modulus) -> u64 {
    operand += 1;
    if operand >= modulus.value() {operand - modulus.value()} else {operand}
}

/** `operand` must be at most (modulus - 1) */
#[inline]
pub fn decrement_u64_mod(operand: u64, modulus: &Modulus) -> u64 {
    if operand == 0 {modulus.value() - 1} else {operand - 1}
}

/** `operand` must be at most modulus */
#[inline]
pub fn negate_u64_mod(operand: u64, modulus: &Modulus) -> u64 {
    if operand == 0 {0} else {modulus.value() - operand}
}

/**
Returns (operand * inv(2)) mod modulus.
Correctness: operand must be even and at most (2 * modulus - 2) or odd and at most (modulus - 2).
@param[in] operand Should be at most (modulus - 1).
*/
#[inline]
pub fn div2_u64_mod(mut operand: u64, modulus: &Modulus) -> u64 {
    if (operand & 1) > 0 {
        let mut temp: u64 = 0;
        let carry = util::add_u64(operand, modulus.value(), &mut temp);
        operand = temp >> 1;
        if carry > 0 {operand | (1 << 63)} else {operand}
    } else {operand >> 1}
}

#[inline]
pub fn add_u64_mod(mut operand1: u64, operand2: u64, modulus: &Modulus) -> u64 {
    operand1 += operand2;
    if operand1 >= modulus.value() {operand1 - modulus.value()} else {operand1}
}

#[inline]
pub fn sub_u64_mod(operand1: u64, operand2: u64, modulus: &Modulus) -> u64 {
    let mut temp = 0_u64;
    let borrow = util::sub_u64(operand1, operand2, &mut temp);
    if borrow > 0 {temp.wrapping_add(modulus.value())} else {temp}
}

pub fn barrett_reduce_u128(input: &[u64], modulus: &Modulus) -> u64 {
    // Reduces input using base 2^64 Barrett reduction
    // input allocation size must be 128 bits
    let mut tmp1 = 0;
    let mut tmp2 = [0, 0];
    let mut tmp3;
    let mut carry = 0;
    let const_ratio = modulus.const_ratio();

    // Multiply input and const_ratio
    // Round 1
    util::multiply_u64_high_word(input[0], const_ratio[0], &mut carry);

    util::multiply_u64_u64(input[0], const_ratio[1], &mut tmp2);
    tmp3 = tmp2[1] + util::add_u64(tmp2[0], carry, &mut tmp1) as u64;

    // Round 2
    util::multiply_u64_u64(input[1], const_ratio[0], &mut tmp2);
    carry = tmp2[1] + util::add_u64(tmp1, tmp2[0], &mut tmp1) as u64;

    // This is all we care about
    tmp1 = input[1].wrapping_mul(const_ratio[1]).wrapping_add(tmp3).wrapping_add(carry);

    // Barrett subtraction
    tmp3 = input[0].wrapping_sub(tmp1.wrapping_mul(modulus.value()));

    // One more subtraction is enough
    if tmp3 >= modulus.value() {tmp3 - modulus.value()} else {tmp3}
}

#[inline]
pub fn barrett_reduce_u64(input: u64, modulus: &Modulus) -> u64 {
    // Reduces input using base 2^64 Barrett reduction
    // floor(2^64 / mod) == floor( floor(2^128 / mod) )
    let mut tmp = [0, 0];
    let const_ratio = modulus.const_ratio();
    util::multiply_u64_high_word(input, const_ratio[1], &mut tmp[1]);

    // Barrett subtraction
    tmp[0] = input - tmp[1] * modulus.value();

    // One more subtraction is enough
    if tmp[0] >= modulus.value() {tmp[0] - modulus.value()} else {tmp[0]}
}

#[inline]
pub fn multiply_u64_mod(operand1: u64, operand2: u64, modulus: &Modulus) -> u64 {
    let mut z = [0, 0];
    util::multiply_u64_u64(operand1, operand2, &mut z);
    barrett_reduce_u128(&z, modulus)
}




/**
This struct contains a operand and a precomputed quotient: (operand << 64) / modulus, for a specific modulus.
When passed to multiply_uint_mod, a faster variant of Barrett reduction will be performed.
Operand must be less than modulus.
*/
#[derive(Clone, Debug, Default)]
pub struct MultiplyU64ModOperand {
    pub operand: u64,
    pub quotient: u64,
}

impl MultiplyU64ModOperand {

    fn set_quotient(&mut self, modulus: &Modulus) {
        let mut wide_quotient = [0, 0];
        let mut wide_coeff = [0, self.operand];
        util::divide_u128_u64_inplace(&mut wide_coeff, modulus.value(), &mut wide_quotient);
        self.quotient = wide_quotient[0];
    }

    // constructor
    pub fn new(operand: u64, modulus: &Modulus) -> Self {
        let mut ret = MultiplyU64ModOperand {
            operand,
            quotient: 0
        };
        ret.set_quotient(modulus);
        ret
    }

}

impl std::fmt::Display for MultiplyU64ModOperand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.operand, self.quotient)?;
        Ok(())
    }
}

/**
Returns x * y mod modulus.
This is a highly-optimized variant of Barrett reduction.
Correctness: modulus should be at most 63-bit, and y must be less than modulus.
*/
#[inline]
pub fn multiply_u64operand_mod(x: u64, y: &MultiplyU64ModOperand, modulus: &Modulus) -> u64 {
    let mut tmp1 = 0;
    let p = modulus.value();
    util::multiply_u64_high_word(x, y.quotient, &mut tmp1);
    let tmp2 = y.operand.wrapping_mul(x).wrapping_sub(tmp1.wrapping_mul(p));
    if tmp2 >= p {tmp2 - p} else {tmp2}
}

/**
Returns x * y mod modulus or x * y mod modulus + modulus.
This is a highly-optimized variant of Barrett reduction and reduce to [0, 2 * modulus - 1].
Correctness: modulus should be at most 63-bit, and y must be less than modulus.
*/
#[inline]
pub fn multiply_u64operand_mod_lazy(x: u64, y: &MultiplyU64ModOperand, modulus: &Modulus) -> u64 {
    let mut tmp1 = 0;
    let p = modulus.value();
    util::multiply_u64_high_word(x, y.quotient, &mut tmp1);
    y.operand.wrapping_mul(x).wrapping_sub(tmp1.wrapping_mul(p))
}



/**
Returns value[0] = value mod modulus.
Correctness: Follows the condition of barrett_reduce_128.
*/
#[inline]
pub fn modulo_uint_inplace(value: &mut [u64], modulus: &Modulus) {
    if value.len() == 1 {
        if value[0] < modulus.value() {return;}
        else {value[0] = barrett_reduce_u64(value[0], modulus);}
    }
    for i in (0..(value.len() - 1)).rev() {
        value[i] = barrett_reduce_u128(&value[i..(i+2)], modulus);
        value[i + 1] = 0;
    }
}

/**
Returns value mod modulus.
Correctness: Follows the condition of barrett_reduce_128.
*/
#[inline]
pub fn modulo_uint(value: &[u64], modulus: &Modulus) -> u64 {
    if value.len() == 1 {
        if value[0] < modulus.value() {value[0]}
        else {barrett_reduce_u64(value[0], modulus)}
    } else {
        let mut temp = [0, value[value.len() - 1]];
        for i in (0..(value.len() - 1)).rev() {
            temp[0] = value[i];
            temp[1] = barrett_reduce_u128(&temp, modulus);
        }
        temp[1]
    }
}

/**
Returns (operand1 * operand2) + operand3 mod modulus.
Correctness: Follows the condition of barrett_reduce_128.
*/
#[inline]
pub fn multiply_add_u64_mod(operand1: u64, operand2: u64, operand3: u64, modulus: &Modulus) -> u64 {
    // lazy reduction
    let mut temp = [0, 0];
    util::multiply_u64_u64(operand1, operand2, &mut temp);
    temp[1] += util::add_u64(temp[0], operand3, &mut temp[0]) as u64;
    barrett_reduce_u128(&temp, modulus)
}

/**
Returns (operand1 * operand2) + operand3 mod modulus.
Correctness: Follows the condition of multiply_uint_mod.
*/
#[inline]
pub fn multiply_u64operand_add_u64_mod(
    operand1: u64, 
    operand2: &MultiplyU64ModOperand, 
    operand3: u64, 
    modulus: &Modulus
) -> u64 {
    add_u64_mod(
        multiply_u64operand_mod(operand1, operand2, modulus), 
        barrett_reduce_u64(operand3, modulus), 
        modulus
    )
}

#[inline]
pub fn try_invert_u64_mod(operand: u64, modulus: &Modulus, result: &mut u64) -> bool {
    try_invert_u64_mod_u64(operand, modulus.value(), result)
}

/**
Returns operand^exponent mod modulus.
Correctness: Follows the condition of barrett_reduce_128.
*/
pub fn exponentiate_u64_mod(operand: u64, mut exponent: u64, modulus: &Modulus) -> u64 {
    if exponent == 0 {return 1;}
    if exponent == 1 {return operand;}
    let mut power = operand; let mut product; let mut intermediate = 1;
    loop {
        if (exponent & 1) > 0 {
            product = multiply_u64_mod(power, intermediate, modulus);
            std::mem::swap(&mut product, &mut intermediate);
        }
        exponent >>= 1;
        if exponent == 0 {break;}
        product = multiply_u64_mod(power, power, modulus);
        std::mem::swap(&mut product, &mut power);
    }
    intermediate
}

/**
Computes numerator = numerator mod modulus, quotient = numerator / modulus.
Correctness: Follows the condition of barrett_reduce_128.
*/
pub fn divide_uint_mod_inplace(numerator: &mut [u64], modulus: &Modulus, quotient: &mut [u64]) {
    let u64_count = quotient.len();
    if u64_count == 2 {
        util::divide_u128_u64_inplace(numerator, modulus.value(), quotient);
    } else if u64_count == 1 {
        numerator[0] = barrett_reduce_u64(numerator[0], modulus);
        quotient[0] = numerator[0] / modulus.value(); return;
    } else {
        // If uint64_count > 2.
        // x = numerator = x1 * 2^128 + x2.
        // 2^128 = A*value + B.
        let mut x1 = vec![0; u64_count - 2];
        let mut x2 = vec![0; 2];
        let mut quot = vec![0; u64_count];
        let mut rem = vec![0; u64_count];
        util::set_uint(&numerator[2..], u64_count - 2, &mut x1);
        util::set_uint(&numerator[..2], 2, &mut x2); // x2 = (num) % 2^128.

        util::multiply_uint(&x1, &modulus.const_ratio()[0..2], &mut quot);
        util::multiply_uint_u64(&x1, modulus.const_ratio()[2], &mut rem);
        util::add_uint_inplace(&mut rem, &x2);

        let remainder_u64_count = util::get_significant_uint64_count_uint(&rem);
        divide_uint_mod_inplace(&mut rem, modulus, &mut quotient[0..remainder_u64_count]);
        util::add_uint_inplace(quotient, &quot);
        numerator[0] = rem[0];
        return;
    }
}

/**
Computes <operand1, operand2> mod modulus.
Correctness: Follows the condition of barrett_reduce_128.
*/
#[inline]
pub fn dot_product_mod(operand1: &[u64], operand2: &[u64], modulus: &Modulus) -> u64 {
    let mut accumulator = [0, 0];
    let mut qword = [0, 0];
    for i in 0..operand1.len() {
        util::multiply_u64_u64(operand1[i], operand2[i], &mut qword);
        util::add_u128_inplace(&mut accumulator, &qword);
    }
    barrett_reduce_u128(&accumulator, modulus)
}