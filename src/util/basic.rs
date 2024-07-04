#![allow(unused)]

pub const HE_MOD_BIT_COUNT_MAX: usize = 61;

pub const HE_POLY_MOD_DEGREE_MAX: usize = 131072;
pub const HE_POLY_MOD_DEGREE_MIN: usize = 2;

pub const HE_COEFF_MOD_COUNT_MAX: usize = 64;
pub const HE_COEFF_MOD_COUNT_MIN: usize = 1;

pub const HE_USER_MOD_BIT_COUNT_MAX: usize = 60;
pub const HE_USER_MOD_BIT_COUNT_MIN: usize = 2;

pub const HE_INTERNAL_MOD_BIT_COUNT: usize = 61;

pub const HE_PLAIN_MOD_BIT_COUNT_MAX: usize = HE_USER_MOD_BIT_COUNT_MAX;
pub const HE_PLAIN_MOD_BIT_COUNT_MIN: usize = HE_USER_MOD_BIT_COUNT_MIN;

pub const HE_CIPHERTEXT_SIZE_MAX: usize = 16;
pub const HE_CIPHERTEXT_SIZE_MIN: usize = 2;

pub const HE_PRNG_SEED_BYTES: usize = 64;

pub const HE_MULTIPLY_ACCUMULATE_USER_MOD_MAX: usize = 1 << (128 - (HE_USER_MOD_BIT_COUNT_MAX << 1));

#[inline]
pub fn get_significant_bit_count(value: u64) -> usize {
    if value == 0 {0}
    else {64 - value.leading_zeros() as usize}
}

#[inline]
pub fn get_significant_bit_count_uint(value: &[u64]) -> usize {
    let mut c = value.len() - 1;
    while c > 0 && value[c] == 0 {c-=1;};
    64 * c + get_significant_bit_count(value[c])
}

#[inline]
pub fn get_significant_uint64_count_uint(value: &[u64]) -> usize {
    let mut c = value.len();
    while c > 0 && value[c-1] == 0 {c-=1;};
    c
}

#[inline]
pub fn get_nonzero_uint64_count_uint(value: &[u64]) -> usize {
    let mut c = 0;
    value.iter().for_each(|&x| {if x!=0 {c+=1;}}); c
}

#[inline]
pub fn get_power_of_two(value: u64) -> isize {
    if value == 0 || (value & (value - 1)) != 0 {-1}
    else {63 - value.leading_zeros() as isize}
}

#[inline]
pub fn reverse_bits_u32(operand: u32, bit_count: usize) -> u32 {
    if bit_count == 0 {
        0
    } else {
        operand.reverse_bits() >> (32 - bit_count)
    }
}

#[inline]
pub fn reverse_bits_u64(operand: u64, bit_count: usize) -> u64 {
    if bit_count == 0 {
        0
    } else {
        operand.reverse_bits() >> (64 - bit_count)
    }
}

pub fn are_close_f64(value1: f64, value2: f64) -> bool {
    let scale_factor = value1.max(value2).max(1.0);
    (value1 - value2).abs() < f64::EPSILON * scale_factor
}

#[inline]
pub fn hamming_weight(x: u8) -> i32 {
    let mut t = x as i32;
    t -= (t >> 1) & 0x55;
    t = (t & 0x33) + ((t >> 2) & 0x33);
    (t + (t >> 4)) & 0x0F
}



#[inline]
pub fn set_zero_uint(target: &mut[u64]) {
    target.fill(0)
}

#[allow(unused)]
#[inline]
pub fn is_zero_uint(value: &[u64]) -> bool {
    value.iter().all(|&x| x == 0)
}

#[allow(unused)]
#[inline]
pub fn set_bit_uint(value: &mut[u64], bit_index: usize) {
    let u64_index = bit_index / 64;
    let sub_bit_index = bit_index % 64;
    value[u64_index] |= (1 << sub_bit_index) as u64;
}

#[inline]
pub fn set_uint(from: &[u64], len: usize, target: &mut[u64]) {
    target[..len].copy_from_slice(&from[..len]);
}



#[inline]
pub fn add_u64_carry(operand1: u64, operand2: u64, carry: u8, result: &mut u64) -> u8 {
    let a = operand1.wrapping_add(operand2);
    *result = a.wrapping_add(carry as u64);
    ((a < operand2) || (!a < (carry as u64))) as u8
}

#[inline]
pub fn add_u64(operand1: u64, operand2: u64, result: &mut u64) -> u8 {
    *result = operand1.wrapping_add(operand2);
    (*result < operand1) as u8
}

#[inline]
pub fn add_u128(operand1: &[u64], operand2: &[u64], result: &mut [u64]) -> u8 {
    let carry = add_u64(operand1[0], operand2[0], &mut result[0]);
    add_u64_carry(operand1[1], operand2[1], carry, &mut result[1])
}

#[inline]
pub fn add_u128_inplace(operand1: &mut [u64], operand2: &[u64]) -> u8 {
    let carry = add_u64(operand1[0], operand2[0], &mut operand1[0]);
    add_u64_carry(operand1[1], operand2[1], carry, &mut operand1[1])
}

#[inline]
pub fn add_uint_carry(operand1: &[u64], operand2: &[u64], carry: u8, result: &mut [u64]) -> u8 {
    let mut carry = carry;
    for i in 0..result.len() {
        let mut temp_result = 0_u64;
        carry = add_u64_carry(
            if i < operand1.len() {operand1[i]} else {0},
            if i < operand2.len() {operand2[i]} else {0},
            carry,
            &mut temp_result
        );
        result[i] = temp_result;
    }
    carry
}

#[inline]
pub fn add_uint_carry_inplace(operand1: &mut [u64], operand2: &[u64], carry: u8) -> u8 {
    let mut carry = carry;
    for i in 0..operand1.len() {
        let mut temp_result = 0_u64;
        carry = add_u64_carry(
            if i < operand1.len() {operand1[i]} else {0},
            if i < operand2.len() {operand2[i]} else {0},
            carry,
            &mut temp_result
        );
        operand1[i] = temp_result;
    }
    carry
}

#[inline]
pub fn add_uint(operand1: &[u64], operand2: &[u64], result: &mut[u64]) -> u8 {
    let mut carry = add_u64(operand1[0], operand2[0], &mut result[0]);
    for i in 1..result.len() {
        let mut temp_result = 0_u64;
        carry = add_u64_carry(operand1[i], operand2[i], carry, &mut temp_result);
        result[i] = temp_result;
    }
    carry
}

#[inline]
pub fn add_uint_inplace(operand1: &mut [u64], operand2: &[u64]) -> u8 {
    let mut carry = add_u64(operand1[0], operand2[0], &mut operand1[0]);
    for i in 1..operand1.len() {
        let mut temp_result = 0_u64;
        carry = add_u64_carry(operand1[i], operand2[i], carry, &mut temp_result);
        operand1[i] = temp_result;
    }
    carry
}

#[inline]
pub fn add_uint_u64(operand1: &[u64], operand2: u64, result: &mut[u64]) -> u8 {
    let mut carry = add_u64(operand1[0], operand2, &mut result[0]);
    for i in 1..result.len() {
        let mut temp_result = 0_u64;
        carry = add_u64_carry(operand1[i], 0, carry, &mut temp_result);
        result[i] = temp_result
    }
    carry
}

#[inline]
pub fn add_uint_u64_inplace(operand1: &mut [u64], operand2: u64) -> u8 {
    let mut carry = add_u64(operand1[0], operand2, &mut operand1[0]);
    for i in 1..operand1.len() {
        let mut temp_result = 0_u64;
        carry = add_u64_carry(operand1[i], 0, carry, &mut temp_result);
        operand1[i] = temp_result
    }
    carry
}




#[inline]
pub fn sub_u64_borrow(operand1: u64, operand2: u64, borrow: u8, result: &mut u64) -> u8 {
    let diff = operand1.wrapping_sub(operand2);
    *result = diff.wrapping_sub((borrow != 0) as u64);
    ((diff > operand1) || (diff < (borrow as u64))) as u8
}

#[inline]
pub fn sub_u64(operand1: u64, operand2: u64, result: &mut u64) -> u8 {
    *result = operand1.wrapping_sub(operand2);
    (operand2 > operand1) as u8
}

#[inline]
pub fn sub_uint_borrow(operand1: &[u64], operand2: &[u64], borrow: u8, result: &mut [u64]) -> u8 {
    let mut borrow = borrow;
    for i in 0..result.len() {
        let mut temp_result: u64 = 0;
        borrow = sub_u64_borrow(
            if i < operand1.len() {operand1[i]} else {0},
            if i < operand2.len() {operand2[i]} else {0},
            borrow, &mut temp_result
        );
        result[i] = temp_result;
    }
    borrow
}

#[inline]
pub fn sub_uint_borrow_inplace(operand1: &mut[u64], operand2: &[u64], borrow: u8) -> u8 {
    let mut borrow = borrow;
    for i in 0..operand1.len() {
        let mut temp_result: u64 = 0;
        borrow = sub_u64_borrow(
            if i < operand1.len() {operand1[i]} else {0},
            if i < operand2.len() {operand2[i]} else {0},
            borrow, &mut temp_result
        );
        operand1[i] = temp_result;
    }
    borrow
}

#[inline]
pub fn sub_uint(operand1: &[u64], operand2: &[u64], result: &mut[u64]) -> u8 {
    let mut borrow = sub_u64(operand1[0], operand2[0], &mut result[0]);
    for i in 1..result.len() {
        let mut temp_result: u64 = 0;
        borrow = sub_u64_borrow(
            if i < operand1.len() {operand1[i]} else {0},
            if i < operand2.len() {operand2[i]} else {0},
            borrow, &mut temp_result
        );
        result[i] = temp_result;
    }
    borrow
}

#[inline]
pub fn sub_uint_inplace(operand1: &mut [u64], operand2: &[u64]) -> u8 {
    let mut borrow = sub_u64(operand1[0], operand2[0], &mut operand1[0]);
    for i in 1..operand1.len() {
        let mut temp_result: u64 = 0;
        borrow = sub_u64_borrow(
            if i < operand1.len() {operand1[i]} else {0},
            if i < operand2.len() {operand2[i]} else {0},
            borrow, &mut temp_result
        );
        operand1[i] = temp_result;
    }
    borrow
}

#[inline]
pub fn sub_uint_u64(operand1: &[u64], operand2: u64, result: &mut[u64]) -> u8 {
    let mut borrow = sub_u64(operand1[0], operand2, &mut result[0]);
    for i in 1..result.len() {
        let mut temp_result: u64 = 0;
        borrow = sub_u64_borrow(operand1[i], 0, borrow, &mut temp_result);
        result[i] = temp_result;
    }
    borrow
}

#[inline]
pub fn sub_uint_u64_inplace(operand1: &mut[u64], operand2: u64) -> u8 {
    let mut borrow = sub_u64(operand1[0], operand2, &mut operand1[0]);
    for i in 1..operand1.len() {
        let mut temp_result: u64 = 0;
        borrow = sub_u64_borrow(operand1[i], 0, borrow, &mut temp_result);
        operand1[i] = temp_result;
    }
    borrow
}


#[inline]
pub fn increment_uint(operand: &[u64], result: &mut[u64]) -> u8 { add_uint_u64(operand, 1, result) }
#[inline]
pub fn decrement_uint(operand: &[u64], result: &mut[u64]) -> u8 { sub_uint_u64(operand, 1, result) }

#[inline]
pub fn increment_uint_inplace(operand: &mut[u64]) -> u8 { add_uint_u64_inplace(operand, 1) }
#[inline]
pub fn decrement_uint_inplace(operand: &mut[u64]) -> u8 { sub_uint_u64_inplace(operand, 1) }

#[inline]
pub fn negate_uint(operand: &[u64], result: &mut[u64]) {
    // negation is equivalent to inverting bits and adding 1.
    let mut carry = add_u64(!operand[0], 1, &mut result[0]);
    for i in 1..result.len() {
        let mut temp_result = 0_u64;
        carry = add_u64_carry(!operand[i], 0, carry, &mut temp_result);
        result[i] = temp_result;
    }
}

#[inline]
pub fn negate_uint_inplace(operand: &mut [u64]) {
    // negation is equivalent to inverting bits and adding 1.
    let mut carry = add_u64(!operand[0], 1, &mut operand[0]);
    for i in 1..operand.len() {
        let mut temp_result = 0_u64;
        carry = add_u64_carry(!operand[i], 0, carry, &mut temp_result);
        operand[i] = temp_result;
    }
}


pub fn left_shift_uint(operand: &[u64], shift_amount: usize, u64_count: usize, result: &mut [u64]) {
    let u64_shift_amount = shift_amount / 64;
    for i in 0..(u64_count - u64_shift_amount) {
        result[u64_count - i - 1] = operand[u64_count - i - 1 - u64_shift_amount];
    }
    for i in (u64_count - u64_shift_amount) .. u64_count {
        result[u64_count - i - 1] = 0;
    }
    let bit_shift_amount = (shift_amount - u64_shift_amount * 64) as u32;
    if bit_shift_amount > 0 {
        let neg_bit_shift_amount = 64 - bit_shift_amount;
        for i in (1..u64_count).rev() {
            result[i] = (result[i] << bit_shift_amount) | (result[i-1] >> neg_bit_shift_amount);
        }
        result[0] <<= bit_shift_amount;
    }
}

pub fn left_shift_uint_inplace(operand: &mut [u64], shift_amount: usize, u64_count: usize) {
    let u64_shift_amount = shift_amount / 64;
    for i in 0..(u64_count - u64_shift_amount) {
        operand[u64_count - i - 1] = operand[u64_count - i - 1 - u64_shift_amount];
    }
    for i in (u64_count - u64_shift_amount) .. u64_count {
        operand[u64_count - i - 1] = 0;
    }
    let bit_shift_amount = (shift_amount - u64_shift_amount * 64) as u32;
    if bit_shift_amount > 0 {
        let neg_bit_shift_amount = 64 - bit_shift_amount;
        for i in (1..u64_count).rev() {
            operand[i] = (operand[i] << bit_shift_amount) | (operand[i-1] >> neg_bit_shift_amount);
        }
        operand[0] <<= bit_shift_amount;
    }
}

pub fn right_shift_uint(operand: &[u64], shift_amount: usize, u64_count: usize, result: &mut [u64]) {
    let u64_shift_amount = shift_amount / 64;
    let copy_amount = u64_count - u64_shift_amount;
    result[..copy_amount].copy_from_slice(&operand[u64_shift_amount..(copy_amount + u64_shift_amount)]);

    for i in (u64_count - u64_shift_amount) .. u64_count {
        result[i] = 0;
    }
    let bit_shift_amount = shift_amount - u64_shift_amount * 64;
    if bit_shift_amount > 0 {
        let neg_bit_shift_amount = 64 - bit_shift_amount;
        for i in 0..(u64_count - 1) {
            result[i] = (result[i] >> bit_shift_amount) | (result[i+1] << neg_bit_shift_amount);
        }
        result[u64_count-1] >>= bit_shift_amount;
    }
}

pub fn right_shift_uint_inplace(operand: &mut [u64], shift_amount: usize, u64_count: usize) {
    let u64_shift_amount = shift_amount / 64;
    for i in 0..(u64_count - u64_shift_amount) {
        operand[i] = operand[i + u64_shift_amount];
    }
    for i in (u64_count - u64_shift_amount) .. u64_count {
        operand[i] = 0;
    }
    let bit_shift_amount = shift_amount - u64_shift_amount * 64;
    if bit_shift_amount > 0 {
        let neg_bit_shift_amount = 64 - bit_shift_amount;
        for i in 0..(u64_count - 1) {
            operand[i] = (operand[i] >> bit_shift_amount) | (operand[i+1] << neg_bit_shift_amount);
        }
        operand[u64_count-1] >>= bit_shift_amount;
    }
}

#[inline]
pub fn left_shift_u128(operand: &[u64], shift_amount: usize, result: &mut [u64]) {
    if (shift_amount & 64) > 0 {
        result[1] = operand[0]; result[0] = 0;
    } else {
        result[1] = operand[1]; result[0] = operand[0];
    }
    let bit_shift_amount = shift_amount & 63;
    if bit_shift_amount > 0 {
        let neg_bit_shift_amount = 64 - bit_shift_amount;
        // warning: if bit_shift_amount == 0 this is incorrect
        result[1] = (result[1] << bit_shift_amount) | (result[0] >> neg_bit_shift_amount);
        result[0] <<= bit_shift_amount;
    }
}

#[inline]
pub fn left_shift_u128_inplace(operand: &mut [u64], shift_amount: usize) {
    if (shift_amount & 64) > 0 {
        operand[1] = operand[0]; operand[0] = 0;
    }
    let bit_shift_amount = shift_amount & 63;
    if bit_shift_amount > 0 {
        let neg_bit_shift_amount = 64 - bit_shift_amount;
        // warning: if bit_shift_amount == 0 this is incorrect
        operand[1] = (operand[1] << bit_shift_amount) | (operand[0] >> neg_bit_shift_amount);
        operand[0] <<= bit_shift_amount;
    }
}

#[inline]
pub fn right_shift_u128(operand: &[u64], shift_amount: usize, result: &mut [u64]) {
    if (shift_amount & 64) > 0 {
        result[0] = operand[1]; result[1] = 0;
    } else {
        result[1] = operand[1]; result[0] = operand[0];
    }
    let bit_shift_amount = shift_amount & 63;
    if bit_shift_amount > 0 {
        let neg_bit_shift_amount = 64 - bit_shift_amount;
        // warning: if bit_shift_amount == 0 this is incorrect
        result[0] = (result[0] >> bit_shift_amount) | (result[1] << neg_bit_shift_amount);
        result[1] >>= bit_shift_amount;
    }
}


#[inline]
pub fn right_shift_u128_inplace(operand: &mut [u64], shift_amount: usize) {
    if (shift_amount & 64) > 0 {
        operand[0] = operand[1]; operand[1] = 0;
    }
    let bit_shift_amount = shift_amount & 63;
    if bit_shift_amount > 0 {
        let neg_bit_shift_amount = 64 - bit_shift_amount;
        // warning: if bit_shift_amount == 0 this is incorrect
        operand[0] = (operand[0] >> bit_shift_amount) | (operand[1] << neg_bit_shift_amount);
        operand[1] >>= bit_shift_amount;
    }
}

#[inline]
pub fn left_shift_u192(operand: &[u64], shift_amount: usize, result: &mut [u64]) {
    if (shift_amount & 128) > 0 {
        result[2] = operand[0]; result[1] = 0; result[0] = 0;
    } else if (shift_amount & 64) > 0 {
        result[2] = operand[1]; result[1] = operand[0]; result[0] = 0;
    } else {
        result[2] = operand[2]; result[1] = operand[1]; result[0] = operand[0];
    }
    let bit_shift_amount = shift_amount & 63;
    if bit_shift_amount > 0 {
        let neg_bit_shift_amount = 64 - bit_shift_amount;
        // warning: if bit_shift_amount == 0 this is incorrect
        result[2] = (result[2] << bit_shift_amount) | (result[1] >> neg_bit_shift_amount);
        result[1] = (result[1] << bit_shift_amount) | (result[0] >> neg_bit_shift_amount);
        result[0] <<= bit_shift_amount;
    }
}

#[inline]
pub fn left_shift_u192_inplace(operand: &mut [u64], shift_amount: usize) {
    if (shift_amount & 128) > 0 {
        operand[2] = operand[0]; operand[1] = 0; operand[0] = 0;
    } else if (shift_amount & 64) > 0 {
        operand[2] = operand[1]; operand[1] = operand[0]; operand[0] = 0;
    }
    let bit_shift_amount = shift_amount & 63;
    if bit_shift_amount > 0 {
        let neg_bit_shift_amount = 64 - bit_shift_amount;
        // warning: if bit_shift_amount == 0 this is incorrect
        operand[2] = (operand[2] << bit_shift_amount) | (operand[1] >> neg_bit_shift_amount);
        operand[1] = (operand[1] << bit_shift_amount) | (operand[0] >> neg_bit_shift_amount);
        operand[0] <<= bit_shift_amount;
    }
}

#[inline]
pub fn right_shift_u192(operand: &[u64], shift_amount: usize, result: &mut [u64]) {
    if (shift_amount & 128) > 0 {
        result[0] = operand[2]; result[1] = 0; result[2] = 0;
    } else if (shift_amount & 64) > 0 {
        result[0] = operand[1]; result[1] = operand[2]; result[2] = 0;
    }
    let bit_shift_amount = shift_amount & 63;
    if bit_shift_amount > 0 {
        let neg_bit_shift_amount = 64 - bit_shift_amount;
        // warning: if bit_shift_amount == 0 this is incorrect
        result[0] = (result[0] >> bit_shift_amount) | (result[1] << neg_bit_shift_amount);
        result[1] = (result[1] >> bit_shift_amount) | (result[2] << neg_bit_shift_amount);
        result[2] >>= bit_shift_amount;
    }
}

#[inline]
pub fn right_shift_u192_inplace(operand: &mut[u64], shift_amount: usize) {
    if (shift_amount & 128) > 0 {
        operand[0] = operand[2]; operand[1] = 0; operand[2] = 0;
    } else if (shift_amount & 64) > 0 {
        operand[0] = operand[1]; operand[1] = operand[2]; operand[2] = 0;
    }
    let bit_shift_amount = shift_amount & 63;
    if bit_shift_amount > 0 {
        let neg_bit_shift_amount = 64 - bit_shift_amount;
        // warning: if bit_shift_amount == 0 this is incorrect
        operand[0] = (operand[0] >> bit_shift_amount) | (operand[1] << neg_bit_shift_amount);
        operand[1] = (operand[1] >> bit_shift_amount) | (operand[2] << neg_bit_shift_amount);
        operand[2] >>= bit_shift_amount;
    }
}

#[inline]
pub fn half_round_up_uint(operand: &[u64], result: &mut [u64]) {
    if result.is_empty() {return;}
    let low_bit_set = (operand[0] & 1) != 0;
    let u64_count = result.len();
    for i in 0..(u64_count - 1) {result[i] = (operand[i] >> 1) | (operand[i +1] << 63);}
    result[u64_count - 1] = operand[u64_count - 1] >> 1;
    if low_bit_set {increment_uint_inplace(result);}
}

#[inline]
pub fn half_round_up_uint_inplace(operand: &mut [u64]) {
    if operand.is_empty() {return;}
    let low_bit_set = (operand[0] & 1) != 0;
    let u64_count = operand.len();
    for i in 0..(u64_count - 1) {operand[i] = (operand[i] >> 1) | (operand[i +1] << 63);}
    operand[u64_count - 1] >>= 1;
    if low_bit_set {increment_uint_inplace(operand);}
}

#[inline]
pub fn not_uint(operand: &[u64], result: &mut[u64]) {
    result.iter_mut().zip(operand.iter()).for_each(|(r, o)| *r = !o);
}

#[inline]
pub fn not_uint_inplace(operand: &mut[u64]) {
    for i in operand.iter_mut() {*i = !*i;}
}

#[inline]
pub fn and_uint(operand1: &[u64], operand2: &[u64], result: &mut[u64]) {
    for i in 0..result.len() {result[i] = operand1[i] & operand2[i];}
}

#[inline]
pub fn and_uint_inplace(operand1: &mut[u64], operand2: &[u64]) {
    for i in 0..operand1.len() {operand1[i] &= operand2[i];}
}

#[inline]
pub fn or_uint(operand1: &[u64], operand2: &[u64], result: &mut[u64]) {
    for i in 0..result.len() {result[i] = operand1[i] | operand2[i];}
}

#[inline]
pub fn or_uint_inplace(operand1: &mut[u64], operand2: &[u64]) {
    for i in 0..operand1.len() {operand1[i] |= operand2[i];}
}

#[inline]
pub fn xor_uint(operand1: &[u64], operand2: &[u64], result: &mut[u64]) {
    for i in 0..result.len() {result[i] = operand1[i] ^ operand2[i];}
}

#[inline]
pub fn xor_uint_inplace(operand1: &mut[u64], operand2: &[u64]) {
    for i in 0..operand1.len() {operand1[i] ^= operand2[i];}
}

#[inline]
pub fn multiply_u64_high_word(operand1: u64, operand2: u64, hw64: &mut u64) {
    *hw64 = (((operand1 as u128) * (operand2 as u128)) >> 64) as u64;
}

#[inline]
pub fn multiply_u64_u64(operand1: u64, operand2: u64, result128: &mut[u64]) {
    let product = (operand1 as u128) * (operand2 as u128);
    result128[0] = product as u64;
    result128[1] = (product >> 64) as u64;
}

pub fn multiply_uint_u64(operand1: &[u64], operand2: u64, result: &mut[u64]) {
    if operand1.is_empty() || operand2 == 0 {
        return set_zero_uint(result);
    } 
    if result.len() == 1 {
        result[0] = operand1[0].wrapping_mul(operand2);
        return;
    }
    set_zero_uint(result);
    let mut carry: u64 = 0;
    let operand1_index_max = std::cmp::min(operand1.len(), result.len());
    for operand1_index in 0..operand1_index_max {
        let mut temp_result = [0; 2];
        multiply_u64_u64(operand1[operand1_index], operand2, temp_result.as_mut_slice());
        let mut temp = 0;
        carry = temp_result[1] + (add_u64_carry(temp_result[0], carry, 0, &mut temp) as u64); // Wrapping add?
        result[operand1_index] = temp;
    }
    if operand1_index_max < result.len() {
        result[operand1_index_max] = carry;
    }
}

pub fn multiply_uint_u64_inplace(operand1: &mut[u64], operand2: u64) {
    if operand1.is_empty() || operand2 == 0 {
        return set_zero_uint(operand1);
    } 
    if operand1.len() == 1 {
        operand1[0] = operand1[0].wrapping_mul(operand2);
        return;
    }
    set_zero_uint(operand1);
    let mut carry: u64 = 0;
    let operand1_index_max = std::cmp::min(operand1.len(), operand1.len());
    for operand1_index in 0..operand1_index_max {
        let mut temp_result = [0; 2];
        multiply_u64_u64(operand1[operand1_index], operand2, temp_result.as_mut_slice());
        let mut temp = 0;
        carry = temp_result[1] + (add_u64_carry(temp_result[0], carry, 0, &mut temp) as u64); // Wrapping add?
        operand1[operand1_index] = temp;
    }
    if operand1_index_max < operand1.len() {
        operand1[operand1_index_max] = carry;
    }
}

pub fn multiply_uint(operand1: &[u64], operand2: &[u64], result: &mut [u64]) {
    if operand1.is_empty() || operand2.is_empty() {return set_zero_uint(result);}
    if result.len() == 1 {result[0] = operand1[0].wrapping_mul(operand1[0]); return;}
    let operand1_uint64_count = get_significant_uint64_count_uint(operand1);
    let operand2_uint64_count = get_significant_uint64_count_uint(operand2);
    if operand1_uint64_count == 1 {
        return multiply_uint_u64(operand2, operand1[0], result);
    }
    if operand2_uint64_count == 1 {
        return multiply_uint_u64(operand1, operand2[0], result);
    }
    set_zero_uint(result);
    let operand1_index_max = std::cmp::min(operand1.len(), result.len());
    for operand1_index in 0 .. operand1_index_max {
        let operand2_index_max = std::cmp::min(operand2.len(), result.len() - operand1_index);
        let mut carry = 0;
        for operand2_index in 0 .. operand2_index_max {
            let mut temp_result = [0; 2];
            multiply_u64_u64(operand1[operand1_index], operand2[operand2_index], &mut temp_result);
            carry = temp_result[1] + (add_u64_carry(temp_result[0], carry, 0, &mut(temp_result[0])) as u64);  // Wrapping add?
            let mut temp = 0;
            carry += add_u64_carry(result[operand1_index + operand2_index], temp_result[0], 0, &mut temp) as u64;  // Wrapping add?
            result[operand1_index + operand2_index] = temp;
        }
        if operand1_index + operand2_index_max < result.len() {
            result[operand1_index + operand2_index_max] = carry;
        }
    }
}

/*
pub fn multiply_uint_inplace(operand1: &mut[u64], operand2: &[u64]) {
    if operand1.len() == 0 || operand2.len() == 0 {return set_zero_uint(operand1);}
    if operand1.len() == 1 {operand1[0] = operand1[0].wrapping_mul(operand1[0]); return;}
    let operand1_uint64_count = get_significant_uint64_count_uint(operand1);
    let operand2_uint64_count = get_significant_uint64_count_uint(operand2);
    if operand1_uint64_count == 1 {
        return multiply_uint_u64(operand2, operand1[0], operand1);
    }
    if operand2_uint64_count == 1 {
        return multiply_uint_u64_inplace(operand1, operand2[0]);
    }
    set_zero_uint(operand1);
    let operand1_index_max = std::cmp::min(operand1.len(), operand1.len());
    for operand1_index in 0 .. operand1_index_max {
        let operand2_index_max = std::cmp::min(operand2.len(), operand1.len() - operand1_index);
        let mut carry = 0;
        for operand2_index in 0 .. operand2_index_max {
            let mut temp_result = [0; 2];
            multiply_u64_u64(operand1[operand1_index], operand2[operand2_index], &mut temp_result);
            carry = temp_result[1] + (add_u64_carry(temp_result[0], carry, 0, &mut(temp_result[0])) as u64);  // Wrapping add?
            let mut temp = 0;
            carry += add_u64_carry(operand1[operand1_index + operand2_index], temp_result[0], 0, &mut temp) as u64;  // Wrapping add?
            operand1[operand1_index + operand2_index] = temp;
        }
        if operand1_index + operand2_index_max < operand1.len() {
            operand1[operand1_index + operand2_index_max] = carry;
        }
    }
}
*/

#[inline]
pub fn divide_round_up_usize(value: usize, divisor: usize) -> usize {
    (value + divisor - 1) / divisor
}

pub fn divide_uint_inplace(numerator: &mut [u64], denominator: &[u64], quotient: &mut [u64]) {
    // assert!(numerator.len() == denominator.len());
    // assert!(numerator.len() == quotient.len());
    let u64_count = quotient.len();
    if u64_count == 0 {return;}
    set_zero_uint(quotient);
    // Determine significant bits in numerator and denominator.
    let mut numerator_bits = get_significant_bit_count_uint(numerator);
    let mut denominator_bits = get_significant_bit_count_uint(denominator);
    // If numerator has fewer bits than denominator, then done.
    if numerator_bits < denominator_bits {return;}
    // Only perform computation up to last non-zero uint64s.
    let u64_count = divide_round_up_usize(numerator_bits, 64);
    // Handle fast case.
    if u64_count == 1 {
        quotient[0] = numerator[0] / denominator[0];
        numerator[0] -= quotient[0] * denominator[0];
        return;
    }
    // Create temporary space to store mutable copy of denominator.
    let mut shifted_denominator = vec![0_u64; u64_count];
    // Shift denominator to bring MSB in alignment with MSB of numerator.
    let denominator_shift = numerator_bits - denominator_bits;
    left_shift_uint(denominator, denominator_shift, u64_count, &mut shifted_denominator);
    let mut difference = vec![0_u64; u64_count];
    denominator_bits += denominator_shift;
    // Perform bit-wise division algorithm.
    let mut remaining_shifts = denominator_shift;
    while numerator_bits == denominator_bits {
        // NOTE: MSBs of numerator and denominator are aligned.
        // Even though MSB of numerator and denominator are aligned,
        // still possible numerator < shifted_denominator.
        if sub_uint(numerator, &shifted_denominator, &mut difference) != 0 {
            if remaining_shifts == 0 {break;}
            add_uint_inplace(&mut difference, numerator);
            left_shift_uint_inplace(quotient, 1, u64_count);
            remaining_shifts -= 1;
        }
        quotient[0] |= 1;
        numerator_bits = get_significant_bit_count_uint(&difference);
        let mut numerator_shift = denominator_bits - numerator_bits;
        if numerator_shift > remaining_shifts {
            numerator_shift = remaining_shifts;
        }
        if numerator_bits > 0 {
            left_shift_uint(&difference, numerator_shift, u64_count, numerator);
            numerator_bits += numerator_shift;
        } else {
            set_zero_uint(numerator);
        }
        left_shift_uint_inplace(quotient, numerator_shift, u64_count);
        remaining_shifts -= numerator_shift;
    }
    if numerator_bits > 0 {
        right_shift_uint_inplace(numerator, denominator_shift, u64_count);
    }
}

#[inline]
pub fn divide_uint(numerator: &[u64], denominator: &[u64], quotient: &mut [u64], remainder: &mut [u64]) {
    set_uint(numerator, remainder.len(), remainder);
    divide_uint_inplace(remainder, denominator, quotient);
}

#[deprecated]
#[allow(unused)]
pub fn divide_u128_u64_inplace_deprecated(numerator: &mut [u64], denominator: u64, quotient: &mut [u64]) {
    quotient[0] = 0; quotient[1] = 0;
    // Determine significant bits in numerator and denominator.
    let mut numerator_bits = get_significant_bit_count_uint(numerator);
    let mut denominator_bits = get_significant_bit_count(denominator);
    // If numerator has fewer bits than denominator, then done.
    if numerator_bits < denominator_bits {return;}
    // Create temporary space to store mutable copy of denominator.
    let mut shifted_denominator = [denominator, 0];
    // Create temporary space to store difference calculation.
    let mut difference = [0, 0];
    // Shift denominator to bring MSB in alignment with MSB of numerator.
    let denominator_shift = numerator_bits - denominator_bits;
    left_shift_u128_inplace(&mut shifted_denominator, denominator_shift);
    denominator_bits += denominator_shift;
    // Perform bit-wise division algorithm.
    let mut remaining_shifts = denominator_shift;
    while numerator_bits == denominator_bits {
        // NOTE: MSBs of numerator and denominator are aligned.
        // Even though MSB of numerator and denominator are aligned,
        // still possible numerator < shifted_denominator.
        if sub_uint(numerator, &shifted_denominator, &mut difference) != 0 {
            if remaining_shifts == 0 {break;}
            add_uint_inplace(&mut difference, numerator);
            quotient[1] = (quotient[1] << 1) | (quotient[0] >> 63);
            quotient[0] <<= 1;
            remaining_shifts -= 1;
        }
        numerator_bits = get_significant_bit_count_uint(&difference);
        let mut numerator_shift = denominator_bits - numerator_bits;
        if numerator_shift > remaining_shifts {
            numerator_shift = remaining_shifts;
        }
        numerator[0] = 0;
        numerator[1] = 0;
        if numerator_bits > 0 {
            left_shift_u128(&difference, numerator_shift, numerator);
            numerator_bits += numerator_shift;
        } 
        quotient[0] |= 1;
        left_shift_u128_inplace(quotient, numerator_shift);
        remaining_shifts -= numerator_shift;
    }
    if numerator_bits > 0 {
        right_shift_u128_inplace(numerator, denominator_shift);
    }

}


pub fn divide_u128_u64_inplace(numerator: &mut [u64], denominator: u64, quotient: &mut [u64]) {
    let mut n = ((numerator[1] as u128) << 64) | numerator[0] as u128;
    let q = n / (denominator as u128);
    n -= q * (denominator as u128);
    numerator[0] = n as u64;
    numerator[1] = 0;
    quotient[0] = q as u64;
    quotient[1] = (q >> 64) as u64;
}

pub fn divide_u192_u64_inplace(numerator: &mut [u64], denominator: u64, quotient: &mut [u64]) {
    quotient[0] = 0; quotient[1] = 0; quotient[2] = 0;
    // Determine significant bits in numerator and denominator.
    let mut numerator_bits = get_significant_bit_count_uint(numerator);
    let mut denominator_bits = get_significant_bit_count(denominator);
    // If numerator has fewer bits than denominator, then done.
    if numerator_bits < denominator_bits {return;}
    // Only perform computation up to last non-zero uint64s.
    let u64_count = divide_round_up_usize(numerator_bits, 64);
    // Handle fast case.
    if u64_count == 1 {
        quotient[0] = numerator[0] / denominator;
        numerator[0] -= quotient[0] * denominator;
        return;
    }
    // Create temporary space to store mutable copy of denominator.
    let mut shifted_denominator = vec![0_u64; u64_count];
    shifted_denominator[0] = denominator;
    // Shift denominator to bring MSB in alignment with MSB of numerator.
    let denominator_shift = numerator_bits - denominator_bits;
    left_shift_u192_inplace(&mut shifted_denominator, denominator_shift);
    let mut difference = vec![0_u64; u64_count];
    denominator_bits += denominator_shift;
    // Perform bit-wise division algorithm.
    let mut remaining_shifts = denominator_shift;
    while numerator_bits == denominator_bits {
        // NOTE: MSBs of numerator and denominator are aligned.
        // Even though MSB of numerator and denominator are aligned,
        // still possible numerator < shifted_denominator.
        if sub_uint(numerator, &shifted_denominator, &mut difference) != 0 {
            if remaining_shifts == 0 {break;}
            add_uint_inplace(&mut difference, numerator);
            left_shift_u192_inplace(quotient, 1);
            remaining_shifts -= 1;
        }
        quotient[0] |= 1;
        numerator_bits = get_significant_bit_count_uint(&difference);
        let mut numerator_shift = denominator_bits - numerator_bits;
        if numerator_shift > remaining_shifts {
            numerator_shift = remaining_shifts;
        }
        if numerator_bits > 0 {
            left_shift_u192(&difference, numerator_shift, numerator);
            numerator_bits += numerator_shift;
        } else {
            set_zero_uint(numerator);
        }
        left_shift_u192_inplace(quotient, numerator_shift);
        remaining_shifts -= numerator_shift;
    }
    if numerator_bits > 0 {
        right_shift_u192_inplace(numerator, denominator_shift);
    }
}




pub fn compare_uint(operand1: &[u64], operand2: &[u64]) -> std::cmp::Ordering {
    let n = std::cmp::max(operand1.len(), operand2.len());
    for i in (0..n).rev() {
        if operand1.len() <= i {
            if operand2[i] > 0 {return std::cmp::Ordering::Less;}
        } else if operand2.len() <= i {
            if operand1[i] > 0 {return std::cmp::Ordering::Greater;}
        } else {
            let cmp = operand1[i].cmp(&operand2[i]);
            if cmp != std::cmp::Ordering::Equal {return cmp;}
        }
    }
    std::cmp::Ordering::Equal
}

#[inline]
pub fn is_greater_than_uint(operand1: &[u64], operand2: &[u64]) -> bool {
    compare_uint(operand1, operand2) == std::cmp::Ordering::Greater
}

#[inline]
pub fn is_greater_than_or_equal_uint(operand1: &[u64], operand2: &[u64]) -> bool {
    compare_uint(operand1, operand2) != std::cmp::Ordering::Less
}

#[inline]
pub fn is_less_than_uint(operand1: &[u64], operand2: &[u64]) -> bool {
    compare_uint(operand1, operand2) == std::cmp::Ordering::Less
}

#[inline]
pub fn is_less_than_or_equal_uint(operand1: &[u64], operand2: &[u64]) -> bool {
    compare_uint(operand1, operand2) != std::cmp::Ordering::Greater
}

#[inline]
pub fn is_equal_uint(operand1: &[u64], operand2: &[u64]) -> bool {
    compare_uint(operand1, operand2) == std::cmp::Ordering::Equal
}







#[inline]
pub fn increment_uint_mod(operand: &[u64], modulus: &[u64], result: &mut [u64]) {
    let carry = increment_uint(operand, result) != 0;
    if carry || is_greater_than_or_equal_uint(result, modulus) {
        sub_uint_inplace(result, modulus);
    }
}

#[inline]
pub fn decrement_uint_mod(operand: &[u64], modulus: &[u64], result: &mut [u64]) {
    if decrement_uint(operand, result) != 0 {
        add_uint_inplace(result, modulus);
    }
}

#[inline]
pub fn negate_uint_mod(operand: &[u64], modulus: &[u64], result: &mut [u64]) {
    if is_zero_uint(operand) {
        set_zero_uint(result);
    } else {
        sub_uint(modulus, operand, result);
    }
}

#[inline]
pub fn div2_uint_mod(operand: &[u64], modulus: &[u64], result: &mut [u64]) {
    if (operand[0] & 1) != 0 {
        let carry = add_uint(operand, modulus, result);
        right_shift_uint_inplace(result, 1, result.len());
        if carry != 0 {
            set_bit_uint(result, result.len() * 64 - 1);
        }
    } else {
        right_shift_uint(operand, 1, result.len(), result);
    }
}

#[inline]
pub fn add_uint_mod(operand1: &[u64], operand2: &[u64], modulus: &[u64], result: &mut [u64]) {
    let carry = add_uint(operand1, operand2, result) != 0;
    if carry || is_greater_than_or_equal_uint(result, modulus) {
        sub_uint_inplace(result, modulus);
    }
}

#[inline]
pub fn add_uint_mod_inplace(operand1: &mut [u64], operand2: &[u64], modulus: &[u64]) {
    let carry = add_uint_inplace(operand1, operand2) != 0;
    if carry || is_greater_than_or_equal_uint(operand1, modulus) {
        sub_uint_inplace(operand1, modulus);
    }
}

#[inline]
pub fn sub_uint_mod(operand1: &[u64], operand2: &[u64], modulus: &[u64], result: &mut [u64]) {
    if sub_uint(operand1, operand2, result) != 0 {
        add_uint_inplace(result, modulus);
    }
}



#[inline]
pub fn multiply_many_u64(operands: &[u64], result: &mut[u64]) {
    if operands.is_empty() {return;}
    set_zero_uint(result); result[0] = operands[0];
    let mut temp_mpi = vec![0; operands.len()];
    for i in 1..operands.len() {
        multiply_uint_u64(result, operands[i], &mut temp_mpi);
        set_uint(&temp_mpi, i + 1, result);
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bits() {

        assert_eq!(get_significant_bit_count(0b0), 0);
        assert_eq!(get_significant_bit_count(0b11), 2);
        assert_eq!(get_significant_bit_count(0b110110110110110), 15);

        let sl: [u64; 2] = [1, 0b1];
        assert_eq!(get_significant_bit_count_uint(&sl), 65);
        assert_eq!(get_significant_uint64_count_uint(&sl), 2);
        assert_eq!(get_nonzero_uint64_count_uint(&sl), 2);

        let sl: [u64; 5] = [1, 1, 0b11111, 0, 0];
        assert_eq!(get_significant_bit_count_uint(&sl), 128 + 5);
        assert_eq!(get_significant_uint64_count_uint(&sl), 3);
        assert_eq!(get_nonzero_uint64_count_uint(&sl), 3);
        
        let sl: [u64; 5] = [1, 1, 0b11111, 0, 0b11];
        assert_eq!(get_significant_bit_count_uint(&sl), 256 + 2);
        assert_eq!(get_significant_uint64_count_uint(&sl), 5);
        assert_eq!(get_nonzero_uint64_count_uint(&sl), 4);

        assert_eq!(get_power_of_two(0), -1);
        assert_eq!(get_power_of_two(16), 4);
        assert_eq!(get_power_of_two(15), -1);

    }

    #[test]
    fn test_add() {

        let test_add_u64_carry = |x: u64, y: u64, carry: u8, out: u64, out_carry: u8| {
            let mut result = 0;
            assert_eq!(add_u64_carry(x, y, carry, &mut result), out_carry);
            assert_eq!(result, out);
        };
        test_add_u64_carry(1, 1, 0, 2, 0);
        test_add_u64_carry(1, 1, 1, 3, 0);
        test_add_u64_carry(0xffff_ffff_ffff_ffff, 0x1, 0, 0, 1);
        test_add_u64_carry(0xffff_ffff_ffff_ffff, 0x1, 1, 1, 1);
        test_add_u64_carry(0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 1, 0xffff_ffff_ffff_ffff, 1);

        
        let test_add_u64 = |x: u64, y: u64, out: u64, out_carry: u8| {
            let mut result = 0;
            assert_eq!(add_u64(x, y, &mut result), out_carry);
            assert_eq!(result, out);
        };
        test_add_u64(1, 1, 2, 0);
        test_add_u64(0xffff_ffff_ffff_ffff, 0x1, 0, 1);

        let test_add_u128 = 
            |o1: [u64; 2], o2: [u64; 2], o3:[u64; 2], carry: u8| {
                let mut result = [0_u64; 2];
                let c = add_u128(&o1, &o2, &mut result);
                assert_eq!(result, o3);
                assert_eq!(c, carry);
            };
        test_add_u128(
            [0x3418e9072c3a0a61, 0xca5ec19b9e101da3],
            [0xae3db791415d70f3, 0xe8163d4482118bd],
            [0xe256a0986d977b54, 0xd8e0256fe6313660], 0
        );
        test_add_u128(
            [0x5065d944029b0242, 0xdd1e40b9f3532fc8],
            [0x61f9f5c87eafc04c, 0xafbb16475d48fbb5],
            [0xb25fcf0c814ac28e, 0x8cd95701509c2b7d], 0x1
        );
        
    }

    #[test]
    fn test_multiply() {
        let test_mul_u64_u64 = |x:u64, y:u64, r0:u64, r1:u64| {
            let mut result = [0; 2]; multiply_u64_u64(x, y, &mut result);
            assert_eq!(result[0], r0); assert_eq!(result[1], r1);
        };
        test_mul_u64_u64(0, 0, 0, 0);
        test_mul_u64_u64(4, 4, 16, 0);
        test_mul_u64_u64(
            0xdeadbeefdeadbeef, 0x1234567890abcdef, 
            0xd3b89abeffbfa421, 0xfd5bdeee3ceb48c);

        let test_mul_uint_u64 =
        |x: &[u64], y: u64, rlen: usize, r:&[u64]| {
            let mut result = vec![0_u64; rlen];
            multiply_uint_u64(x, y, result.as_mut_slice());
            assert_eq!(result, r);
        };
        test_mul_uint_u64(&[], 0, 0, &[]);
        test_mul_uint_u64(&[], 1, 0, &[]);
        test_mul_uint_u64(&[], 0xbead005946621c1c, 1, &[0]);
        test_mul_uint_u64(&[0x38603a368dc7161c], 0x300b86532dbe7240, 1, &[0x1db6e47f6e65ff00]);
        test_mul_uint_u64(&[0x38603a368dc7161c], 0x300b86532dbe7240, 2, &[0x1db6e47f6e65ff00, 0xa9494a16aabb469]);
        test_mul_uint_u64(&[0xab0bc09f7b288a5e, 0x1613bdbc5066de5c], 0x611bbb8ef414913d, 3, &[0x9b38e7f2b6603666, 0xe96b9f5536fba9a, 0x85fdf261cebd933]);

        let test_mul_uint =
        |x: &[u64], y: &[u64], rlen: usize, r:&[u64]| {
            let mut result = vec![0_u64; rlen];
            multiply_uint(x, y, result.as_mut_slice());
            assert_eq!(result, r);
        };
        test_mul_uint(&[], &[], 0, &[]);
        test_mul_uint(&[], &[0xbead005946621c1c], 1, &[0]);
        test_mul_uint(
            &[0x2ab4f6ef5c8d6205, 0xfb49f1a6128fbd46, 0x66b72c7f86d79dd8], 
            &[0xf6639b8f1e77ba65, 0xeda2107393685f21, 0xd7df5e486c4f352d], 
            3, 
            &[0x2e2db4ae63524df9, 0x2b55e17efb94b806, 0xc3b4577b011a8cf4]
        );
        test_mul_uint(
            &[0x2ab4f6ef5c8d6205, 0xfb49f1a6128fbd46, 0x66b72c7f86d79dd8], 
            &[0xf6639b8f1e77ba65, 0xeda2107393685f21, 0xd7df5e486c4f352d], 
            6, 
            &[0x2e2db4ae63524df9, 0x2b55e17efb94b806, 0xc3b4577b011a8cf4, 0xa3e9fd16fdb71a0a, 0xb5a777d46f14340d, 0x569d75c32ea5f167]
        );
    }

    #[test]
    fn test_divide() {
        let test_divide_uint_inplace = 
        |numerator: &[u64], denominator: &[u64], quotient: &[u64], remainder: &[u64]| {
            let mut numerator = numerator.to_owned();
            let denominator = denominator.to_owned();
            let mut computed_quotient = numerator.clone();
            divide_uint_inplace(&mut numerator, &denominator, &mut computed_quotient);
            assert_eq!(remainder, &numerator[..remainder.len()]);
            assert_eq!(quotient, &computed_quotient[..quotient.len()]);
        };
        test_divide_uint_inplace(&[1], &[1], &[1], &[0]);
        test_divide_uint_inplace(&[16], &[1], &[16], &[0]);
        test_divide_uint_inplace(&[16], &[5], &[3], &[1]);
        test_divide_uint_inplace(
            &[0x7d6112ec7f1902b, 0x72870865d354e6f1], &[0xfe9aaaf7d7b4], 
            &[0xc51b92990d851bd2, 0x7327], &[0xeafb305ea283]
        );
        test_divide_uint_inplace(
            &[0x153e235f0fd3f123, 0x596ab8b0c3c7b048, 0xd00750c13822be9d, 0xde061e96884b8a96], &[0xe239675985a60044, 0xfc9a15316], 
            &[0xf5c6b5a03514f4a3, 0xe31f8f9a2e9b27c6, 0xe102bb3], &[0x89fdf476a590f5d7, 0x8c48bb986]
        );
        test_divide_uint_inplace(
            &[0x377aaf500976c], &[0x24df8dd80ab231e4, 0x7844224f4], 
            &[], &[0x377aaf500976c]
        );
    }

}