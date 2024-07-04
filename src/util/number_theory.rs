use crate::util;
use crate::modulus::Modulus;
use rand::Rng;

const IS_PRIME_NUM_ROUNDS: usize = 40;
const TRY_PRIMITIVE_ROOT_NUM_ROUNDS: usize = 100;

pub fn naf(mut value: i32) -> Vec<i32> {
    let mut res = vec![];
    // Record the sign of the original value and compute abs
    let sign = value < 0;
    value = value.abs();
    // Transform to non-adjacent form (NAF)
    let mut i = 0;
    while value > 0 {
        let zi = if (value & 0x1) != 0 {2 - (value & 0x3)} else {0};
        value = (value - zi) >> 1;
        if zi != 0 {res.push((if sign {-zi} else {zi}) * (1 << i));}
        i += 1
    }
    res
}

pub fn gcd(x: u64, y: u64) -> u64 {
    if x < y {
        gcd(y, x)
    } else if y == 0 {
        x
    } else {
        let f = x % y;
        if f == 0 { y } else { gcd(y, f) }
    }
}


/** Extended GCD:
Returns (gcd, x, y) where gcd is the greatest common divisor of a and b.
The numbers x, y are such that gcd = ax + by.
*/
pub fn xgcd(mut x: u64, mut y: u64) -> (u64, i64, i64) {
    let mut prev_a = 1; let mut a = 0;
    let mut prev_b = 0; let mut b = 1;
    while y != 0 {
        let q = (x / y) as i64;
        let mut temp = (x % y) as i64;
        x = y;
        y = temp as u64;
        temp = a;
        a = prev_a - q * a;
        prev_a = temp;
        temp = b;
        b = prev_b - q * b;
        prev_b = temp;
    }
    (x, prev_a, prev_b)
}

pub fn are_coprime(x: u64, y: u64) -> bool {
    gcd(x, y) <= 1
}

#[allow(unused)]
pub fn conjugate_classes(modulus: u64, subgroup_generator: u64) -> Vec<u64> {
    let mut classes = vec![0];
    for i in 1..modulus {
        classes.push(
            if gcd(i, modulus) > 1 {0} else {i}
        );
    }
    for i in 0..modulus {
        if classes[i as usize] == 0 {continue;}
        if classes[i as usize] < i {
            // i is not a pivot, update its pivot
            classes[i as usize] = classes[(classes[i as usize]) as usize];
            continue;
        }
        // If i is a pivot, update other pivots to point to it
        let mut j = (i * subgroup_generator) % modulus;
        while classes[j as usize] != i {
            // Merge the equivalence classes of j and i
            // Note: if classes[j] != j then classes[j] will be updated later,
            // when we get to i = j and use the code for "i not pivot".
            let id = classes[j as usize];
            classes[id as usize] = i;
            j = (i * subgroup_generator) % modulus;
        }
    }
    classes
}

pub fn try_invert_u64_mod_u64(value: u64, modulus: u64, result: &mut u64) -> bool {
    if value == 0 {return false;}
    let (cd, a, _) = xgcd(value, modulus);
    if cd != 1 {
        false
    } else if a < 0 {
        *result = (modulus as i64 + a) as u64;
        true
    } else {
        *result = a as u64;
        true
    }
}

pub fn is_prime(modulus: &Modulus) -> bool {
    let value = modulus.value();
    // First check the simplest cases.
    if value < 2 {return false;}
    if value == 2 {return true;}
    if value % 2 == 0 {return false;}
    if value == 3 {return true;}
    if value % 3 == 0 {return false;}
    if value == 5 {return true;}
    if value % 5 == 0 {return false;}
    if value == 7 {return true;}
    if value % 7 == 0 {return false;}
    if value == 11 {return true;}
    if value % 11 == 0 {return false;}
    if value == 13 {return true;}
    if value % 13 == 0 {return false;}
    // Second, Miller-Rabin test.
    // Find r and odd d that satisfy value = 2^r * d + 1.
    let mut d = value - 1;
    let mut r = 0;
    while (d & 1) == 0 {d >>= 1; r += 1;}
    if r == 0 {return false;}
    // 1) Pick a = 2, check a^(value - 1).
    // 2) Pick a randomly from [3, value - 1], check a^(value - 1).
    // 3) Repeat 2) for another num_rounds - 2 times.
    let mut random_generator = rand::thread_rng();
    let num_rounds = IS_PRIME_NUM_ROUNDS;
    for i in 0..num_rounds {
        let a = if i==0 {2} else {random_generator.gen_range(3..value)};
        let mut x = util::exponentiate_u64_mod(a, d, modulus);
        if x == 1 || x == value - 1 {continue;}
        let mut count = 0;
        loop {
            x = util::multiply_u64_mod(x, x, modulus);
            count += 1;
            if (x == value - 1) || (count >= r - 1) {break;}
        }
        if x != value - 1 {return false;}
    };
    true
}

pub fn get_primes(factor: u64, bit_size: usize, mut count: usize) -> Vec<Modulus> {
    let mut destination = vec![];
    // Start with (2^bit_size - 1) / factor * factor + 1
    let mut value = ((0x1u64 << bit_size) - 1) / factor * factor + 1;
    let lower_bound = 0x1 << (bit_size - 1);
    while count > 0 && value > lower_bound {
        let new_mod = Modulus::new(value);
        if new_mod.is_prime() {
            destination.push(new_mod);
            count -= 1;
        }
        value -= factor;
    }
    if count > 0 {
        panic!("[Logic error] Failed to find enough qualifying primes.");
    }
    destination
}

#[allow(unused)]
pub fn get_prime(factor: u64, bit_size: usize) -> Modulus {
    let ret = get_primes(factor, bit_size, 1);
    ret.into_iter().next().unwrap()
}

pub fn is_primitive_root(root: u64, degree: u64, modulus: &Modulus) -> bool {
    if root == 0 {
        false
    } else {
        // We check if root is a degree-th root of unity in integers modulo modulus,
        // where degree is a power of two. It suffices to check that root^(degree/2)
        // is -1 modulo modulus.
        util::exponentiate_u64_mod(root, degree >> 1, modulus) == (modulus.value() - 1)
    }
}

pub fn try_primitive_root(degree: u64, modulus: &Modulus, destination: &mut u64) -> bool {
    // We need to divide modulus-1 by degree to get the size of the quotient group
    let size_entire_group = modulus.value() - 1;
    // Compute size of quotient group
    let size_quotient_group = size_entire_group / degree;
    // size_entire_group must be divisible by degree, or otherwise the primitive root does not
    // exist in integers modulo modulus
    if size_entire_group - size_quotient_group * degree != 0 {
        return false;
    }
    let mut attempt_counter = 0;
    let mut random_generator = rand::thread_rng();
    loop {
        attempt_counter += 1;
        // Set destination to be a random number modulo modulus.
        *destination = util::barrett_reduce_u64(random_generator.gen::<u64>(), modulus);
        
        // Raise the random number to power the size of the quotient
        // to get rid of irrelevant part
        *destination = util::exponentiate_u64_mod(*destination, size_quotient_group, modulus);
        
        // Stop condition
        let cond = !is_primitive_root(*destination, degree, modulus) && (attempt_counter < TRY_PRIMITIVE_ROOT_NUM_ROUNDS);
        if !cond {break;}
    }
    is_primitive_root(*destination, degree, modulus)
}

pub fn try_minimal_primitive_root(degree: u64, modulus: &Modulus, destination: &mut u64) -> bool {
    let mut root = 0;
    if !try_primitive_root(degree, modulus, &mut root) {return false;}
    let generator_sq = util::multiply_u64_mod(root, root, modulus);
    let mut current_generator = root;
    // destination is going to always contain the smallest generator found
    for _ in 0..((degree+1)/2) {
        // If our current generator is strictly smaller than destination,
        // update
        if current_generator < root {root = current_generator;}
        // Then move on to the next generator
        current_generator = util::multiply_u64_mod(current_generator, generator_sq, modulus);
    }
    *destination = root; true
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_gcd() {
        assert_eq!(1, gcd(1, 1));
        assert_eq!(1, gcd(2, 1));
        assert_eq!(1, gcd(1, 2));
        assert_eq!(2, gcd(2, 2));
        assert_eq!(3, gcd(6, 15));
        assert_eq!(3, gcd(15, 6));
        assert_eq!(1, gcd(7, 15));
        assert_eq!(1, gcd(15, 7));
        assert_eq!(1, gcd(7, 15));
        assert_eq!(3, gcd(11112, 44445));

        assert_eq!(xgcd(7, 7), (7, 0, 1));
        assert_eq!(xgcd(2, 2), (2, 0, 1));
        assert_eq!(xgcd(1, 1), (1, 0, 1));
        assert_eq!(xgcd(1, 2), (1, 1, 0));
        assert_eq!(xgcd(5, 6), (1, -1, 1));
        assert_eq!(xgcd(13, 19), (1, 3, -2));
        assert_eq!(xgcd(14, 21), (7, -1, 1));
        assert_eq!(xgcd(2, 1), (1, 0, 1));
        assert_eq!(xgcd(6, 5), (1, 1, -1));
        assert_eq!(xgcd(19, 13), (1, -2, 3));
        assert_eq!(xgcd(21, 14), (7, 1, -1));
    }

    #[test]
    fn test_try_invert_uint_mod() {
        let closure = |input: u64, modulus: u64, result: u64, success: bool| {
            let mut r: u64 = 0; 
            assert_eq!(success, try_invert_u64_mod_u64(input, modulus, &mut r));
            if success {assert_eq!(r, result);}
        };
        closure(1, 2, 1, true);
        closure(2, 2, 0, false);
        closure(3, 2, 1, true);
        closure(0xffffff, 2, 1, true);
        closure(0xfffffe, 2, 0, false);
        closure(12345, 3, 0, false);
        closure(5, 19, 4, true);
        closure(4, 19, 5, true);
    }

    #[test]
    fn test_is_prime() {
        assert!(!is_prime(&Modulus::new(0)));
        assert!(is_prime(&Modulus::new(2)));
        assert!(is_prime(&Modulus::new(3)));
        assert!(!is_prime(&Modulus::new(4)));
        assert!(is_prime(&Modulus::new(5)));
        assert!(!is_prime(&Modulus::new(221)));
        assert!(is_prime(&Modulus::new(65537)));
        assert!(!is_prime(&Modulus::new(65536)));
        assert!(is_prime(&Modulus::new(59399)));
        assert!(is_prime(&Modulus::new(72307)));
        assert!(!is_prime(&Modulus::new(72307 * 59399)));
        assert!(is_prime(&Modulus::new(36893488147419103)));
        assert!(!is_prime(&Modulus::new(36893488147419107)));
    }

    #[test]
    fn test_primitive_root() {

        let closure = |modulus: u64, degree: u64, corrects: &[u64]| {
            let mut r: u64 = 0;
            let modulus = Modulus::new(modulus);
            let success = try_primitive_root(degree, &modulus, &mut r);
            assert!(success);
            assert!(corrects.iter().any(|&x| x == r));
        };
        closure(11, 2, &[10]);
        closure(29, 2, &[28]);
        closure(29, 4, &[12, 17]);
        closure(1234565441, 2, &[1234565440]);
        closure(1234565441, 8, &[984839708, 273658408, 249725733, 960907033]);

        let modulus = Modulus::new(11);
        assert!(is_primitive_root(10, 2, &modulus));
        assert!(!is_primitive_root(9, 2, &modulus));
        assert!(!is_primitive_root(10, 4, &modulus));
        let modulus = Modulus::new(29);
        assert!(is_primitive_root(28, 2, &modulus));
        assert!(is_primitive_root(12, 4, &modulus));
        assert!(!is_primitive_root(12, 2, &modulus));
        assert!(!is_primitive_root(12, 8, &modulus));
        let modulus = Modulus::new(1234565441);
        assert!(is_primitive_root(1234565440, 2, &modulus));
        assert!(is_primitive_root(960907033, 8, &modulus));
        assert!(is_primitive_root(1180581915, 16, &modulus));
        assert!(!is_primitive_root(1180581915, 32, &modulus));
        assert!(!is_primitive_root(1180581915, 8, &modulus));
        assert!(!is_primitive_root(1180581915, 2, &modulus));

        let closure = |degree: u64, modulus: &Modulus, result: u64| {
            let mut r = 0; 
            assert!(try_minimal_primitive_root(degree, modulus, &mut r));
            assert_eq!(r, result);
        };
        let modulus = Modulus::new(11);
        closure(2, &modulus, 10);
        let modulus = Modulus::new(29);
        closure(2, &modulus, 28);
        closure(4, &modulus, 12);
        let modulus = Modulus::new(1234565441);
        closure(2, &modulus, 1234565440);
        closure(8, &modulus, 249725733);

    }
}