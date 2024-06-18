pub mod cipher1d;
pub mod cipher2d;
pub mod cipher3d;
pub mod bolt_cp;
pub mod bolt_cc_cr;
pub mod bolt_cc_dc;
pub mod cheetah;

pub use cipher1d::{Cipher1d, Plain1d};
pub use cipher2d::{Cipher2d, Plain2d};
pub use cheetah::MatmulHelperObjective;

pub fn ceil_two_power(n: usize) -> usize {
    let mut x = 1;
    while x < n {
        x <<= 1;
    }
    x
}
pub fn ceil_div(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}