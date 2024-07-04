//! Provide various utility functions and structs.
//! 
//! The utility objects in this submodule are not documented.
//! Use at your own risk.
#![allow(missing_docs)]

mod basic;
pub(crate) mod dwthandler;
mod galois;
pub(crate) mod hash;
pub mod he_standard_params;
mod number_theory;
mod ntt;
pub(crate) mod polysmallmod;
mod rns;
mod uintsmallmod;
pub mod rlwe;
mod random_generator;
pub(crate) mod scaling_variant;

// gather utilities in this module
pub use basic::*;
pub use ntt::*;
pub use number_theory::*;
pub use rns::*;
pub use uintsmallmod::*;
pub use galois::*;
pub use random_generator::{BlakeRNGFactory, BlakeRNG, PRNGSeed};

#[cfg(test)]
pub(crate) mod timer;
#[cfg(test)]
#[allow(unused)]
pub(crate) use timer::Timer;