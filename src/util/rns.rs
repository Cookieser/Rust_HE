use crate::{
    Modulus,
    util::NTTTables,
    util::{self, HE_INTERNAL_MOD_BIT_COUNT},
    util::MultiplyU64ModOperand,
    polymod
};

use super::set_zero_uint;

#[derive(Clone)]
pub struct RNSBase {
    base: Vec<Modulus>,
    base_prod: Vec<u64>,
    punctured_prod: Vec<Vec<u64>>,
    inv_punctured_prod_mod_base: Vec<MultiplyU64ModOperand>,
}

fn multiply_many_u64_except(operands: &[u64], except: usize, result: &mut[u64]) {
    let count = operands.len();
    set_zero_uint(result); 
    if count == 1 && except == 0 {
        result[0] = 1; return;
    }
    result[0] = if except == 0 {1} else {operands[0]};
    let mut temp_mpi = vec![0; count];
    for i in 1..count {
        if i != except {
            util::multiply_uint_u64(result, operands[i], &mut temp_mpi[0..i+1]);
            util::set_uint(&temp_mpi, i+1, result);
        }
    }
}

#[allow(unused)]
impl RNSBase {
    
    pub fn new(rnsbase: &[Modulus]) -> Result<Self, String> {
        if rnsbase.is_empty() {
            return Err("[Invalid argument] RNSBase cannot be empty.".to_string());
        }
        let n = rnsbase.len();
        for i in 0..n {
            if rnsbase[i].is_zero() {
                return Err("[Invalid argument] RNSBase modulus cannot be zero.".to_string());
            }
            for j in 0..i {
                if !util::are_coprime(rnsbase[i].value(), rnsbase[j].value()) {
                    return Err("[Invalid argument] RNSBase moduli must be pairwise coprime.".to_string());
                }
            }
        }
        // Base is good; now copy it.
        let ret = RNSBase {
            base: rnsbase.to_vec(),
            base_prod: vec![],
            punctured_prod: vec![],
            inv_punctured_prod_mod_base: vec![]
        };
        ret.initialize()
    }

    fn initialize(mut self) -> Result<Self, String> {
        let n = self.base.len();
        // Verify the size is not too large.
        let _ = n * n;
        let mut base_prod = vec![0; n];
        let mut punctured_prod = vec![vec![0_u64; n]; n];
        let mut inv_punctured_prod_mod_base = vec![MultiplyU64ModOperand::default(); n];
        
        if n > 1 {
            let rnsbase_values = self.base.iter()
                .map(|x| x.value()).collect::<Vec<_>>();
            // create punctured products
            for i in 0..n {
                multiply_many_u64_except(&rnsbase_values, i, &mut punctured_prod[i]);
            }
            // Compute the full product
            util::multiply_uint_u64(&punctured_prod[0], self.base[0].value(), &mut base_prod);
            // Compute inverses of punctured products mod primes
            let mut invertible = true;
            for i in 0..n {
                let temp = util::modulo_uint(&punctured_prod[i], &self.base[i]);
                let mut inv_temp = 0;
                invertible = invertible && util::try_invert_u64_mod(temp, &self.base[i], &mut inv_temp);
                if !invertible {
                    return Err("[Invalid argument] RNSBase product is not invertible.".to_string());
                }
                inv_punctured_prod_mod_base[i] = MultiplyU64ModOperand::new(inv_temp, &self.base[i]);
            }
        } else {
            base_prod[0] = self.base[0].value();
            punctured_prod[0] = vec![1];
            inv_punctured_prod_mod_base[0] = MultiplyU64ModOperand::new(1, &self.base[0]);
        }
        self.base_prod = base_prod;
        self.punctured_prod = punctured_prod;
        self.inv_punctured_prod_mod_base = inv_punctured_prod_mod_base;
        Ok(self)
    }

    pub fn contains(&self, modulus: &Modulus) -> bool {
        self.base.iter().any(|x| x == modulus)
    }

    pub fn is_subbase_of(&self, superbase: &Self) -> bool {
        self.base.iter().all(|x| superbase.contains(x))
    }

    pub fn is_superbase_of(&self, subbase: &Self) -> bool {
        subbase.is_subbase_of(self)
    }

    pub fn is_proper_subbase_of(&self, superbase: &Self) -> bool {
        self.base.len() < superbase.base.len() && self.is_subbase_of(superbase)
    }

    pub fn is_proper_superbase_of(&self, subbase: &Self) -> bool {
        subbase.is_proper_subbase_of(self) // Note: in original seal there is a typo.
    }

    pub fn extend_modulus(&self, modulus: &Modulus) -> Result<Self, String> {
        if modulus.is_zero() {return Err("[Invalid argument] Modulus cannot be zero.".to_string());}
        if self.base.iter().any(|x| !util::are_coprime(x.value(), modulus.value())) {
            return Err("[Invalid argument] New modulus is not coprime with existing ones.".to_string());
        }
        let mut base = self.base.clone(); base.push(*modulus);
        let ret = RNSBase {
            base,
            base_prod: vec![],
            punctured_prod: vec![],
            inv_punctured_prod_mod_base: vec![]
        };
        ret.initialize()
    }

    pub fn extend(&self, other: &Self) -> Result<Self, String> {
        if self.base.iter().any(|x| {
            other.base.iter().any(|y| !util::are_coprime(x.value(), y.value()))
        }) {
            return Err("[Invalid argument] New modulus is not coprime with existing ones.".to_string());
        }
        let mut base = self.base.clone(); base.extend(other.base.clone());
        let ret = RNSBase {
            base,
            base_prod: vec![],
            punctured_prod: vec![],
            inv_punctured_prod_mod_base: vec![]
        };
        ret.initialize()
    }

    pub fn drop(&self, modulus: &Modulus) -> Result<Self, String> {
        if self.base.len() == 1 {
            return Err("[Logic error] Cannot drop the only modulus.".to_string());
        }
        if !self.contains(modulus) {
            return Err("[Logic error] Does not contain this modulus.".to_string());
        }
        
        let base = self.base.iter()
            .filter(|&x| x != modulus).copied()
            .collect::<Vec<_>>();
        let ret = RNSBase {
            base,
            base_prod: vec![],
            punctured_prod: vec![],
            inv_punctured_prod_mod_base: vec![]
        };
        ret.initialize()
    }

    pub fn drop_last(&self) -> Result<Self, String> {
        let modulus = self.base[self.base.len() - 1];
        self.drop(&modulus)
    }
    
    pub fn decompose(&self, value: &mut[u64]) {
        assert_eq!(value.len(), self.base.len(), "[Invalid argument] Value should have same length as base.");
        if self.base.len() > 1 {
            let copied = value.to_vec();
            for i in 0..self.base.len() {
                value[i] = util::modulo_uint(&copied, &self.base[i]);
            }
        }
    }

    pub fn decompose_array(&self, value: &mut[u64]) {
        assert_eq!(value.len() % self.base.len(), 0, "[Invalid argument] Value length is not multiple of base length.");
        let count = value.len() / self.base.len();
        let size = self.base.len();
        if size > 1 {
            let copied = value.to_vec();
            self.base.iter().enumerate().for_each(|(i, base)| {
                copied.chunks(size).enumerate().for_each(|(j, chunk)| {
                    value[i * count + j] = util::modulo_uint(chunk, base);
                });
            });
        }
    } 

    pub fn compose(&self, value: &mut[u64]) {
        assert_eq!(value.len(), self.base.len(), "[Invalid argument] Value should have same length as base.");
        let size = self.base.len();
        if size > 1 {
            let temp_value = value.to_vec();
            util::set_zero_uint(value);
            let mut temp_mpi = vec![0; size];
            for i in 0..size {
                let temp_prod = util::multiply_u64operand_mod(temp_value[i], 
                    &self.inv_punctured_prod_mod_base[i], &self.base[i]);
                util::multiply_uint_u64(&self.punctured_prod[i], temp_prod, &mut temp_mpi);
                util::add_uint_mod_inplace(value, &temp_mpi, &self.base_prod);
            }
        }
    }

    pub fn compose_array(&self, value: &mut[u64]) {
        use itertools::multizip;
        assert_eq!(value.len() % self.base.len(), 0, "[Invalid argument] Value length is not multiple of base length.");
        let count = value.len() / self.base.len();
        let size = self.base.len();
        if size > 1 {
            let mut temp_array = vec![0; size * count];
            for i in 0..count {for j in 0..size {
                temp_array[j + (i * size)] = value[(j * count) + i];
            }}
            util::set_zero_uint(value);
            let mut temp_mpi = vec![0; size];
            value.chunks_mut(size).zip(temp_array.chunks(size)).enumerate().for_each(|(_i, (value_chunk, temp_array_chunk))| {
                multizip((temp_array_chunk.iter(), self.inv_punctured_prod_mod_base.iter(), self.punctured_prod.iter(), self.base.iter())).for_each(|(temp_array_chunk, inv_punctured_prod_mod_base, punctured_prod, base)| {
                    let temp_prod = util::multiply_u64operand_mod(*temp_array_chunk, 
                        inv_punctured_prod_mod_base, base);
                    util::multiply_uint_u64(punctured_prod, temp_prod, &mut temp_mpi);
                    util::add_uint_mod_inplace(value_chunk, &temp_mpi, &self.base_prod);
                });
            });

        }
    }

    pub fn len(&self) -> usize {self.base.len()}
    pub fn is_empty(&self) -> bool {self.base.is_empty()}
    pub fn punctured_prod(&self) -> &[Vec<u64>] {&self.punctured_prod}
    pub fn base(&self) -> &[Modulus] {&self.base}
    pub fn base_at(&self, index: usize) -> &Modulus {&self.base[index]}
    pub fn inv_punctured_prod_mod_base(&self) -> &[MultiplyU64ModOperand] {&self.inv_punctured_prod_mod_base}
    pub fn base_prod(&self) -> &[u64] {&self.base_prod}

}

impl std::ops::Index<usize> for RNSBase {
    type Output = Modulus;
    fn index(&self, index: usize) -> &Self::Output {
        &self.base[index]
    }
}

struct BaseConverter {
    ibase: RNSBase,
    obase: RNSBase,
    base_change_matrix: Vec<Vec<u64>>,
}

impl BaseConverter {

    pub fn new(ibase: &RNSBase, obase: &RNSBase) -> Self {
        BaseConverter{
            ibase: ibase.clone(), 
            obase: obase.clone(), 
            base_change_matrix: vec![]
        }.initialize()
    }

    pub fn initialize(mut self) -> Self {
        let mut base_change_matrix = vec![vec![0; self.ibase.len()]; self.obase.len()];
        for i in 0..self.obase.len() {
            for j in 0..self.ibase.len() {
                base_change_matrix[i][j] = 
                    util::modulo_uint(&self.ibase.punctured_prod()[j], self.obase.base_at(i))
            }
        }
        self.base_change_matrix = base_change_matrix;
        self
    }

    #[allow(unused)]
    pub fn fast_convert(&self, input: &[u64], output: &mut[u64]) {
        let ibase_size = self.ibase.len();
        let obase_size = self.obase.len();
        let mut temp = vec![0; ibase_size];
        for i in 0..ibase_size {
            temp[i] = util::multiply_u64operand_mod(input[i],
                &self.ibase.inv_punctured_prod_mod_base()[i], self.ibase.base_at(i));
        }
        for i in 0..obase_size {
            output[i] = util::dot_product_mod(&temp, &self.base_change_matrix[i], self.obase.base_at(i));
        }
    }

    pub fn fast_convert_array(&self, input: &[u64], output: &mut[u64]) {
        let ibase_size = self.ibase.len();
        let obase_size = self.obase.len();
        let count = input.len() / ibase_size;
        assert_eq!(count * ibase_size, input.len(), "[Invalid argument] Input should contain count * ibase_size items.");
        assert_eq!(count * obase_size, output.len(), "[Invalid argument] Output should contain count * obase_size items.");
        let mut temp = vec![0; count * ibase_size];
        for i in 0..ibase_size {
            let op = &self.ibase.inv_punctured_prod_mod_base()[i];
            let base = &self.ibase.base_at(i);
            if op.operand == 1 {
                for j in 0..count {
                    temp[j * ibase_size + i] = util::barrett_reduce_u64(input[i * count + j], base);
                }
            } else {
                for j in 0..count {
                    temp[j * ibase_size + i] = util::multiply_u64operand_mod(input[i * count + j], op, base);
                }
            }
        }
        for i in 0..obase_size {
            for j in 0..count {
                output[i * count + j] = util::dot_product_mod(
                    &temp[(j * ibase_size) .. ((j + 1) * ibase_size)],
                    &self.base_change_matrix[i], self.obase.base_at(i))
            }
        }
    }

    // See "An Improved RNS Variant of the BFV Homomorphic Encryption Scheme" (CT-RSA 2019) for details
    pub fn exact_convey_array(&self, input: &[u64], output: &mut[u64]) {
        let ibase_size = self.ibase.len();
        let obase_size = self.obase.len();
        let count = input.len() / ibase_size;
        assert_eq!(obase_size, 1, "[Invalid argument] Output base should contain only 1 modulus.");
        // Note that the stride size is ibase_size
        let mut temp = vec![0; count * ibase_size];
        let mut v = vec![0f64; count * ibase_size];
        let mut aggregated_rounded_v = vec![0; count];
        for i in 0..ibase_size {
            let ibase_modulus = &self.ibase.base_at(i);
            let divisor = ibase_modulus.value() as f64;
            let op = &self.ibase.inv_punctured_prod_mod_base()[i];
            if op.operand == 1 {
                for j in 0..count {
                    temp[j * ibase_size + i] = util::barrett_reduce_u64(input[i * count + j], ibase_modulus);
                    let dividend = temp[j * ibase_size + i] as f64;
                    v[j * ibase_size + i] = dividend / divisor;
                }
            } else {
                for j in 0..count {
                    temp[j * ibase_size + i] = util::multiply_u64operand_mod(input[i * count + j], op, ibase_modulus);
                    let dividend = temp[j * ibase_size + i] as f64;
                    v[j * ibase_size + i] = dividend / divisor;
                }
            }
        }
        // Aggregate v and rounding
        for i in 0..count {
            let aggregated_v: f64 = v[(i*ibase_size)..((i+1)*ibase_size)].iter().sum();
            aggregated_rounded_v[i] = aggregated_v.round() as u64;
        }
        let p = &self.obase.base_at(0);
        let q_mod_p = util::modulo_uint(self.ibase.base_prod(), p);
        let base_change_matrix_first = self.base_change_matrix[0].as_slice();
        for j in 0..count {
            let sum_mod_obase = util::dot_product_mod(
                &temp[(j * ibase_size) .. ((j+1) * ibase_size)], 
                base_change_matrix_first, p);
            let v_q_mod_p = util::multiply_u64_mod(aggregated_rounded_v[j], q_mod_p, p);
            output[j] = util::sub_u64_mod(sum_mod_obase, v_q_mod_p, p);
        }   
    }

}

#[allow(non_snake_case)]
pub struct RNSTool { // NOTE: Maybe use Box<...> for better performance.
    coeff_count: usize,
    base_q: RNSBase,
    base_B: RNSBase,
    base_Bsk: RNSBase,
    base_Bsk_m_tilde: RNSBase,
    base_t_gamma: Option<RNSBase>,
    base_q_to_Bsk_conv: BaseConverter,
    base_q_to_m_tilde_conv: BaseConverter,
    base_B_to_q_conv: BaseConverter,
    base_B_to_m_sk_conv: BaseConverter,
    base_q_to_t_gamma_conv: Option<BaseConverter>,
    base_q_to_t_conv: Option<BaseConverter>,
    inv_prod_q_mod_Bsk: Vec<MultiplyU64ModOperand>,
    neg_inv_prod_q_mod_m_tilde: MultiplyU64ModOperand,
    inv_prod_B_mod_m_sk: MultiplyU64ModOperand,
    inv_gamma_mod_t: Option<MultiplyU64ModOperand>,
    prod_B_mod_q: Vec<u64>,
    inv_m_tilde_mod_Bsk: Vec<MultiplyU64ModOperand>,
    prod_q_mod_Bsk: Vec<u64>,
    neg_inv_q_mod_t_gamma: Option<Vec<MultiplyU64ModOperand>>,
    prod_t_gamma_mod_q: Option<Vec<MultiplyU64ModOperand>>,
    inv_q_last_mod_q: Vec<MultiplyU64ModOperand>,
    base_Bsk_ntt_tables: Vec<NTTTables>,
    m_tilde: Modulus,
    m_sk: Modulus,
    t: Modulus,
    gamma: Modulus,
    inv_q_last_mod_t: u64,
    // q_last_mod_t: u64
}

#[allow(non_snake_case)]
// #[allow(unused)]
impl RNSTool {

    pub fn base_q(&self) -> &RNSBase {
        &self.base_q
    }

    pub fn base_Bsk(&self) -> &RNSBase {
        &self.base_Bsk
    }

    pub fn base_Bsk_m_tilde(&self) -> &RNSBase {
        &self.base_Bsk_m_tilde
    }

    pub fn base_B(&self) -> &RNSBase {
        &self.base_B
    }

    pub fn base_t_gamma(&self) -> &Option<RNSBase> {
        &self.base_t_gamma
    }

    pub fn inv_prod_q_mod_Bsk(&self) -> &Vec<MultiplyU64ModOperand> {
        &self.inv_prod_q_mod_Bsk
    }

    pub fn neg_inv_prod_q_mod_m_tilde(&self) -> &MultiplyU64ModOperand {
        &self.neg_inv_prod_q_mod_m_tilde
    }

    pub fn inv_prod_B_mod_m_sk(&self) -> &MultiplyU64ModOperand {
        &self.inv_prod_B_mod_m_sk
    }

    pub fn inv_gamma_mod_t(&self) -> &Option<MultiplyU64ModOperand> {
        &self.inv_gamma_mod_t
    }

    pub fn prod_B_mod_q(&self) -> &Vec<u64> {
        &self.prod_B_mod_q
    }

    pub fn base_Bsk_ntt_tables(&self) -> &Vec<NTTTables> {
        &self.base_Bsk_ntt_tables
    }

    pub fn inv_q_last_mod_q(&self) -> &Vec<MultiplyU64ModOperand> {
        &self.inv_q_last_mod_q
    }

    pub fn inv_q_last_mod_t(&self) -> u64 {
        self.inv_q_last_mod_t
    }

}

impl RNSTool {
    
    #[allow(non_snake_case)]
    pub fn new(poly_modulus_degree: usize, q: &RNSBase, t: &Modulus) -> Result<Self, String> {
        
        if q.len() < util::HE_COEFF_MOD_COUNT_MIN || q.len() > util::HE_COEFF_MOD_COUNT_MAX {
            return Err("[Invalid argument] RNSBase length invalid.".to_string());
        }

        let coeff_count_power = util::get_power_of_two(poly_modulus_degree as u64);
        if !(
            (coeff_count_power >= 0) &&
            (util::HE_POLY_MOD_DEGREE_MIN..=util::HE_POLY_MOD_DEGREE_MAX).contains(&poly_modulus_degree)
        ) {
            return Err("[Invalid argument] Poly modulus degree invalid.".to_string());
        }

        // Allocate memory for the bases q, B, Bsk, Bsk U m_tilde, t_gamma
        let base_q_size = q.len();

        // In some cases we might need to increase the size of the base B by one, namely we require
        // K * n * t * q^2 < q * prod(B) * m_sk, where K takes into account cross terms when larger size ciphertexts
        // are used, and n is the "delta factor" for the ring. We reserve 32 bits for K * n. Here the coeff modulus
        // primes q_i are bounded to be HE_USER_MOD_BIT_COUNT_MAX (60) bits, and all primes in B and m_sk are
        // HE_INTERNAL_MOD_BIT_COUNT (61) bits.
        let total_coeff_bit_count = util::get_significant_bit_count_uint(q.base_prod());

        let mut base_B_size = base_q_size;
        if 32 + t.bit_count() + total_coeff_bit_count >= util::HE_INTERNAL_MOD_BIT_COUNT * base_q_size + HE_INTERNAL_MOD_BIT_COUNT {
            base_B_size += 1;
        }

        let base_Bsk_size = base_B_size + 1;
        let base_Bsk_m_tilde_size = base_Bsk_size + 1;

        // let mut base_t_gamma_size = 0;

        // Sample primes for B and two more primes: m_sk and gamma
        let coeff_count = poly_modulus_degree;
        let baseconv_primes = util::get_primes(
            2 * coeff_count as u64, util::HE_INTERNAL_MOD_BIT_COUNT,
            base_Bsk_m_tilde_size
        );
        let mut baseconv_primes_iter = baseconv_primes.iter();
        let m_sk = *baseconv_primes_iter.next().unwrap();
        let gamma = *baseconv_primes_iter.next().unwrap();
        let base_B_primes = baseconv_primes_iter.copied().collect::<Vec<_>>();

        // Set m_tilde to a non-prime value
        let m_tilde = Modulus::new(1 << 32);

        // Populate the base arrays
        let base_q = q.clone();
        let base_B = RNSBase::new(&base_B_primes)?;
        let base_Bsk = base_B.extend_modulus(&m_sk)?;
        let base_Bsk_m_tilde = base_Bsk.extend_modulus(&m_tilde)?;

        // Set up t-gamma base if t_ is non-zero (using BFV)
        let base_t_gamma = if t.is_zero() {None} else {
            Some(RNSBase::new(&[*t, gamma])?)
        };

        // Generate the Bsk NTTTables; these are used for NTT after base extension to Bsk
        let base_Bsk_ntt_tables = 
            NTTTables::create_ntt_tables(coeff_count_power as usize, base_Bsk.base()).unwrap();

        let base_q_to_t_conv = if t.is_zero() {None} else {
            Some(BaseConverter::new(&base_q, &RNSBase::new(&[*t])?))
        };

        let base_q_to_Bsk_conv = BaseConverter::new(&base_q, &base_Bsk);
        let base_q_to_m_tilde_conv = BaseConverter::new(&base_q, &RNSBase::new(&[m_tilde])?);
        let base_B_to_q_conv = BaseConverter::new(&base_B, &base_q);
        let base_B_to_m_sk_conv = BaseConverter::new(&base_B, &RNSBase::new(&[m_sk])?);

        let base_q_to_t_gamma_conv = base_t_gamma.as_ref().map(|base_t_gamma| BaseConverter::new(&base_q, base_t_gamma));

        // Compute prod(B) mod q
        let prod_B_mod_q = base_q.base().iter().map(|x| {
            util::modulo_uint(base_B.base_prod(), x)
        }).collect::<Vec<_>>();

        // Compute prod(q)^(-1) mod Bsk
        let inv_prod_q_mod_Bsk = base_Bsk.base().iter().map(|modulus| {
            let mut temp = util::modulo_uint(base_q.base_prod(), modulus);
            assert!(util::try_invert_u64_mod(temp, modulus, &mut temp), "[Logic error] Unable to invert base_q product.");
            MultiplyU64ModOperand::new(temp, modulus)
        }).collect::<Vec<_>>();

        // Compute prod(B)^(-1) mod m_sk
        let mut temp = util::modulo_uint(base_B.base_prod(), &m_sk);
        assert!(util::try_invert_u64_mod(temp, &m_sk, &mut temp), "[Logic error] Unable to invert base_B product.");
        let inv_prod_B_mod_m_sk = MultiplyU64ModOperand::new(temp, &m_sk);

        // Compute m_tilde^(-1) mod Bsk
        let inv_m_tilde_mod_Bsk = base_Bsk.base().iter().map(|modulus| {
            assert!(
                util::try_invert_u64_mod(
                    util::barrett_reduce_u64(m_tilde.value(), modulus), 
                    modulus, &mut temp
                ), "[Logic error] Unable to invert m_tilde."
            );
            MultiplyU64ModOperand::new(temp, modulus)
        }).collect::<Vec<_>>();

        // Compute prod(q)^(-1) mod m_tilde
        let mut temp = util::modulo_uint(base_q.base_prod(), &m_tilde);
        assert!(util::try_invert_u64_mod(temp, &m_tilde, &mut temp), "[Logic error] Unable to invert base_B product.");
        let neg_inv_prod_q_mod_m_tilde = MultiplyU64ModOperand::new(
            util::negate_u64_mod(temp, &m_tilde), &m_tilde
        );

        // Compute prod(q) mod Bsk
        let prod_q_mod_Bsk = base_Bsk.base().iter().map(|modulus| {
            util::modulo_uint(&base_q.base_prod, modulus)
        }).collect::<Vec<_>>();

        let mut inv_gamma_mod_t = None;
        let mut prod_t_gamma_mod_q = None;
        let mut neg_inv_q_mod_t_gamma = None;
        let mut inv_q_last_mod_t = 1;
        // let mut q_last_mod_t = 1;
        if let Some(base_t_gamma) = &base_t_gamma {

            // Compute gamma^(-1) mod t
            let mut temp = 0;
            assert!(
                util::try_invert_u64_mod(t.reduce(gamma.value()), t, &mut temp),
                "[Logic error] Unable to invert gamma mod t."
            );
            inv_gamma_mod_t = Some(MultiplyU64ModOperand::new(temp, t));

            // Compute prod({t, gamma}) mod q
            prod_t_gamma_mod_q = Some(base_q.base().iter().map(|x| {
                MultiplyU64ModOperand::new(
                    util::multiply_u64_mod(
                        base_t_gamma.base_at(0).value(), 
                        base_t_gamma.base_at(1).value(), x
                    ), x
                )
            }).collect::<Vec<_>>());

            // Compute -prod(q)^(-1) mod {t, gamma}
            neg_inv_q_mod_t_gamma = Some(base_t_gamma.base().iter().map(|x| {
                let mut operand = util::modulo_uint(base_q.base_prod(), x);
                assert!(
                    util::try_invert_u64_mod(operand, x, &mut operand),
                    "[Logic error] Unable to invert base_q mod mod t_gamma."
                );
                MultiplyU64ModOperand::new(util::negate_u64_mod(operand, x), x)
            }).collect::<Vec<_>>());
        }

        // Compute q[last]^(-1) mod q[i] for i = 0..last-1
        // This is used by modulus switching and rescaling
        let mut inv_q_last_mod_q = vec![MultiplyU64ModOperand::default(); base_q_size - 1];
        let last_q = &(base_q.base_at(base_q_size - 1));
        for i in 0..base_q_size - 1 {
            let mut temp = 0; let b = &(base_q.base_at(i));
            assert!(
                util::try_invert_u64_mod(last_q.value(), b, &mut temp),
                "[Logic error] Unable to invert q_last mod q_i."
            );
            inv_q_last_mod_q[i] = MultiplyU64ModOperand::new(temp, b);
        }
            

        if !t.is_zero() {
            let mut temp = 0;
            assert!(
                util::try_invert_u64_mod(last_q.value(), t, &mut temp),
                "[Logic error] Unable to invert last_q mod t."
            );
            inv_q_last_mod_t = temp;
            // q_last_mod_t = util::barrett_reduce_u64(last_q.value(), &t);
        }

        Ok(RNSTool {
            t: *t,
            coeff_count,
            m_tilde,
            m_sk,
            gamma,
            base_q,
            base_B,
            base_Bsk,
            base_Bsk_m_tilde,
            base_t_gamma,
            base_q_to_Bsk_conv,
            base_q_to_m_tilde_conv,
            base_B_to_q_conv,
            base_q_to_t_conv,
            base_q_to_t_gamma_conv,
            base_B_to_m_sk_conv,
            prod_B_mod_q,
            inv_prod_q_mod_Bsk,
            inv_prod_B_mod_m_sk,
            inv_m_tilde_mod_Bsk,
            neg_inv_prod_q_mod_m_tilde,
            prod_q_mod_Bsk,
            inv_gamma_mod_t,
            prod_t_gamma_mod_q,
            neg_inv_q_mod_t_gamma,
            inv_q_last_mod_q,
            inv_q_last_mod_t,
            // q_last_mod_t,
            base_Bsk_ntt_tables,
        })

    }

    pub fn divide_and_round_q_last_inplace(&self, input: &mut[u64]) {
        let base_q_size = self.base_q.len();
        let last_modulus = self.base_q.base_at(base_q_size - 1);
        let coeff_count = self.coeff_count;
        let last_input_offset = (base_q_size - 1) * coeff_count;
        // Add (qi-1)/2 to change from flooring to rounding
        let half = last_modulus.value() >> 1;
        polymod::add_scalar_inplace(&mut input[last_input_offset..last_input_offset + coeff_count], half, last_modulus);
        let mut temp = vec![0; coeff_count];
        for i in 0..base_q_size - 1 {
            let b = self.base_q.base_at(i);
            // (ct mod qk) mod qi
            polymod::modulo(&input[last_input_offset..last_input_offset + coeff_count], b, &mut temp);
            // Subtract rounding correction here; the negative sign will turn into a plus in the next subtraction
            let half_mod = util::barrett_reduce_u64(half, b);
            polymod::sub_scalar_inplace(&mut temp, half_mod, b);
            // (ct mod qi) - (ct mod qk) mod qi
            polymod::sub_inplace(&mut input[i*coeff_count..(i+1)*coeff_count], &temp, b);
            // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
            polymod::multiply_operand_inplace(&mut input[i*coeff_count..(i+1)*coeff_count], &self.inv_q_last_mod_q[i], b);
        }
    }

    pub fn divide_and_round_q_last_ntt_inplace(&self, input: &mut[u64], rns_ntt_tables: &[NTTTables]) {
        let base_q_size = self.base_q.len();
        let last_modulus = self.base_q.base_at(base_q_size - 1);
        let coeff_count = self.coeff_count;
        let last_input_offset = (base_q_size - 1) * coeff_count;

        // Convert to non-NTT form
        rns_ntt_tables[base_q_size - 1].inverse_ntt_negacyclic_harvey(&mut input[last_input_offset..last_input_offset + coeff_count]);

        // Add (qi-1)/2 to change from flooring to rounding
        let half = last_modulus.value() >> 1;
        polymod::add_scalar_inplace(&mut input[last_input_offset..last_input_offset + coeff_count], half, last_modulus);

        let mut temp = vec![0; coeff_count];
        for i in 0..base_q_size - 1 {
            let b = self.base_q.base_at(i);
            // (ct mod qk) mod qi
            if b.value() < last_modulus.value() {
                polymod::modulo(&input[last_input_offset..last_input_offset + coeff_count],  b, &mut temp);
            } else {
                util::set_uint(&input[last_input_offset..last_input_offset + coeff_count], coeff_count, &mut temp);
            }

            // Lazy subtraction here. ntt_negacyclic_harvey_lazy can take 0 < x < 4*qi input.
            let neg_half_mod = b.value() - util::barrett_reduce_u64(half, b);

            // Note: lambda function parameter must be passed by reference here
            for j in 0..coeff_count {temp[j] += neg_half_mod;}

            // Since SEAL uses at most 60-bit moduli, 8*qi < 2^63.
            // This ntt_negacyclic_harvey_lazy results in [0, 4*qi).
            let qi_lazy = b.value() << 2;
            rns_ntt_tables[i].ntt_negacyclic_harvey_lazy(&mut temp);
            // Lazy subtraction again, results in [0, 2*qi_lazy),
            // The reduction [0, 2*qi_lazy) -> [0, qi) is done implicitly in multiply_poly_scalar_coeffmod.
            for j in 0..coeff_count { input[i * coeff_count + j] += qi_lazy - temp[j]; }

            // qk^(-1) * ((ct mod qi) - (ct mod qk)) mod qi
            polymod::multiply_operand_inplace(&mut input[i*coeff_count..(i+1)*coeff_count], &self.inv_q_last_mod_q[i], b);
        }
    }

    #[allow(non_snake_case)]
    pub fn fastbconv_sk(&self, input: &[u64], destination: &mut [u64]) {
        /*
        Require: Input in base Bsk
        Ensure: Output in base q
        */

        let base_q_size = self.base_q.len();
        let base_B_size = self.base_B.len();
        let coeff_count = self.coeff_count;

        // Fast convert B -> q; input is in Bsk but we only use B
        self.base_B_to_q_conv.fast_convert_array(&input[..base_B_size * coeff_count], destination);

        // Compute alpha_sk
        // Fast convert B -> {m_sk}; input is in Bsk but we only use B
        let mut temp = vec![0; coeff_count];
        self.base_B_to_m_sk_conv.fast_convert_array(&input[..base_B_size * coeff_count], &mut temp);

        // Take the m_sk part of input, subtract from temp, and multiply by inv_prod_B_mod_m_sk_
        // Note: input_sk is allocated in input[base_B_size]
        let mut alpha_sk = vec![0; coeff_count];
        for i in 0..self.coeff_count {
            // It is not necessary for the negation to be reduced modulo the small prime
            alpha_sk[i] = util::multiply_u64operand_mod(temp[i] + (self.m_sk.value() - input[base_B_size * coeff_count + i]), &self.inv_prod_B_mod_m_sk, &self.m_sk);
        }

        // alpha_sk is now ready for the Shenoy-Kumaresan conversion; however, note that our
        // alpha_sk here is not a centered reduction, so we need to apply a correction below.
        let m_sk_div_2 = self.m_sk.value() >> 1;
        for i in 0..base_q_size {
            let b = &(self.base_q.base_at(i));
            // Set up the multiplication helpers
            let prod_B_mod_q_elt = MultiplyU64ModOperand::new(self.prod_B_mod_q[i], b);

            let neg_prod_B_mod_q_elt = MultiplyU64ModOperand::new(b.value() - self.prod_B_mod_q[i], b);

            for j in 0..coeff_count {
                let dest = &mut destination[i * coeff_count + j];
                // Correcting alpha_sk since it represents a negative value
                if alpha_sk[j] > m_sk_div_2
                {
                    *dest = util::multiply_u64operand_add_u64_mod(
                        util::negate_u64_mod(alpha_sk[j], &self.m_sk), &prod_B_mod_q_elt, *dest, b);
                } else {
                    // No correction needed
                    // It is not necessary for the negation to be reduced modulo the small prime
                    *dest = util::multiply_u64operand_add_u64_mod(
                        alpha_sk[j], &neg_prod_B_mod_q_elt, *dest, b);
                }
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn sm_mrq(&self, input: &[u64], destination: &mut [u64]) {
        /*
        Require: Input in base Bsk U {m_tilde}
        Ensure: Output in base Bsk
        */
        let base_Bsk_size = self.base_Bsk.len();
        let coeff_count = self.coeff_count;

        // The last component of the input is mod m_tilde
        let m_tilde_div_2 = self.m_tilde.value() >> 1;

        // Compute r_m_tilde
        let mut r_m_tilde = vec![0; coeff_count];
        polymod::multiply_operand(
            &input[base_Bsk_size * coeff_count .. (base_Bsk_size + 1) * coeff_count], 
            &self.neg_inv_prod_q_mod_m_tilde, &self.m_tilde, &mut r_m_tilde);

        for i in 0..base_Bsk_size {
            let b = &(self.base_Bsk.base_at(i));
            let prod_q_mod_Bsk_elt = MultiplyU64ModOperand::new(self.prod_q_mod_Bsk[i], b);
            for j in 0..coeff_count {
                // We need centered reduction of r_m_tilde modulo Bsk. Note that m_tilde is chosen
                // to be a power of two so we have '>=' below.
                let mut temp = r_m_tilde[j];
                if temp >= m_tilde_div_2 {
                    temp += b.value() - self.m_tilde.value();
                }

                // Compute (input + q*r_m_tilde)*m_tilde^(-1) mod Bsk
                destination[i * coeff_count + j] = util::multiply_u64operand_mod(
                    util::multiply_u64operand_add_u64_mod(
                        temp, &prod_q_mod_Bsk_elt, input[i * coeff_count + j], b
                    ), &self.inv_m_tilde_mod_Bsk[i], b
                );
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn fast_floor(&self, input: &[u64], destination: &mut [u64]) {
        /*
        Require: Input in base q U Bsk
        Ensure: Output in base Bsk
        */

        let base_q_size = self.base_q.len();
        let base_Bsk_size = self.base_Bsk.len();
        let coeff_count = self.coeff_count;

        // Convert q -> Bsk
        self.base_q_to_Bsk_conv.fast_convert_array(
            &input[..base_q_size * coeff_count], destination);

        // Move input pointer to past the base q components
        let input = &input[base_q_size * coeff_count ..];
        for i in 0..base_Bsk_size {
            for j in 0..coeff_count {
                // It is not necessary for the negation to be reduced modulo base_Bsk_elt
                destination[i * coeff_count + j] = util::multiply_u64operand_mod(
                    input[i * coeff_count + j] + 
                        (self.base_Bsk.base_at(i).value() - destination[i * coeff_count + j]), 
                    &self.inv_prod_q_mod_Bsk[i], 
                    self.base_Bsk.base_at(i)
                );
            }
        }
    }

    #[allow(non_snake_case)]
    pub fn fastbconv_m_tilde(&self, input: &[u64], destination: &mut [u64]) {
        /*
        Require: Input in q
        Ensure: Output in Bsk U {m_tilde}
        */

        let base_q_size = self.base_q.len();
        let base_Bsk_size = self.base_Bsk.len();
        let coeff_count = self.coeff_count;

        // We need to multiply first the input with m_tilde mod q
        // This is to facilitate Montgomery reduction in the next step of multiplication
        // This is NOT an ideal approach: as mentioned in BEHZ16, multiplication by
        // m_tilde can be easily merge into the base conversion operation; however, then
        // we could not use the BaseConverter as below without modifications.
        let mut temp = vec![0; coeff_count * base_q_size];
        polymod::multiply_scalar_p(input, self.m_tilde.value(), coeff_count, self.base_q.base(), &mut temp);

        // Now convert to Bsk
        self.base_q_to_Bsk_conv.fast_convert_array(&temp, &mut destination[.. base_Bsk_size * coeff_count]);

        // Finally convert to {m_tilde}
        self.base_q_to_m_tilde_conv.fast_convert_array(&temp, &mut destination[base_Bsk_size * coeff_count .. (base_Bsk_size + 1) * coeff_count]);
    }

    pub fn decrypt_scale_and_round(&self, input: &[u64], destination: &mut [u64]) {

        let base_q_size = self.base_q.len();
        let base_t_gamma = self.base_t_gamma.as_ref().unwrap();
        let base_t_gamma_size = base_t_gamma.len();
        let coeff_count = self.coeff_count;

        // Compute |gamma * t|_qi * ct(s)
        let mut temp = vec![0; coeff_count * base_q_size];
        for i in 0..base_q_size {
            polymod::multiply_operand(
                &input[i*coeff_count .. (i+1)*coeff_count],
                &self.prod_t_gamma_mod_q.as_ref().unwrap()[i],
                self.base_q.base_at(i),
                &mut temp[i*coeff_count .. (i+1)*coeff_count],
            );
        }

        // Make another temp destination to get the poly in mod {t, gamma}
        let mut temp_t_gamma = vec![0; coeff_count * base_t_gamma_size];

        // Convert from q to {t, gamma}
        let base_q_to_t_gamma_conv = &self.base_q_to_t_gamma_conv;
        base_q_to_t_gamma_conv.as_ref().unwrap().fast_convert_array(&temp, &mut temp_t_gamma);

        // Multiply by -prod(q)^(-1) mod {t, gamma}
        for i in 0 .. base_t_gamma_size {
            polymod::multiply_operand_inplace(
                &mut temp_t_gamma[i*coeff_count .. (i+1)*coeff_count],
                &self.neg_inv_q_mod_t_gamma.as_ref().unwrap()[i],
                base_t_gamma.base_at(i),
            );
        }

        // Need to correct values in temp_t_gamma (gamma component only) which are
        // larger than floor(gamma/2)
        let gamma_div_2 = base_t_gamma.base_at(1).value() >> 1;
        let t = &self.t;
        let gamma = &self.gamma;
        let inv_gamma_mod_t = self.inv_gamma_mod_t.as_ref().unwrap();

        // Now compute the subtraction to remove error and perform final multiplication by
        // gamma inverse mod t
        for i in 0..coeff_count {
            // Need correction because of centered mod
            if temp_t_gamma[coeff_count + i] > gamma_div_2 {
                // Compute -(gamma - a) instead of (a - gamma)
                destination[i] = util::add_u64_mod(temp_t_gamma[i], t.reduce(gamma.value() - temp_t_gamma[coeff_count + i]), t);
            } else {
                // No correction needed
                destination[i] = util::sub_u64_mod(temp_t_gamma[i], t.reduce(temp_t_gamma[coeff_count + i]), t);
            }

            // If this coefficient was non-zero, multiply by gamma^(-1)
            if 0 != destination[i]
            {
                // Perform final multiplication by gamma inverse mod t
                destination[i] = util::multiply_u64operand_mod(destination[i], inv_gamma_mod_t, t);
            }
        }
    }

    /// Note: As BGV now uses NTT-form ciphertexts, this is no longer needed.
    pub fn mod_t_and_divide_q_last_inplace(&self, input: &mut [u64]) {
        let modulus_size = self.base_q.len();
        // const Modulus *curr_modulus = base_q_->base();
        let base_q = self.base_q.base();
        let plain_modulus = &self.t;
        let last_modulus_value = base_q[modulus_size - 1].value();
        let coeff_count = self.coeff_count;

        let mut neg_c_last_mod_t = vec![0; coeff_count];
        // neg_c_last_mod_t = - c_last (mod t)
        polymod::modulo(
            &input[(modulus_size - 1) * coeff_count .. modulus_size * coeff_count], 
            plain_modulus, &mut neg_c_last_mod_t);
        polymod::negate_inplace(&mut neg_c_last_mod_t, plain_modulus);
        if self.inv_q_last_mod_t != 1
        {
            // neg_c_last_mod_t *= q_last^(-1) (mod t)
            polymod::multiply_scalar_inplace(
                &mut neg_c_last_mod_t, self.inv_q_last_mod_t, plain_modulus);
        }

        let mut delta_mod_q_i = vec![0; coeff_count];

        for i in 0 .. modulus_size - 1 {
            // delta_mod_q_i = neg_c_last_mod_t (mod q_i)
            let curr_modulus = &base_q[i];
            polymod::modulo(&neg_c_last_mod_t, curr_modulus, &mut delta_mod_q_i);

            // delta_mod_q_i *= q_last (mod q_i)
            polymod::multiply_scalar_inplace(
                &mut delta_mod_q_i, last_modulus_value, curr_modulus);

            // c_i = c_i - c_last - neg_c_last_mod_t * q_last (mod 2q_i)
            let two_times_q_i = curr_modulus.value() << 1;
            for j in 0..coeff_count {
                input[i * coeff_count + j] += two_times_q_i - curr_modulus.reduce(input[(modulus_size - 1) * coeff_count + j]) - delta_mod_q_i[j];
            }

            // c_i = c_i * inv_q_last_mod_q_i (mod q_i)
            polymod::multiply_operand_inplace(
                &mut input[i * coeff_count .. (i + 1) * coeff_count], 
                &self.inv_q_last_mod_q[i], curr_modulus);
        }
    }

    pub fn mod_t_and_divide_q_last_ntt_inplace(&self, input: &mut [u64], rns_ntt_tables: &[NTTTables]) {
        let modulus_size = self.base_q.len();
        // const Modulus *curr_modulus = base_q_->base();
        let base_q = self.base_q.base();
        let plain_modulus = &self.t;
        let last_modulus_value = base_q[modulus_size - 1].value();
        let coeff_count = self.coeff_count;

        polymod::intt(
            &mut input[(modulus_size - 1) * coeff_count .. modulus_size * coeff_count], 
            &rns_ntt_tables[modulus_size - 1]
        );

        let mut neg_c_last_mod_t = vec![0; coeff_count];
        // neg_c_last_mod_t = - c_last (mod t)
        polymod::modulo(
            &input[(modulus_size - 1) * coeff_count .. modulus_size * coeff_count], 
            plain_modulus, &mut neg_c_last_mod_t);
        polymod::negate_inplace(&mut neg_c_last_mod_t, plain_modulus);
        if self.inv_q_last_mod_t != 1
        {
            // neg_c_last_mod_t *= q_last^(-1) (mod t)
            polymod::multiply_scalar_inplace(
                &mut neg_c_last_mod_t, self.inv_q_last_mod_t, plain_modulus);
        }

        let mut delta_mod_q_i = vec![0; coeff_count];

        for i in 0 .. modulus_size - 1 {
            // delta_mod_q_i = neg_c_last_mod_t (mod q_i)
            let curr_modulus = &base_q[i];
            polymod::modulo(&neg_c_last_mod_t, curr_modulus, &mut delta_mod_q_i);

            // delta_mod_q_i *= q_last (mod q_i)
            polymod::multiply_scalar_inplace(
                &mut delta_mod_q_i, last_modulus_value, curr_modulus);

            // c_i = c_i - c_last - neg_c_last_mod_t * q_last (mod 2q_i)
            //   first all all those to be subtracted to delta_mod_q_i
            for j in 0..coeff_count {
                delta_mod_q_i[j] += curr_modulus.reduce(input[(modulus_size - 1) * coeff_count + j]);
            }
            polymod::ntt(&mut delta_mod_q_i, &rns_ntt_tables[i]);
            //   then subtract them all
            for j in 0..coeff_count {
                input[i * coeff_count + j] = util::sub_u64_mod(
                    input[i * coeff_count + j],
                    delta_mod_q_i[j],
                    curr_modulus
                );
            }

            // c_i = c_i * inv_q_last_mod_q_i (mod q_i)
            polymod::multiply_operand_inplace(
                &mut input[i * coeff_count .. (i + 1) * coeff_count], 
                &self.inv_q_last_mod_q[i], curr_modulus);
        }
    }


    pub fn decrypt_mod_t(&self, phase: &[u64], destination: &mut [u64]) {
        // Use exact base convension rather than convert the base through the compose API
        self.base_q_to_t_conv.as_ref().unwrap().exact_convey_array(phase, destination);
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_compose_decompose() {
        let closure = 
        |base: &RNSBase, input: Vec<u64>, output: Vec<u64>| {
            let mut copy = input.clone();
            base.decompose(&mut copy);
            assert_eq!(copy, output);
            base.compose(&mut copy);
            assert_eq!(copy, input);
        };
        let to_moduli = |m: Vec<u64>| m.into_iter().map(Modulus::new).collect::<Vec<_>>();
        let base = RNSBase::new(&to_moduli(vec![2])).unwrap();
        closure(&base, vec![0], vec![0]);
        closure(&base, vec![1], vec![1]);

        let base = RNSBase::new(&to_moduli(vec![5])).unwrap();
        closure(&base, vec![0], vec![0]);
        closure(&base, vec![1], vec![1]);
        closure(&base, vec![2], vec![2]);
        closure(&base, vec![3], vec![3]);
        closure(&base, vec![4], vec![4]);

        let base = RNSBase::new(&to_moduli(vec![3, 5])).unwrap();
        closure(&base, vec![0, 0], vec![0, 0]);
        closure(&base, vec![1, 0], vec![1, 1]);
        closure(&base, vec![2, 0], vec![2, 2]);
        closure(&base, vec![3, 0], vec![0, 3]);
        closure(&base, vec![4, 0], vec![1, 4]);
        closure(&base, vec![5, 0], vec![2, 0]);
        closure(&base, vec![8, 0], vec![2, 3]);
        closure(&base, vec![12, 0], vec![0, 2]);
        closure(&base, vec![14, 0], vec![2, 4]);
        
        let base = RNSBase::new(&to_moduli(vec![2, 3, 5])).unwrap();
        closure(&base, vec![0, 0, 0], vec![0, 0, 0]);
        closure(&base, vec![1, 0, 0], vec![1, 1, 1]);
        closure(&base, vec![2, 0, 0], vec![0, 2, 2]);
        closure(&base, vec![3, 0, 0], vec![1, 0, 3]);
        closure(&base, vec![4, 0, 0], vec![0, 1, 4]);
        closure(&base, vec![5, 0, 0], vec![1, 2, 0]);
        closure(&base, vec![10, 0, 0], vec![0, 1, 0]);
        closure(&base, vec![11, 0, 0], vec![1, 2, 1]);
        closure(&base, vec![16, 0, 0], vec![0, 1, 1]);
        closure(&base, vec![27, 0, 0], vec![1, 0, 2]);
        closure(&base, vec![29, 0, 0], vec![1, 2, 4]);
        
        let base = RNSBase::new(&to_moduli(vec![13, 37, 53, 97])).unwrap();
        closure(&base, vec![0, 0, 0, 0], vec![0, 0, 0, 0]);
        closure(&base, vec![1, 0, 0, 0], vec![1, 1, 1, 1]);
        closure(&base, vec![2, 0, 0, 0], vec![2, 2, 2, 2]);
        closure(&base, vec![12, 0, 0, 0], vec![12, 12, 12, 12]);
        closure(&base, vec![321, 0, 0, 0], vec![9, 25, 3, 30]);

        let primes = util::get_primes(2048, 60, 4);
        let input = vec![0xAAAAAAAAAAA, 0xBBBBBBBBBB, 0xCCCCCCCCCC, 0xDDDDDDDDDD];
        let base = RNSBase::new(&primes).unwrap();
        let output = vec![
            util::modulo_uint(&input, &primes[0]),
            util::modulo_uint(&input, &primes[1]),
            util::modulo_uint(&input, &primes[2]),
            util::modulo_uint(&input, &primes[3]),
        ];
        closure(&base, input, output);
    }
    
    #[test]
    fn test_compose_decompose_array() {
        let closure = 
        |base: &RNSBase, input: Vec<u64>, output: Vec<u64>| {
            let mut copy = input.clone();
            base.decompose_array(&mut copy);
            assert_eq!(copy, output);
            base.compose_array(&mut copy);
            assert_eq!(copy, input);
        };
        let to_moduli = |m: Vec<u64>| m.into_iter().map(Modulus::new).collect::<Vec<_>>();
    
        let base = RNSBase::new(&to_moduli(vec![2])).unwrap();
        closure(&base, vec![0], vec![0]);
        closure(&base, vec![1], vec![1]);

        let base = RNSBase::new(&to_moduli(vec![5])).unwrap();
        closure(&base, vec![0, 1, 2], vec![0, 1, 2]);

        let base = RNSBase::new(&to_moduli(vec![3, 5])).unwrap();
        closure(&base, vec![0, 0], vec![0, 0]);
        closure(&base, vec![2, 0], vec![2, 2]);
        closure(&base, vec![7, 0], vec![1, 2]);
        closure(&base, vec![0, 0, 0, 0], vec![0, 0, 0, 0]);
        closure(&base, vec![1, 0, 2, 0], vec![1, 2, 1, 2]);
        closure(&base, vec![7, 0, 8, 0], vec![1, 2, 2, 3]);

        let base = RNSBase::new(&to_moduli(vec![3, 5, 7])).unwrap();
        closure(&base, vec![0, 0, 0], vec![0, 0, 0]);
        closure(&base, vec![2, 0, 0], vec![2, 2, 2]);
        closure(&base, vec![7, 0, 0], vec![1, 2, 0]);
        closure(&base, vec![0, 0, 0, 0, 0, 0], vec![0, 0, 0, 0, 0, 0]);
        closure(&base, vec![1, 0, 0, 2, 0, 0], vec![1, 2, 1, 2, 1, 2]);
        closure(&base, vec![7, 0, 0, 8, 0, 0], vec![1, 2, 2, 3, 0, 1]);
        closure(&base, vec![7, 0, 0, 8, 0, 0, 9, 0, 0], vec![1, 2, 0, 2, 3, 4, 0, 1, 2]);

        let primes = util::get_primes(2048, 60, 2);
        let input = vec![0xAAAAAAAAAAA, 0xBBBBBBBBBB, 0xCCCCCCCCCC,
            0xDDDDDDDDDD, 0xEEEEEEEEEE, 0xFFFFFFFFFF];
        let base = RNSBase::new(&primes).unwrap();
        let output = vec![
            util::modulo_uint(&input[0..2], &primes[0]),
            util::modulo_uint(&input[2..4], &primes[0]),
            util::modulo_uint(&input[4..6], &primes[0]),
            util::modulo_uint(&input[0..2], &primes[1]),
            util::modulo_uint(&input[2..4], &primes[1]),
            util::modulo_uint(&input[4..6], &primes[1]),
        ];
        closure(&base, input, output);
    }

    #[test]
    fn test_base_convert() {
        let construct_base_converter =
        |in_mod: Vec<u64>, out_mod: Vec<u64>| {
            let in_mod = in_mod.into_iter().map(Modulus::new).collect::<Vec<_>>();
            let out_mod = out_mod.into_iter().map(Modulus::new).collect::<Vec<_>>();
            let ibase = RNSBase::new(&in_mod).unwrap();
            let obase = RNSBase::new(&out_mod).unwrap();
            BaseConverter::new(&ibase, &obase)
        };
        let closure =
        |base_converter: &BaseConverter, input: Vec<u64>, output: Vec<u64>| {
            let mut result = vec![0; output.len()];
            base_converter.fast_convert(&input, &mut result);
            assert_eq!(output, result);
        };

        let bct = construct_base_converter(vec![2], vec![2]);
        closure(&bct, vec![0], vec![0]);
        closure(&bct, vec![1], vec![1]);

        let bct = construct_base_converter(vec![2], vec![3]);
        closure(&bct, vec![0], vec![0]);
        closure(&bct, vec![1], vec![1]);

        let bct = construct_base_converter(vec![3], vec![2]);
        closure(&bct, vec![0], vec![0]);
        closure(&bct, vec![1], vec![1]);
        closure(&bct, vec![2], vec![0]);
        
        let bct = construct_base_converter(vec![2, 3], vec![2]);
        closure(&bct, vec![0, 0], vec![0]);
        closure(&bct, vec![1, 1], vec![1]);
        closure(&bct, vec![0, 2], vec![0]);
        closure(&bct, vec![1, 0], vec![1]);
        
        let bct = construct_base_converter(vec![2, 3], vec![2, 3]);
        closure(&bct, vec![0, 0], vec![0, 0]);
        closure(&bct, vec![1, 1], vec![1, 1]);
        closure(&bct, vec![1, 2], vec![1, 2]);
        closure(&bct, vec![0, 2], vec![0, 2]);

        let bct = construct_base_converter(vec![2, 3], vec![3, 4, 5]);
        closure(&bct, vec![0, 0], vec![0, 0, 0]);
        closure(&bct, vec![1, 1], vec![1, 3, 2]);
        closure(&bct, vec![1, 2], vec![2, 1, 0]);

        let bct = construct_base_converter(vec![3, 4, 5], vec![2, 3]);
        closure(&bct, vec![0, 0, 0], vec![0, 0]);
        closure(&bct, vec![1, 1, 1], vec![1, 1]);
    }

    #[test]
    fn test_base_convert_array() {
        let construct_base_converter =
        |in_mod: Vec<u64>, out_mod: Vec<u64>| {
            let in_mod = in_mod.into_iter().map(Modulus::new).collect::<Vec<_>>();
            let out_mod = out_mod.into_iter().map(Modulus::new).collect::<Vec<_>>();
            let ibase = RNSBase::new(&in_mod).unwrap();
            let obase = RNSBase::new(&out_mod).unwrap();
            BaseConverter::new(&ibase, &obase)
        };
        let closure =
        |base_converter: &BaseConverter, input: Vec<u64>, output: Vec<u64>| {
            let mut result = vec![0; output.len()];
            base_converter.fast_convert_array(&input, &mut result);
            assert_eq!(output, result);
        };

        let bct = construct_base_converter(vec![3], vec![2]);
        closure(&bct, vec![0, 1, 2], vec![0, 1, 0]);

        let bct = construct_base_converter(vec![2, 3], vec![2]);
        closure(&bct, vec![0, 1, 0, 0, 1, 2], vec![0, 1, 0]);

        let bct = construct_base_converter(vec![2, 3], vec![2, 3]);
        closure(&bct, vec![1, 1, 0, 1, 2, 2], vec![1, 1, 0, 1, 2, 2]);

        let bct = construct_base_converter(vec![2, 3], vec![3, 4, 5]);
        closure(&bct, vec![0, 1, 1, 0, 1, 2], vec![0, 1, 2, 0, 3, 1, 0, 2, 0]);
    }

    #[allow(non_snake_case)]
    mod rns_tool {
        use super::*;

        #[test]
        fn test_fast_b_conv_m_tilde() {
    
            let to_moduli = |m: Vec<u64>| m.into_iter().map(Modulus::new).collect::<Vec<_>>();
            let to_rns_base = |m: Vec<u64>| RNSBase::new(&to_moduli(m)).unwrap();
    
            let poly_modulus_degree = 2;
            let plain_t = Modulus::new(0);
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![3]), &plain_t).unwrap();
            let base_q_size = rns_tool.base_q.len();
            let base_Bsk_m_tilde_size = rns_tool.base_Bsk_m_tilde.len();

            let input = vec![0; poly_modulus_degree * base_q_size];
            let output = vec![0; poly_modulus_degree * base_Bsk_m_tilde_size];
            let mut destination = vec![0; poly_modulus_degree * base_Bsk_m_tilde_size];

            rns_tool.fastbconv_m_tilde(&input, &mut destination);
            assert_eq!(destination, output);

            let input = vec![1, 2];
            rns_tool.fastbconv_m_tilde(&input, &mut destination);
            
            // These are results for fase base conversion for a length-2 array ((m_tilde), (2*m_tilde))
            // before reduction to target base.
            let temp = rns_tool.m_tilde.value() % 3;
            let temp2 = (2 * rns_tool.m_tilde.value()) % 3;

            assert_eq!(temp % (rns_tool.base_Bsk_m_tilde.base_at(0).value()), destination[0]);
            assert_eq!(temp2 % (rns_tool.base_Bsk_m_tilde.base_at(0).value()), destination[1]);
            assert_eq!(temp % (rns_tool.base_Bsk_m_tilde.base_at(1).value()), destination[2]);
            assert_eq!(temp2 % (rns_tool.base_Bsk_m_tilde.base_at(1).value()), destination[3]);
            assert_eq!(temp % (rns_tool.base_Bsk_m_tilde.base_at(2).value()), destination[4]);
            assert_eq!(temp2 % (rns_tool.base_Bsk_m_tilde.base_at(2).value()), destination[5]);

            let poly_modulus_degree = 2;
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![3, 5]), &plain_t).unwrap();
            let base_q_size = rns_tool.base_q.len();
            let base_Bsk_m_tilde_size = rns_tool.base_Bsk_m_tilde.len();

            let input = vec![0; poly_modulus_degree * base_q_size];
            let output = vec![0; poly_modulus_degree * base_Bsk_m_tilde_size];
            let mut destination = vec![0; poly_modulus_degree * base_Bsk_m_tilde_size];

            rns_tool.fastbconv_m_tilde(&input, &mut destination);
            assert_eq!(destination, output);

            let input = vec![1, 1, 2, 2];
            rns_tool.fastbconv_m_tilde(&input, &mut destination);
            let m_tilde = rns_tool.m_tilde.value();

            // This is the result of fast base conversion for a length-2 array
            // ((m_tilde, 2*m_tilde), (m_tilde, 2*m_tilde)) before reduction to target base.
            let temp = ((2 * m_tilde) % 3) * 5 + ((4 * m_tilde) % 5) * 3;

            assert_eq!(temp % rns_tool.base_Bsk_m_tilde[0].value(), destination[0]);
            assert_eq!(temp % rns_tool.base_Bsk_m_tilde[0].value(), destination[1]);
            assert_eq!(temp % rns_tool.base_Bsk_m_tilde[1].value(), destination[2]);
            assert_eq!(temp % rns_tool.base_Bsk_m_tilde[1].value(), destination[3]);
            assert_eq!(temp % rns_tool.base_Bsk_m_tilde[2].value(), destination[4]);
            assert_eq!(temp % rns_tool.base_Bsk_m_tilde[2].value(), destination[5]);
            assert_eq!(temp % rns_tool.base_Bsk_m_tilde[3].value(), destination[6]);
            assert_eq!(temp % rns_tool.base_Bsk_m_tilde[3].value(), destination[7]);
        }

        #[test]
        fn test_montgomery_reduction() {
            // This function assumes the input is in base Bsk U {m_tilde}. If the input is
            // |[c*m_tilde]_q + qu|_m for m in Bsk U {m_tilde}, then the output is c' in Bsk
            // such that c' = c mod q. In other words, this function cancels the extra multiples
            // of q in the Bsk U {m_tilde} representation. The functions works correctly for
            // sufficiently small values of u.
            
            let to_moduli = |m: Vec<u64>| m.into_iter().map(Modulus::new).collect::<Vec<_>>();
            let to_rns_base = |m: Vec<u64>| RNSBase::new(&to_moduli(m)).unwrap();
    
            let poly_modulus_degree = 2;
            let plain_t = Modulus::new(0);
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![3]), &plain_t).unwrap();
            let base_Bsk_m_tilde_size = rns_tool.base_Bsk_m_tilde.len();
            let base_Bsk_size = rns_tool.base_Bsk.len();
            
            let input = vec![0; poly_modulus_degree * base_Bsk_m_tilde_size];
            let output = vec![0; poly_modulus_degree * base_Bsk_size];
            let mut destination = vec![0; poly_modulus_degree * base_Bsk_size];

            rns_tool.sm_mrq(&input, &mut destination);
            assert_eq!(output, destination);

            // Input base is Bsk U {m_tilde}, in this case consisting of 3 primes.
            // m_tilde is always smaller than the primes in Bsk (HE_INTERNAL_MOD_BIT_COUNT (61) bits).
            // Set the length-2 array to have values 1*m_tilde and 2*m_tilde.
            let input = vec![
                rns_tool.m_tilde.value(),
                2 * rns_tool.m_tilde.value(),
                rns_tool.m_tilde.value(),
                2 * rns_tool.m_tilde.value(),
                0,
                0,
            ];
            // This should simply get rid of the m_tilde factor
            rns_tool.sm_mrq(&input, &mut destination);
            assert_eq!(destination, [1, 2, 1, 2]);

            // Next add a multiple of q to the input and see if it is reduced properly
            let input = [rns_tool.base_q[0].value(); 6];
            rns_tool.sm_mrq(&input, &mut destination);
            assert_eq!(destination, [0; 4]);

            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![3, 5]), &plain_t).unwrap();
            let base_Bsk_m_tilde_size = rns_tool.base_Bsk_m_tilde.len();
            let base_Bsk_size = rns_tool.base_Bsk.len();
            
            let input = vec![0; poly_modulus_degree * base_Bsk_m_tilde_size];
            let mut destination = vec![0; poly_modulus_degree * base_Bsk_size];

            rns_tool.sm_mrq(&input, &mut destination);

            // Input base is Bsk U {m_tilde}, in this case consisting of 6 primes.
            // m_tilde is always smaller than the primes in Bsk (HE_INTERNAL_MOD_BIT_COUNT (61) bits).
            // Set the length-2 array to have values 1*m_tilde and 2*m_tilde.
            let input = vec![
                rns_tool.m_tilde.value(),
                2 * rns_tool.m_tilde.value(),
                rns_tool.m_tilde.value(),
                2 * rns_tool.m_tilde.value(),
                rns_tool.m_tilde.value(),
                2 * rns_tool.m_tilde.value(),
                0,
                0,
            ];

            rns_tool.sm_mrq(&input, &mut destination);
            assert_eq!(destination, [1, 2, 1, 2, 1, 2]);

            let input = [15, 30, 15, 30, 15, 30, 15, 30];
            rns_tool.sm_mrq(&input, &mut destination);
            assert_eq!(destination, [0; 6]);

            // Now with a multiple of m_tilde + multiple of q
            let input = [
                2 * rns_tool.m_tilde.value() + 15,
                2 * rns_tool.m_tilde.value() + 30,
                2 * rns_tool.m_tilde.value() + 15,
                2 * rns_tool.m_tilde.value() + 30,
                2 * rns_tool.m_tilde.value() + 15,
                2 * rns_tool.m_tilde.value() + 30,
                2 * rns_tool.m_tilde.value() + 15,
                2 * rns_tool.m_tilde.value() + 30,
            ];
            rns_tool.sm_mrq(&input, &mut destination);
            assert_eq!(destination, [2; 6]);

        }

        #[test]
        fn test_fast_floor() {
            // This function assumes the input is in base q U Bsk. It outputs an approximation of
            // the value divided by q floored in base Bsk. The approximation has absolute value up
            // to k-1, where k is the number of primes in the base q.
            
            let to_moduli = |m: Vec<u64>| m.into_iter().map(Modulus::new).collect::<Vec<_>>();
            let to_rns_base = |m: Vec<u64>| RNSBase::new(&to_moduli(m)).unwrap();
    
            let poly_modulus_degree = 2;
            let plain_t = Modulus::new(0);
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![3]), &plain_t).unwrap();
            let base_q_size = rns_tool.base_q.len();
            let base_Bsk_size = rns_tool.base_Bsk.len();

            let input = vec![0; poly_modulus_degree * (base_q_size + base_Bsk_size)];
            let output = vec![0; poly_modulus_degree * base_Bsk_size];
            let mut destination = vec![0; poly_modulus_degree * base_Bsk_size];

            rns_tool.fast_floor(&input, &mut destination);
            assert_eq!(output, destination);

            let input = [15, 3, 15, 3, 15, 3];
            // The size of q U Bsk is 3. We set the input to have values 15 and 5, and divide by 3 (i.e., q).
            rns_tool.fast_floor(&input, &mut destination);
            assert_eq!(vec![5, 1, 5, 1], destination);

            let input = [17, 4, 17, 4, 17, 4];
            // We get an exact result in this case since input base only has size 1
            rns_tool.fast_floor(&input, &mut destination);
            assert_eq!(vec![5, 1, 5, 1], destination);

            let poly_modulus_degree = 2;
            let plain_t = Modulus::new(0);
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![3, 5]), &plain_t).unwrap();
            let base_q_size = rns_tool.base_q.len();
            let base_Bsk_size = rns_tool.base_Bsk.len();

            let input = vec![0; poly_modulus_degree * (base_q_size + base_Bsk_size)];
            let output = vec![0; poly_modulus_degree * base_Bsk_size];
            let mut destination = vec![0; poly_modulus_degree * base_Bsk_size];

            rns_tool.fast_floor(&input, &mut destination);
            assert_eq!(output, destination);
            
            let input = [15, 30, 15, 30, 15, 30, 15, 30, 15, 30];
            rns_tool.fast_floor(&input, &mut destination);
            assert_eq!(vec![1, 2, 1, 2, 1, 2], destination);
            
            let input = [21, 32, 21, 32, 21, 32, 21, 32, 21, 32];
            rns_tool.fast_floor(&input, &mut destination);
            assert!((1_i32 - destination[0] as i32).abs() <= 1);
            assert!((2_i32 - destination[1] as i32).abs() <= 1);
            assert!((1_i32 - destination[2] as i32).abs() <= 1);
            assert!((2_i32 - destination[3] as i32).abs() <= 1);
            assert!((1_i32 - destination[4] as i32).abs() <= 1);
            assert!((2_i32 - destination[5] as i32).abs() <= 1);
        }

        #[test]
        fn test_fastbconv_sk() {
            // This function assumes the input is in base Bsk and outputs a fast base conversion
            // with Shenoy-Kumaresan correction to base q. The conversion is exact.
            
            let to_moduli = |m: Vec<u64>| m.into_iter().map(Modulus::new).collect::<Vec<_>>();
            let to_rns_base = |m: Vec<u64>| RNSBase::new(&to_moduli(m)).unwrap();
    
            let poly_modulus_degree = 2;
            let plain_t = Modulus::new(0);
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![3]), &plain_t).unwrap();
            let base_q_size = rns_tool.base_q.len();
            let base_Bsk_size = rns_tool.base_Bsk.len();

            let input = vec![0; poly_modulus_degree * base_Bsk_size];
            let output = vec![0; poly_modulus_degree * base_q_size];
            let mut destination = vec![0; poly_modulus_degree * base_q_size];

            rns_tool.fastbconv_sk(&input, &mut destination);
            assert_eq!(destination, output);

            // The size of Bsk is 2
            let input = [1, 2, 1, 2];
            rns_tool.fastbconv_sk(&input, &mut destination);
            assert_eq!(destination, vec![1, 2]);

            let poly_modulus_degree = 2;
            let plain_t = Modulus::new(0);
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![3, 5]), &plain_t).unwrap();
            let base_q_size = rns_tool.base_q.len();

            let mut destination = vec![0; poly_modulus_degree * base_q_size];
            
            // The size of Bsk is 3
            let input = [1, 2, 1, 2, 1, 2];
            rns_tool.fastbconv_sk(&input, &mut destination);
            assert_eq!(destination, vec![1, 2, 1, 2]);

        }


        #[test]
        fn test_exact_scale_and_round() {

            // This function computes [round(t/q * |input|_q)]_t exactly using the gamma-correction technique.
            let to_moduli = |m: Vec<u64>| m.into_iter().map(Modulus::new).collect::<Vec<_>>();
            let to_rns_base = |m: Vec<u64>| RNSBase::new(&to_moduli(m)).unwrap();
    
            let poly_modulus_degree = 2;
            let plain_t = Modulus::new(3);
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![5, 7]), &plain_t).unwrap();

            let mut destination = vec![0; poly_modulus_degree];

            // rns_tool.decrypt_scale_and_round(&input, &mut destination);
            // assert_eq!(output, destination);

            // // The size of Bsk is 2. Both values here are multiples of 35 (i.e., q).
            // // Skip tests exceeding input bound when using HEXL in DEBUG mode
            // let input = [35, 70, 35, 70];

            // // We expect to get a zero output in this case
            // rns_tool.decrypt_scale_and_round(&input, &mut destination);
            // assert_eq!(destination, vec![0, 0]);

            // Now try a non-trivial case
            let input = [29, 65, 29, 65];

            // Here 29 will scale and round to 2 and 30 will scale and round to 0.
            // The added 35 should not make a difference.
            rns_tool.decrypt_scale_and_round(&input, &mut destination);
            assert_eq!(destination, vec![2, 0]);
        }

        #[test]
        fn test_divide_and_round_q_last_inplace() {
            // This function approximately divides the input values by the last prime in the base q.
            // Input is in base q; the last RNS component becomes invalid.

            let to_moduli = |m: Vec<u64>| m.into_iter().map(Modulus::new).collect::<Vec<_>>();
            let to_rns_base = |m: Vec<u64>| RNSBase::new(&to_moduli(m)).unwrap();
    
            let poly_modulus_degree = 2;
            let plain_t = Modulus::new(0);
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![13, 7]), &plain_t).unwrap();
            let base_q_size = rns_tool.base_q.len();

            let mut input = vec![0; poly_modulus_degree * base_q_size];
            rns_tool.divide_and_round_q_last_inplace(&mut input);
            assert_eq!(input[0..2], [0, 0]);

            let mut input = [1, 2, 1, 2];
            rns_tool.divide_and_round_q_last_inplace(&mut input);
            assert_eq!(input[0..2], [0, 0]);

            let mut input = [12, 11, 4, 3];
            rns_tool.divide_and_round_q_last_inplace(&mut input);
            assert_eq!(input[0..2], [4, 3]);

            let mut input = [6, 2, 5, 1];
            rns_tool.divide_and_round_q_last_inplace(&mut input);
            assert_eq!(input[0..2], [3, 2]);
            
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![3, 5, 7, 11]), &plain_t).unwrap();
            let base_q_size = rns_tool.base_q.len();

            let mut input = vec![0; poly_modulus_degree * base_q_size];
            rns_tool.divide_and_round_q_last_inplace(&mut input);
            assert_eq!(input[0..6], [0; 6]);

            let mut input = [1, 2, 1, 2, 1, 2, 1, 2];
            rns_tool.divide_and_round_q_last_inplace(&mut input);
            assert_eq!(input[0..6], [0; 6]);

            let mut input = [0, 1, 0, 0, 4, 0, 5, 4];
            rns_tool.divide_and_round_q_last_inplace(&mut input);
            assert!((3 + 2 - input[0]) % 3 <= 1);
            assert!((3 + 0 - input[1]) % 3 <= 1);
            assert!((5 + 0 - input[2]) % 5 <= 1);
            assert!((5 + 1 - input[3]) % 5 <= 1);
            assert!((7 + 5 - input[4]) % 7 <= 1);
            assert!((7 + 6 - input[5]) % 7 <= 1);

        }

        #[test]
        fn test_mod_t_and_divide_q_last_inplace() {

            let to_moduli = |m: Vec<u64>| m.into_iter().map(Modulus::new).collect::<Vec<_>>();
            let to_rns_base = |m: Vec<u64>| RNSBase::new(&to_moduli(m)).unwrap();
    
            let poly_modulus_degree = 2;
            let plain_t = Modulus::new(3);
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![13, 7]), &plain_t).unwrap();
            let base_q_size = rns_tool.base_q.len();

            let mut input = vec![0; poly_modulus_degree * base_q_size];
            rns_tool.mod_t_and_divide_q_last_inplace(&mut input);
            assert_eq!(input[0..2], [0, 0]);

            let mut input = [1, 2, 1, 2];
            rns_tool.mod_t_and_divide_q_last_inplace(&mut input);
            assert_eq!(input[0..2], [11, 12]);

            let mut input = [12, 11, 4, 3];
            rns_tool.mod_t_and_divide_q_last_inplace(&mut input);
            assert_eq!(input[0..2], [1, 3]);
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![5, 7, 11]), &plain_t).unwrap();
            let base_q_size = rns_tool.base_q.len();

            let mut input = vec![0; poly_modulus_degree * base_q_size];
            rns_tool.mod_t_and_divide_q_last_inplace(&mut input);
            assert_eq!(input[0..4], [0; 4]);

            let mut input = [1, 2, 1, 2, 1, 2];
            rns_tool.mod_t_and_divide_q_last_inplace(&mut input);
            assert_eq!(input[0..4], [4, 3, 6, 5]);

            let mut input = [0, 1, 0, 0, 4, 0];
            rns_tool.mod_t_and_divide_q_last_inplace(&mut input);
            assert_eq!(input[0..4], [0, 1, 5, 0]);

        }

        #[test]
        fn test_decrypt_mod_t() {

            let to_moduli = |m: Vec<u64>| m.into_iter().map(Modulus::new).collect::<Vec<_>>();
            let to_rns_base = |m: Vec<u64>| RNSBase::new(&to_moduli(m)).unwrap();
    
            let poly_modulus_degree = 2;
            let plain_t = Modulus::new(3);
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![13, 7]), &plain_t).unwrap();
            let base_q_size = rns_tool.base_q.len();

            let input = vec![0; poly_modulus_degree * base_q_size];
            let mut output = vec![0; poly_modulus_degree];
            rns_tool.decrypt_mod_t(&input, &mut output);
            assert_eq!(output[0..2], [0, 0]);

            let input = [1, 2, 1, 2];
            let mut output = vec![0; poly_modulus_degree];
            rns_tool.decrypt_mod_t(&input, &mut output);
            assert_eq!(output[0..2], [1, 2]);

            let input = [12, 11, 4, 3];
            let mut output = vec![0; poly_modulus_degree];
            rns_tool.decrypt_mod_t(&input, &mut output);
            assert_eq!(output[0..2], [1, 0]);
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![5, 7, 11]), &plain_t).unwrap();
            let base_q_size = rns_tool.base_q.len();

            let input = vec![0; poly_modulus_degree * base_q_size];
            let mut output = vec![0; poly_modulus_degree];
            rns_tool.decrypt_mod_t(&input, &mut output);
            assert_eq!(output[0..2], [0, 0]);

            let input = [1, 2, 1, 2, 1, 2];
            let mut output = vec![0; poly_modulus_degree];
            rns_tool.decrypt_mod_t(&input, &mut output);
            assert_eq!(output[0..2], [1, 2]);

            let input = [0, 1, 0, 0, 4, 0];
            let mut output = vec![0; poly_modulus_degree];
            rns_tool.decrypt_mod_t(&input, &mut output);
            assert_eq!(output[0..2], [1, 2]);

        }

        #[test]
        fn test_divide_and_round_q_last_ntt_inplace() {
            // This function approximately divides the input values by the last prime in the base q.
            // The input and output are both in NTT form. Input is in base q; the last RNS component
            // becomes invalid.

            let to_moduli = |m: Vec<u64>| m.into_iter().map(Modulus::new).collect::<Vec<_>>();
            let to_rns_base = |m: Vec<u64>| RNSBase::new(&to_moduli(m)).unwrap();
    
            let poly_modulus_degree = 2;
            let plain_t = Modulus::new(0);

            let ntt = [NTTTables::new(1, &Modulus::new(53)).unwrap(), NTTTables::new(1, &Modulus::new(13)).unwrap()];
    
            let rns_tool = RNSTool::new(poly_modulus_degree, &to_rns_base(vec![53, 13]), &plain_t).unwrap();
            let base_q_size = rns_tool.base_q.len();

            let mut input = vec![0; poly_modulus_degree * base_q_size];
            rns_tool.divide_and_round_q_last_ntt_inplace(&mut input, &ntt);
            assert_eq!(input[0..2], [0, 0]);

            let mut input = vec![1, 2, 1, 2];
            ntt[0].ntt_negacyclic_harvey(&mut input[0..2]);
            ntt[1].ntt_negacyclic_harvey(&mut input[2..4]);
            rns_tool.divide_and_round_q_last_ntt_inplace(&mut input, &ntt);
            ntt[0].inverse_ntt_negacyclic_harvey(&mut input[0..2]);
            assert_eq!(input[0..2], [0, 0]);

            let mut input = vec![4, 12, 4, 12];
            ntt[0].ntt_negacyclic_harvey(&mut input[0..2]);
            ntt[1].ntt_negacyclic_harvey(&mut input[2..4]);
            rns_tool.divide_and_round_q_last_ntt_inplace(&mut input, &ntt);
            ntt[0].inverse_ntt_negacyclic_harvey(&mut input[0..2]);
            assert!((53 + 1 - input[0]) % 53 <= 1);
            assert!((53 + 2 - input[1]) % 53 <= 1);

            let mut input = vec![25, 35, 12, 9];
            ntt[0].ntt_negacyclic_harvey(&mut input[0..2]);
            ntt[1].ntt_negacyclic_harvey(&mut input[2..4]);
            rns_tool.divide_and_round_q_last_ntt_inplace(&mut input, &ntt);
            ntt[0].inverse_ntt_negacyclic_harvey(&mut input[0..2]);
            assert!((53 + 2 - input[0]) % 53 <= 1);
            assert!((53 + 3 - input[1]) % 53 <= 1);
        }

    }


}