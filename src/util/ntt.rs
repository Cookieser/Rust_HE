use super::dwthandler::{Arithmetic, DWTHandler};
use crate::{
    util, Modulus,
    util::MultiplyU64ModOperand,
};

#[derive(Clone, Copy, Default)]
struct ModArithLazy {
    modulus: Modulus,
    two_times_modulus: u64,
}
type NTTHandler = DWTHandler<ModArithLazy>;

impl Arithmetic for ModArithLazy {
    type Value = u64;
    type Root = MultiplyU64ModOperand;
    type Scalar = MultiplyU64ModOperand;

    #[inline]
    fn add(&self, a: &Self::Value, b: &Self::Value) -> Self::Value {
        a + b
    }

    #[inline]
    fn sub(&self, a: &Self::Value, b: &Self::Value) -> Self::Value {
        a + self.two_times_modulus - b
    }

    #[inline]
    fn mul_root(&self, a: &Self::Value, r: &Self::Root) -> Self::Value {
        util::multiply_u64operand_mod_lazy(*a, r, &self.modulus)
    }

    #[inline]
    fn mul_scalar(&self, a: &Self::Value, s: &Self::Scalar) -> Self::Value {
        util::multiply_u64operand_mod_lazy(*a, s, &self.modulus)
    }

    #[inline]
    fn guard(&self, a: &Self::Value) -> Self::Value {
        if *a >= self.two_times_modulus {*a - self.two_times_modulus}
        else {*a}
    }
}

impl ModArithLazy {

    pub fn new(modulus: &Modulus) -> Self {
        ModArithLazy { 
            modulus: *modulus, 
            two_times_modulus: modulus.value() << 1 
        }
    }

}

#[derive(Clone, Default)]
pub struct NTTTables {
    root: u64,
    // inv_root: u64,
    coeff_count_power: usize,
    coeff_count: usize,
    modulus: Modulus,
    inv_degree_modulo: MultiplyU64ModOperand,
    root_powers: Vec<MultiplyU64ModOperand>,
    inv_root_powers: Vec<MultiplyU64ModOperand>,
    // mod_arith_lazy: ModArithLazy,
    ntt_handler: NTTHandler,
}

impl NTTTables {

    // constructor
    pub fn new(coeff_count_power: usize, modulus: &Modulus) -> Result<Self, &str> {
        let coeff_count = (1 << coeff_count_power) as usize;
        let modulus = *modulus;
        // We defer parameter checking to try_minimal_primitive_root(...)
        let mut root: u64 = 0;
        if !util::try_minimal_primitive_root(2 * coeff_count as u64, &modulus, &mut root) {
            return Err("[Invalid argument] Invalid modulus.");
        }
        let mut inv_root: u64 = 0;
        if !util::try_invert_u64_mod(root, &modulus, &mut inv_root) {
            return Err("[Invalid argument] Invalid modulus, unable to invert.");
        }

        // Populate tables with powers of root in specific orders.
        let mut root_powers = vec![MultiplyU64ModOperand::default(); coeff_count];
        let root_operand = MultiplyU64ModOperand::new(root, &modulus);
        let mut power = root;
        for i in 1..coeff_count {
            root_powers[util::reverse_bits_u64(i as u64, coeff_count_power) as usize] = MultiplyU64ModOperand::new(power, &modulus);
            power = util::multiply_u64operand_mod(power, &root_operand, &modulus);
        }
        root_powers[0] = MultiplyU64ModOperand::new(1, &modulus);

        let mut inv_root_powers = vec![MultiplyU64ModOperand::default(); coeff_count];
        let root_operand = MultiplyU64ModOperand::new(inv_root, &modulus);
        let mut power = inv_root;
        for i in 1..coeff_count {
            inv_root_powers[util::reverse_bits_u64((i - 1) as u64, coeff_count_power) as usize + 1] = MultiplyU64ModOperand::new(power, &modulus);
            power = util::multiply_u64operand_mod(power, &root_operand, &modulus);
        }
        inv_root_powers[0] = MultiplyU64ModOperand::new(1, &modulus);

        let degree_uint = coeff_count as u64;
        let mut inv_degree_modulo = 0;
        if !util::try_invert_u64_mod(degree_uint, &modulus, &mut inv_degree_modulo) {
            return Err("[Invalid argument] Invalid modulus, unable to invert degree.");
        }
        let inv_degree_modulo = MultiplyU64ModOperand::new(inv_degree_modulo, &modulus);

        let mod_arith_lazy = ModArithLazy::new(&modulus);

        Ok(NTTTables {
            root,
            // inv_root,
            coeff_count_power,
            coeff_count,
            modulus,
            inv_degree_modulo,
            root_powers,
            inv_root_powers,
            // mod_arith_lazy,
            ntt_handler: NTTHandler::new(&mod_arith_lazy),
        })
    }

    // get members
    pub fn root(&self) -> u64 {self.root}
    pub fn get_root_powers(&self) -> &[MultiplyU64ModOperand] {&self.root_powers}
    pub fn get_inv_root_powers(&self) -> &[MultiplyU64ModOperand] {&self.inv_root_powers}
    pub fn inv_degree_modulo(&self) -> MultiplyU64ModOperand {self.inv_degree_modulo.clone()}
    // pub fn modulus(&self) -> &Modulus {&self.modulus}
    pub fn coeff_count_power(&self) -> usize {self.coeff_count_power}
    pub fn coeff_count(&self) -> usize {self.coeff_count}

    // create multiple
    pub fn create_ntt_tables(coeff_count_power: usize, moduli: &[Modulus]) -> Result<Vec<NTTTables>, String> {
        if moduli.is_empty() {
            return Err("[Invalid argument] Moduli is empty.".to_string());
        }
        let mut ret = Vec::with_capacity(moduli.len());
        for x in moduli {
            if let Ok(table) = Self::new(coeff_count_power, x) {
                ret.push(table);
            } else {
                return Err("[Invalid argument] Moduli is empty.".to_string());
            }
        }
        Ok(ret)
    }

    // utilities
    pub fn ntt_negacyclic_harvey_lazy(&self, operand: &mut[u64]) {
        self.ntt_handler.transform_to_rev(operand, self.coeff_count_power, &self.root_powers, None);
    }

    pub fn ntt_negacyclic_harvey(&self, operand: &mut[u64]) {
        self.ntt_negacyclic_harvey_lazy(operand);
        // Finally maybe we need to reduce every coefficient modulo q, but we
        // know that they are in the range [0, 4q).
        // Since word size is controlled this is fast.
        let modulus = self.modulus.value();
        let two_times_modulus = modulus << 1;
        operand.iter_mut().for_each(|x| {
            if *x >= two_times_modulus {*x -= two_times_modulus}
            if *x >= modulus {*x -= modulus}
        });
    }

    pub fn inverse_ntt_negacyclic_harvey_lazy(&self, operand: &mut[u64]) {
        self.ntt_handler.transform_from_rev(operand, self.coeff_count_power, &self.inv_root_powers, 
            Some(&self.inv_degree_modulo));
    }

    pub fn inverse_ntt_negacyclic_harvey(&self, operand: &mut[u64]) {
        self.inverse_ntt_negacyclic_harvey_lazy(operand);
        // Final adjustments; compute a[j] = a[j] * n^{-1} mod q.
        // We incorporated the final adjustment in the butterfly. Only need to reduce here.
        let modulus = self.modulus.value();
        operand.iter_mut().for_each(|x| {
            if *x >= modulus {*x -= modulus}
        });
    }

}

#[cfg(test)]
mod tests {
    use crate::CoeffModulus;

    use super::*;
    use rand::{Rng, SeedableRng};

    #[test]
    fn test_ntt_basics() {

        let coeff_count_power = 1;
        let modulus = util::get_prime(2 << coeff_count_power, 60);
        let tables = NTTTables::new(coeff_count_power, &modulus).unwrap();
        assert_eq!(2, tables.coeff_count());
        assert_eq!(1, tables.coeff_count_power());
        
        let coeff_count_power = 2;
        let modulus = util::get_prime(2 << coeff_count_power, 50);
        let tables = NTTTables::new(coeff_count_power, &modulus).unwrap();
        assert_eq!(4, tables.coeff_count());
        assert_eq!(2, tables.coeff_count_power());
        
        let coeff_count_power = 10;
        let modulus = util::get_prime(2 << coeff_count_power, 40);
        let tables = NTTTables::new(coeff_count_power, &modulus).unwrap();
        assert_eq!(1024, tables.coeff_count());
        assert_eq!(10, tables.coeff_count_power());

        NTTTables::create_ntt_tables(
            coeff_count_power, 
            &CoeffModulus::create(
                1 << coeff_count_power, 
                vec![20, 20, 20, 20, 20]
            )
        ).unwrap().iter().for_each(|table| {
            assert_eq!(1024, table.coeff_count());
            assert_eq!(10, table.coeff_count_power());
        });
    }

    #[test]
    fn test_ntt_primitive_roots() {
        let coeff_count_power = 1;
        let modulus = Modulus::new(0xffffffffffc0001);
        let tables = NTTTables::new(coeff_count_power, &modulus).unwrap();
        assert_eq!(1, tables.get_root_powers()[0].operand);
        assert_eq!(288794978602139552, tables.get_root_powers()[1].operand);
        let mut inv: u64 = 0; 
        util::try_invert_u64_mod(288794978602139552, &modulus, &mut inv);
        assert_eq!(inv, tables.get_inv_root_powers()[1].operand);
        
        let coeff_count_power = 2;
        let tables = NTTTables::new(coeff_count_power, &modulus).unwrap();
        assert_eq!(288794978602139552, tables.get_root_powers()[1].operand);
        assert_eq!(178930308976060547, tables.get_root_powers()[2].operand);
        assert_eq!(748001537669050592, tables.get_root_powers()[3].operand);
    }

    #[test]
    fn test_negacyclic_ntt() {
        let coeff_count_power = 1;
        let modulus = Modulus::new(0xffffffffffc0001);
        let tables = NTTTables::new(coeff_count_power, &modulus).unwrap();
        
        let mut poly = [0, 0];
        tables.ntt_negacyclic_harvey(&mut poly);
        assert_eq!(poly, [0, 0]);

        let mut poly = [1, 0];
        tables.ntt_negacyclic_harvey(&mut poly);
        assert_eq!(poly, [1, 1]);

        let mut poly = [1, 1];
        tables.ntt_negacyclic_harvey(&mut poly);
        assert_eq!(poly, [288794978602139553, 864126526004445282]);
    }

    #[test]
    fn test_inverse_negacyclic_ntt() {
        const COEFF_COUNT_POWER: usize = 3;
        const N: usize = 1 << COEFF_COUNT_POWER;
        let modulus = Modulus::new(0xffffffffffc0001);
        let tables = NTTTables::new(COEFF_COUNT_POWER, &modulus).unwrap();

        let mut poly = [0; N];
        tables.inverse_ntt_negacyclic_harvey(&mut poly);
        assert_eq!(poly, [0; N]);

        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        for each in &mut poly {
            *each = modulus.reduce(rng.gen());
        }
        let copied = poly;

        tables.ntt_negacyclic_harvey(&mut poly);
        tables.inverse_ntt_negacyclic_harvey(&mut poly);
        assert_eq!(poly, copied);
    }

}