use std::sync::RwLock;

use crate::{util, Modulus};

pub(crate) const GALOIS_GENERATOR: usize = 3;

pub struct GaloisTool {

    coeff_count_power: usize,
    coeff_count: usize,
    permutation_tables: RwLock<Vec<Vec<usize>>>,
}

#[allow(unused)]
impl GaloisTool {

    pub fn new(coeff_count_power: usize) -> Self {
        assert!(coeff_count_power as isize <= util::get_power_of_two(util::HE_POLY_MOD_DEGREE_MAX as u64)
            && coeff_count_power as isize >= util::get_power_of_two(util::HE_POLY_MOD_DEGREE_MIN as u64),
            "[Invalid argument] Coeff count power out of range.");
        GaloisTool { 
            coeff_count_power, 
            coeff_count: 1 << coeff_count_power, 
            permutation_tables: RwLock::new(vec![vec![]; 1 << coeff_count_power]),
        }
    }

    pub fn generate_table_ntt(&self, galois_elt: usize) -> Vec<usize> {
        let coeff_count = self.coeff_count;
        let mut result = vec![0; coeff_count];
        let coeff_count_minus_one = coeff_count - 1;
        for i in coeff_count .. (coeff_count << 1) {
            let reversed = util::reverse_bits_u32(i as u32, self.coeff_count_power + 1);
            let index_raw = ((galois_elt as u64 * reversed as u64) >> 1) & coeff_count_minus_one as u64;
            result[i - coeff_count] = util::reverse_bits_u32(index_raw as u32, self.coeff_count_power) as usize;
        }
        result
    }

    /**
    Compute the Galois element corresponding to a given rotation step.
    */
    pub fn get_elt_from_step(&self, step: isize) -> usize {
        let n = self.coeff_count;
        let m = n * 2;
        if step == 0 {m - 1}
        else {
            // Extract sign of steps. When steps is positive, the rotation
            // is to the left; when steps is negative, it is to the right.
            let sign = step < 0;
            let pos_step = step.unsigned_abs();
            assert!(pos_step < (n>>1), "[Invalid argument] Step count too large.");
            let pos_step = pos_step & (m - 1);
            let step = if sign {(n>>1) - pos_step} else {pos_step};
            let gen = GALOIS_GENERATOR; let mut galois_elt = 1;
            // Construct Galois element for row rotation
            for _ in 0..step {
                galois_elt = (galois_elt * gen) & (m - 1);
            }
            galois_elt
        }
    }

    /**
    Compute the Galois elements corresponding to a vector of given rotation steps.
    */
    pub fn get_elts_from_steps(&self, steps: &[isize]) -> Vec<usize> {
        steps.iter().map(|&x| self.get_elt_from_step(x)).collect()
    }

    /**
    Compute a vector of all necessary galois_elts.
    */
    pub fn get_elts_all(&self) -> Vec<usize> {
        let n = self.coeff_count;
        let m = n << 1;

        // Generate Galois keys for m - 1 (X -> X^{m-1})
        let mut galois_elts = vec![m - 1];
        galois_elts.reserve(self.coeff_count_power * 2 - 1);
        
        // Generate Galois key for power of generator_ mod m (X -> X^{3^k}) and
        // for negative power of generator_ mod m (X -> X^{-3^k})
        let mut pos_power = GALOIS_GENERATOR;
        let mut neg_power_u64 = 0;
        util::try_invert_u64_mod_u64(GALOIS_GENERATOR as u64, m as u64, &mut neg_power_u64);
        let mut neg_power = neg_power_u64 as usize;
        for _ in 0..self.coeff_count_power - 1 {
            galois_elts.push(pos_power);
            pos_power = (pos_power * pos_power) & (m - 1);
            galois_elts.push(neg_power);
            neg_power = (neg_power * neg_power) & (m - 1);
        }
        galois_elts
    }

    /**
    Compute the index in the range of 0 to (coeff_count_ - 1) of a given Galois element.
    */
    pub fn get_index_from_elt(galois_elt: usize) -> usize {
        assert!(galois_elt & 1 > 0, "[Invalid argument] Galois elt is not invalid");
        (galois_elt - 1) >> 1
    }

    pub fn apply(&self, operand: &[u64], galois_elt: usize, modulus: &Modulus, result: &mut [u64]) {
        let coeff_count_minus_one = self.coeff_count - 1;
        let mut index_raw = 0;
        for i in 0..self.coeff_count {
            let index = index_raw & coeff_count_minus_one;
            let mut result_value = if i <= operand.len() {operand[i]} else {0};
            if ((index_raw >> self.coeff_count_power) & 1) > 0 {
                result_value = util::negate_u64_mod(result_value, modulus);
            }
            result[index] = result_value;
            index_raw += galois_elt;
        }
    }

    #[inline]
    pub fn apply_p(&self, poly: &[u64], galois_elt: usize, moduli: &[Modulus], result: &mut [u64]) {
        let mut offset = 0; let degree = self.coeff_count;
        for i in 0..moduli.len() {
            self.apply(&poly[offset..offset+degree], galois_elt, &moduli[i], &mut result[offset..offset+degree]);
            offset += degree;
        }
    }

    #[inline]
    pub fn apply_ps(&self, polys: &[u64], pcount: usize, galois_elt: usize, moduli: &[Modulus], result: &mut[u64]) {
        let degree = self.coeff_count; let d = degree * moduli.len();
        let mut offset = 0;
        for _ in 0..pcount {
            self.apply_p(&polys[offset..offset+d], galois_elt, moduli, &mut result[offset..offset+d]);
            offset += d;
        }
    }

    #[inline]
    pub fn apply_ntt(&self, operand: &[u64], galois_elt: usize, result: &mut [u64]) {
        let index = Self::get_index_from_elt(galois_elt);

        // Acquire lock
        let need_to_generate = {
            let tables = self.permutation_tables.read().unwrap();
            (*tables)[index].is_empty()
        };
        if need_to_generate {
            let mut tables = self.permutation_tables.write().unwrap();
            (*tables)[index] = self.generate_table_ntt(galois_elt);
        }

        // Acquire read
        let reader = self.permutation_tables.read().unwrap();
        let table = &(*reader)[index];
        // Perform permutation.
        assert_eq!(result.len(), self.coeff_count);
        result.iter_mut().zip(table.iter()).for_each(|(r, &t)| *r = operand[t]);
    }

    #[inline]
    pub fn apply_ntt_p(&self, poly: &[u64], coeff_modulus_size: usize, galois_elt: usize, result: &mut [u64]) {
        let mut offset = 0; let degree = self.coeff_count;
        for _ in 0..coeff_modulus_size {
            self.apply_ntt(&poly[offset..offset+degree], galois_elt, &mut result[offset..offset+degree]);
            offset += degree;
        }
    }

    #[inline]
    pub fn apply_ntt_ps(&self, polys: &[u64], pcount: usize, coeff_modulus_size: usize, galois_elt: usize, result: &mut[u64]) {
        let degree = self.coeff_count; let d = degree * coeff_modulus_size;
        let mut offset = 0;
        for _ in 0..pcount {
            self.apply_ntt_p(&polys[offset..offset+d], coeff_modulus_size, galois_elt, &mut result[offset..offset+d]);
            offset += d;
        }
    }

}

#[cfg(test)]
mod tests {
    use crate::{EncryptionParameters, HeContext, SchemeType};

    use super::*;
    
    #[test]
    fn test_get_elts() {
        let tool = GaloisTool::new(3);
        assert_eq!(15, tool.get_elt_from_step(0));
        assert_eq!( 3, tool.get_elt_from_step(1));
        assert_eq!( 3, tool.get_elt_from_step(-3));
        assert_eq!( 9, tool.get_elt_from_step(2));
        assert_eq!( 9, tool.get_elt_from_step(-2));
        assert_eq!(11, tool.get_elt_from_step(3));
        assert_eq!(11, tool.get_elt_from_step(-1));

        let elts = tool.get_elts_from_steps(&[0,1,-3,2,-2,3,-1]);
        assert_eq!(elts, vec![15, 3, 3, 9, 9, 11, 11]);

        let elts = tool.get_elts_all();
        assert_eq!(elts, vec![15, 3, 11, 9, 9]);

        assert_eq!(7, GaloisTool::get_index_from_elt(15));
        assert_eq!(1, GaloisTool::get_index_from_elt(3));
        assert_eq!(4, GaloisTool::get_index_from_elt(9));
        assert_eq!(5, GaloisTool::get_index_from_elt(11));
    }

    #[test]
    fn test_apply_galois() {
        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(8)
            .set_coeff_modulus(&[Modulus::new(17)]);
        let context = HeContext::new(parms, false, crate::SecurityLevel::None);
        let context_data = context.key_context_data().unwrap();
        let galois_tool = context_data.galois_tool();
        let input = vec![0,1,2,3,4,5,6,7];
        let mut output = vec![0; 8];
        galois_tool.apply(&input, 3, &Modulus::new(17), &mut output);
        assert_eq!(output, vec![0,14,6,1,13,7,2,12]);

        let mut output = vec![0; 8];
        galois_tool.apply_ntt(&input, 3, &mut output);
        assert_eq!(output, vec![4,5,7,6,1,0,2,3]);
    }


}