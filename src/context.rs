use crate::{
    EncryptionParameters,
    EncryptionParameterQualifiers,
    encryption_parameters,
    SecurityLevel,
    util::{
        self,
        RNSTool,
        NTTTables,
        GaloisTool, 
        MultiplyU64ModOperand, BlakeRNGFactory, BlakeRNG
    },
    ParmsID, SchemeType, CoeffModulus, PARMS_ID_ZERO
};

use std::sync::{Weak, Arc};
use std::collections::HashMap;

/**
Struct to hold pre-computation data for a given set of encryption parameters.
*/
#[derive(Default)]
pub struct ContextData {
    parms: EncryptionParameters,
    qualifiers: EncryptionParameterQualifiers,
    rns_tool: Option<RNSTool>, // Maybe change to MaybeUninit<T>?
    small_ntt_tables: Vec<NTTTables>,
    plain_ntt_tables: Option<NTTTables>,
    galois_tool: Option<GaloisTool>,
    total_coeff_modulus: Vec<u64>,
    total_coeff_modulus_bit_count: usize,
    coeff_div_plain_modulus: Vec<MultiplyU64ModOperand>,
    plain_upper_half_threshold: u64,
    plain_upper_half_increment: Vec<u64>,
    upper_half_threshold: Vec<u64>,
    upper_half_increment: Vec<u64>,
    coeff_modulus_mod_plain_modulus: u64,
    prev_context_data: Option<Weak<ContextData>>,
    next_context_data: Option<Arc<ContextData>>,
    chain_index: usize,
}

impl ContextData {

    /// Creates a new ContextData object with the given [EncryptionParameters].
    pub fn new(parms: EncryptionParameters) -> Self {
        let x = ContextData { parms: parms, ..Default::default() };
        x
    }
    
    /// Returns the [ParmsID] of this level of [ContextData].
    pub fn parms_id(&self) -> &ParmsID {
        self.parms.parms_id()
    }

    /// Total bit count of the coefficient modulus (the product of all coefficients in the
    /// coefficient moduli chain).
    pub fn total_coeff_modulus_bit_count(&self) -> usize {
        self.total_coeff_modulus_bit_count
    }

    /// Returns the total coefficient modulus (the product of all coefficients in the
    /// coefficient moduli chain).
    pub fn total_coeff_modulus(&self) -> &Vec<u64> {
        &self.total_coeff_modulus
    }

    /// Approximation threshold used in decoding.
    pub fn upper_half_threshold(&self) -> &Vec<u64> {
        &self.upper_half_threshold
    }

    /// Coefficient modulus divided by plain modulus. (q/t)
    pub fn coeff_div_plain_modulus(&self) -> &Vec<MultiplyU64ModOperand> {
        &self.coeff_div_plain_modulus
    }
    
    /// Upper half increment.
    pub fn plain_upper_half_threshold(&self) -> u64 {
        self.plain_upper_half_threshold
    }

    /// Upper half increment.
    pub fn plain_upper_half_increment(&self) -> &Vec<u64> {
        &self.plain_upper_half_increment
    }

    /// Coefficient modulus mod by plain modulus. (q mod t)
    pub fn coeff_modulus_mod_plain_modulus(&self) -> u64 {
        self.coeff_modulus_mod_plain_modulus
    }

    /// [EncryptionParameters] associated with this level of [ContextData].
    pub fn parms(&self) -> &EncryptionParameters {
        &self.parms
    }

    /// [EncryptionParameterQualifiers] associated [Self::parms].
    pub fn qualifiers(&self) -> &EncryptionParameterQualifiers {
        &self.qualifiers
    }

    /// NTT tables of the plain modulus.
    pub fn plain_ntt_tables(&self) -> &NTTTables {
        self.plain_ntt_tables.as_ref().unwrap()
    }

    /// NTT tables of the coeffcient moduli.
    pub fn small_ntt_tables(&self) -> &Vec<NTTTables> {
        &self.small_ntt_tables
    }

    /// The chain index of this level of [ContextData].
    pub fn chain_index(&self) -> usize {
        self.chain_index
    }

    /// The RNS composition/decomposition tool of this level of [ContextData].
    pub(crate) fn rns_tool(&self) -> &RNSTool {
        self.rns_tool.as_ref().unwrap()
    }

    /// The Galois transformation tool of this level of [ContextData].
    pub(crate) fn galois_tool(&self) -> &GaloisTool {
        self.galois_tool.as_ref().unwrap()
    }

    /// Get the next level of [ContextData].
    pub fn next_context_data(&self) -> Option<ContextDataPointer> {
        Some(self.next_context_data.as_ref()?.clone())
    }

    /// Get the previous level of [ContextData].
    pub fn prev_context_data(&self) -> Option<ContextDataPointer> {
        let rc = self.prev_context_data.as_ref()?.upgrade()?;
        Some(rc)
    }

    /// Is the scheme [SchemeType::BFV]?
    pub fn is_bfv(&self) -> bool {
        matches!(self.parms.scheme(), SchemeType::BFV)
    }

    /// Is the scheme [SchemeType::CKKS]?
    pub fn is_ckks(&self) -> bool {
        matches!(self.parms.scheme(), SchemeType::CKKS)
    }

    /// Is the scheme [SchemeType::BGV]?
    pub fn is_bgv(&self) -> bool {
        matches!(self.parms.scheme(), SchemeType::BGV)
    }

}

type ContextDataPointer = Arc<ContextData>;

/// Stores a chain of [ContextData] used for a set of [EncryptionParameters].
///
/// Performs sanity checks (validation) and pre-computations for a given set of encryption
/// parameters. While the EncryptionParameters class is intended to be a light-weight class
/// to store the encryption parameters, the HeContext class is a heavy-weight class that
/// is constructed from a given set of encryption parameters. It validates the parameters
/// for correctness, evaluates their properties, and performs and stores the results of
/// several costly pre-computations.
/// 
/// After the user has set at least the poly_modulus, coeff_modulus, and plain_modulus
/// parameters in a given EncryptionParameters instance, the parameters can be validated
/// for correctness and functionality by constructing an instance of HeContext. The
/// constructor of HeContext does all of its work automatically, and concludes by
/// constructing and storing an instance of the EncryptionParameterQualifiers class, with
/// its flags set according to the properties of the given parameters. If the created
/// instance of EncryptionParameterQualifiers has the parameters_set flag set to true, the
/// given parameter set has been deemed valid and is ready to be used. If the parameters
/// were for some reason not appropriately set, the parameters_set flag will be false,
/// and a new HeContext will have to be created after the parameters are corrected.
/// 
/// By default, HeContext creates a chain of HeContext::ContextData instances. The
/// first one in the chain corresponds to special encryption parameters that are reserved
/// to be used by the various key classes (SecretKey, PublicKey, etc.). These are the exact
/// same encryption parameters that are created by the user and passed to th constructor of
/// HeContext. The functions key_context_data() and key_parms_id() return the ContextData
/// and the parms_id corresponding to these special parameters. The rest of the ContextData
/// instances in the chain correspond to encryption parameters that are derived from the
/// first encryption parameters by always removing the last one of the moduli in the
/// coeff_modulus, until the resulting parameters are no longer valid, e.g., there are no
/// more primes left. These derived encryption parameters are used by ciphertexts and
/// plaintexts and their respective ContextData can be accessed through the
/// get_context_data(parms_id_type) function. The functions first_context_data() and
/// last_context_data() return the ContextData corresponding to the first and the last
/// set of parameters in the "data" part of the chain, i.e., the second and the last element
/// in the full chain. The chain itself is a doubly linked list, and is referred to as the
/// modulus switching chain.
/// 
/// - See [EncryptionParameters] for more details on the parameters.
/// - See [EncryptionParameterQualifiers] for more details on the qualifiers.
pub struct HeContext {
    key_parms_id: ParmsID,
    first_parms_id: ParmsID,
    last_parms_id: ParmsID,
    context_data_map: HashMap<ParmsID, ContextDataPointer>,
    sec_level: SecurityLevel,
    using_keyswitching: bool,
    random_generator_factory: BlakeRNGFactory,
}

impl HeContext {

    /// Get the [ParmsID] of the key level.
    pub fn key_parms_id(&self) -> &ParmsID {
        &self.key_parms_id
    }
    
    /// Get the [ParmsID] of the first ciphertext level.
    pub fn first_parms_id(&self) -> &ParmsID {
        &self.first_parms_id
    }
    
    /// Get the [ParmsID] of the last ciphertext level.
    pub fn last_parms_id(&self) -> &ParmsID {
        &self.last_parms_id
    }

    /// Get the [ContextData] pointer of the specified [ParmsID].
    pub fn get_context_data(&self, parms_id: &ParmsID) -> Option<ContextDataPointer> {
        let obtained = self.context_data_map.get(parms_id)?;
        Some(obtained.clone())
    }

    /// Get the [ContextData] of the key level.
    pub fn key_context_data(&self) -> Option<ContextDataPointer> {
        self.get_context_data(&self.key_parms_id)
    }

    /// Get the [ContextData] of the first ciphertext level.
    pub fn first_context_data(&self) -> Option<ContextDataPointer> {
        self.get_context_data(&self.first_parms_id)
    }

    /// Get the [ContextData] of the last ciphertext level.
    pub fn last_context_data(&self) -> Option<ContextDataPointer> {
        self.get_context_data(&self.last_parms_id)
    }

    /// Does this set of encryption parameters support keyswitching?
    pub fn using_keyswitching(&self) -> bool {
        self.using_keyswitching
    }

    /// Get the security level of this set of encryption parameters
    pub fn security_level(&self) -> SecurityLevel {
        self.sec_level
    }

    /// Are the parameters correctly set? See [EncryptionParameterQualifiers::parameters_set].
    pub fn parameters_set(&self) -> bool {
        let first_context_data = self.first_context_data();
        if let Some(first_context_data) = first_context_data {
            first_context_data.qualifiers.parameters_set()
        } else {
            false
        }
    }

}

impl HeContext {

    fn validate(parms: EncryptionParameters, sec_level: SecurityLevel) -> ContextData {
        type ErrorType = encryption_parameters::ErrorType;
        let mut c = ContextData::new(parms);
        c.qualifiers.parameter_error = ErrorType::Success;

        if let SchemeType::None = c.parms.scheme() {
            c.qualifiers.parameter_error = ErrorType::InvalidScheme;
            return c;
        }
        let coeff_modulus = c.parms.coeff_modulus();
        let plain_modulus = c.parms.plain_modulus();

        // The number of coeff moduli is restricted to 64 to prevent unexpected behaviors
        if coeff_modulus.len() > util::HE_COEFF_MOD_COUNT_MAX || coeff_modulus.len() < util::HE_COEFF_MOD_COUNT_MIN {
            c.qualifiers.parameter_error = ErrorType::InvalidCoeffModulusSize;
            return c;
        } 

        let coeff_modulus_size = coeff_modulus.len();
        for i in 0..coeff_modulus_size {
            // Check coefficient moduli bounds
            if (coeff_modulus[i].value() >> util::HE_USER_MOD_BIT_COUNT_MAX) > 0 ||
                (coeff_modulus[i].value() >> (util::HE_USER_MOD_BIT_COUNT_MIN - 1)) == 0 
            {
                c.qualifiers.parameter_error = ErrorType::InvalidCoeffModulusBitCount;
                return c;
            }
        }

        // Compute the product of all coeff moduli
        c.total_coeff_modulus = vec![0; coeff_modulus_size];
        let coeff_modulus_values = coeff_modulus.iter().map(|x| x.value()).collect::<Vec<_>>();
        util::multiply_many_u64(coeff_modulus_values.as_slice(), &mut c.total_coeff_modulus);
        c.total_coeff_modulus_bit_count = util::get_significant_bit_count_uint(&c.total_coeff_modulus);

        // Check polynomial modulus degree and create poly_modulus
        let poly_modulus_degree = c.parms.poly_modulus_degree();
        if !(util::HE_POLY_MOD_DEGREE_MIN..=util::HE_POLY_MOD_DEGREE_MAX).contains(&poly_modulus_degree) {
            c.qualifiers.parameter_error = ErrorType::InvalidPolyModulusDegree;
            return c;
        }
        let coeff_count_power = util::get_power_of_two(poly_modulus_degree as u64);
        if coeff_count_power < 0 {
            c.qualifiers.parameter_error = ErrorType::InvalidPolyModulusDegreeNonPowerOfTwo;
            return c;
        }
        let coeff_count_power = coeff_count_power as usize;

        if coeff_modulus_size.overflowing_mul(poly_modulus_degree).1 {
            c.qualifiers.parameter_error = ErrorType::InvalidParametersTooLarge;
            return c;
        }

        // Polynomial modulus X^(2^k) + 1 is guaranteed at this point
        c.qualifiers.using_fft = true;

        // Assume parameters satisfy desired security level
        c.qualifiers.sec_level = sec_level;
        // Check if the parameters are secure according to HomomorphicEncryption.org security standard
        if c.total_coeff_modulus_bit_count > CoeffModulus::max_bit_count(poly_modulus_degree, sec_level) {
            c.qualifiers.sec_level = SecurityLevel::None;
            if let SecurityLevel::None = sec_level {
            } else {
                c.qualifiers.parameter_error = ErrorType::InvalidParametersInsecure;
                return c;
            }
        }

        // Set up RNSBase for coeff_modulus
        // RNSBase's constructor may fail due to:
        //   (1) coeff_mod not coprime
        //   (2) cannot find inverse of punctured products (because of (1))
        let coeff_modulus_base = util::RNSBase::new(coeff_modulus);
        if coeff_modulus_base.is_err() {
            c.qualifiers.parameter_error = ErrorType::FailedCreatingRNSBase;
            return c;
        }
        let coeff_modulus_base = coeff_modulus_base.unwrap();

        // Can we use NTT with coeff_modulus?
        c.qualifiers.using_ntt = true;
        let small_ntt_tables = NTTTables::create_ntt_tables(coeff_count_power, coeff_modulus);
        if let Ok(table) = small_ntt_tables {
            c.small_ntt_tables = table;
        } else {
            c.qualifiers.using_ntt = false;
            c.qualifiers.parameter_error = ErrorType::InvalidCoeffModulusNoNTT;
            return c;
        }

        match c.parms.scheme() {
            SchemeType::BFV | SchemeType::BGV => {
                // Plain modulus must be at least 2 and at most 60 bits
                if (plain_modulus.value() >> util::HE_PLAIN_MOD_BIT_COUNT_MAX) > 0 ||
                    (plain_modulus.value() >> (util::HE_PLAIN_MOD_BIT_COUNT_MIN - 1)) == 0
                {
                    c.qualifiers.parameter_error = ErrorType::InvalidPlainModulusBitCount;
                    return c;
                }

                // Check that all coeff moduli are relatively prime to plain_modulus
                for each in coeff_modulus {
                    if !util::are_coprime(each.value(), plain_modulus.value()) {
                        c.qualifiers.parameter_error = ErrorType::InvalidPlainModulusCoprimality;
                        return c;
                    }
                }
                
                // Check that plain_modulus is smaller than total coeff modulus
                if !util::is_less_than_uint(&[plain_modulus.value()], &c.total_coeff_modulus) {
                    // Parameters are not valid
                    c.qualifiers.parameter_error = ErrorType::InvalidPlainModulusTooLarge;
                    return c;
                }
                
                // Can we use batching? (NTT with plain_modulus)
                c.qualifiers.using_batching = true;
                let table = NTTTables::new(coeff_count_power, plain_modulus);
                if let Ok(table) = table {
                    c.plain_ntt_tables = Some(table);
                } else {
                    c.qualifiers.using_batching = false;
                }

                // Check for plain_lift
                // If all the small coefficient moduli are larger than plain modulus, we can quickly
                // lift plain coefficients to RNS form
                c.qualifiers.using_fast_plain_lift = true;
                for each in coeff_modulus {
                    if each.value() <= plain_modulus.value() {
                        c.qualifiers.using_fast_plain_lift = false;
                    }
                }

                // Calculate coeff_div_plain_modulus (BFV-"Delta") and the remainder upper_half_increment
                let mut temp_coeff_div_plain_modulus = vec![0; coeff_modulus_size];
                c.upper_half_increment = vec![0; coeff_modulus_size];
                let mut wide_plain_modulus = vec![0; coeff_modulus_size];
                wide_plain_modulus[0] = plain_modulus.value();
                util::divide_uint(
                    c.total_coeff_modulus.as_slice(), 
                    wide_plain_modulus.as_slice(), 
                    &mut temp_coeff_div_plain_modulus,
                    &mut c.upper_half_increment);
                
                // Store the non-RNS form of upper_half_increment for BFV encryption
                c.coeff_modulus_mod_plain_modulus = c.upper_half_increment[0];

                // Decompose coeff_div_plain_modulus into RNS factors
                coeff_modulus_base.decompose(&mut temp_coeff_div_plain_modulus);
                c.coeff_div_plain_modulus = temp_coeff_div_plain_modulus.iter()
                    .zip(coeff_modulus_base.base().iter())
                    .map(|(x, y)| MultiplyU64ModOperand::new(*x, y))
                    .collect::<Vec<_>>();
                
                // Decompose upper_half_increment into RNS factors
                coeff_modulus_base.decompose(&mut c.upper_half_increment);

                // Calculate (plain_modulus + 1) / 2.
                c.plain_upper_half_threshold = (plain_modulus.value() + 1) >> 1;

                // Calculate coeff_modulus - plain_modulus.
                c.plain_upper_half_increment = vec![0; coeff_modulus_size];
                if c.qualifiers.using_fast_plain_lift {
                    // Calculate coeff_modulus[i] - plain_modulus if using_fast_plain_lift
                    for i in 0..coeff_modulus_size {
                        c.plain_upper_half_increment[i] = coeff_modulus[i].value() - plain_modulus.value();
                    }
                } else {
                    util::sub_uint(&c.total_coeff_modulus, &wide_plain_modulus, &mut c.plain_upper_half_increment);
                }
            } 
            SchemeType::CKKS => {
                // Check that plain_modulus is set to zero
                if !plain_modulus.is_zero() {
                    c.qualifiers.parameter_error = ErrorType::InvalidPlainModulusNonzero;
                    return c;
                }
                
                // When using CKKS batching (BatchEncoder) is always enabled
                c.qualifiers.using_batching = true;
                
                // Cannot use fast_plain_lift for CKKS since the plaintext coefficients
                // can easily be larger than coefficient moduli
                c.qualifiers.using_fast_plain_lift = false;

                // Calculate 2^64 / 2 (most negative plaintext coefficient value)
                c.plain_upper_half_threshold = 1 << 63;

                // Calculate plain_upper_half_increment = 2^64 mod coeff_modulus for CKKS plaintexts
                c.plain_upper_half_increment = vec![0; coeff_modulus_size];
                for i in 0..coeff_modulus_size {
                    let tmp = coeff_modulus[i].reduce(1 << 63);
                    c.plain_upper_half_increment[i] =
                        util::multiply_u64_mod(tmp, coeff_modulus[i].value() - 2, &coeff_modulus[i]);
                }

                // Compute the upper_half_threshold for this modulus.
                c.upper_half_threshold = vec![0; coeff_modulus_size];
                util::increment_uint(&c.total_coeff_modulus, &mut c.upper_half_threshold);
                util::right_shift_uint_inplace(&mut c.upper_half_threshold, 1, coeff_modulus_size);
            } 
            _ => {
                // This should never be executed
                // because scheme check has been done previously.
                c.qualifiers.parameter_error = ErrorType::InvalidScheme;
                return c;
            }
        }
        
        // Create RNSTool
        // RNSTool's constructor may fail due to:
        //   (1) auxiliary base being too large
        //   (2) cannot find inverse of punctured products in auxiliary base
        let rns_tool = RNSTool::new(poly_modulus_degree, &coeff_modulus_base, plain_modulus);
        if let Ok(rns_tool) = rns_tool {
            c.rns_tool = Some(rns_tool);
        } else {
            c.qualifiers.parameter_error = ErrorType::FailedCreatingRNSTool;
            return c;
        }

        // Check whether the coefficient modulus consists of a set of primes that are in decreasing order
        c.qualifiers.using_descending_modulus_chain = true;
        for i in 0..coeff_modulus_size - 1 {
            if coeff_modulus[i].value() <= coeff_modulus[i + 1].value() {
                c.qualifiers.using_descending_modulus_chain = false;
            }
        }

        // Create GaloisTool
        c.galois_tool = Some(GaloisTool::new(coeff_count_power));

        // Done with validation and pre-computations
        c
    }

    fn create_next_context_data(
        context_data_map: &mut HashMap<ParmsID, ContextDataPointer>, 
        prev_parms_id: &ParmsID,
        sec_level: SecurityLevel,
    ) -> ParmsID {
        // Create the next set of parameters by removing last modulus
        let next_parms = context_data_map.get(prev_parms_id).unwrap().parms.clone();
        let mut next_coeff_modulus = next_parms.coeff_modulus().to_vec();
        next_coeff_modulus.pop();
        let next_parms = next_parms.set_coeff_modulus(&next_coeff_modulus);
        let next_parms_id = *next_parms.parms_id();
        
        // Validate next parameters and create next context_data
        let mut next_context_data = Self::validate(next_parms, sec_level);
        
        // If not valid then return zero parms_id
        if !next_context_data.qualifiers.parameters_set() {
            return PARMS_ID_ZERO;
        }
        
        // Add pointer to next context_data to the previous one (linked list)
        // Add pointer to previous context_data to the next one (doubly linked list)
        // We need to remove constness first to modify this
        next_context_data.prev_context_data = Some(Arc::downgrade(context_data_map.get(prev_parms_id).unwrap()));
        let prev_context_data = context_data_map.get(prev_parms_id).unwrap();
        let new_context_data = Arc::new(next_context_data);
        unsafe {
            let ptr = Arc::as_ptr(prev_context_data).cast_mut();
            (*ptr).next_context_data = Some(new_context_data.clone());
        }

        // Add them to the context_data_map_
        context_data_map.insert(next_parms_id, new_context_data);
    
        next_parms_id
    }

    /// Create [HeContext] with the given parameters and security level.
    /// `expand_mod_chain` is need for enabling relinearization and galois transformation.
    pub fn new(parms: EncryptionParameters, expand_mod_chain: bool, sec_level: SecurityLevel) -> Arc<Self> {
        
        // Note: Set random generator.

        // Validate parameters and add new ContextData to the map
        // Note that this happens even if parameters are not valid

        // First create key_parms_id_.
        let mut context_data_map = HashMap::new();
        let key_context_data = Self::validate(parms.clone(), sec_level);
        let key_parms_id = *parms.parms_id();
        context_data_map.insert(key_parms_id, Arc::new(key_context_data));
        
        // Then create first_parms_id_ if the parameters are valid and there is
        // more than one modulus in coeff_modulus. This is equivalent to expanding
        // the chain by one step. Otherwise, we set first_parms_id_ to equal
        // key_parms_id_.
        let first_parms_id = if 
            !context_data_map.get(&key_parms_id).unwrap().qualifiers.parameters_set() || 
            parms.coeff_modulus().len() == 1 || parms.use_special_prime_for_encryption()
        {
            key_parms_id
        } else {
            let next_parms_id = Self::create_next_context_data(&mut context_data_map, &key_parms_id, sec_level);
            if next_parms_id == PARMS_ID_ZERO {key_parms_id} else {next_parms_id}
        };

        // Set last_parms_id_ to point to first_parms_id_
        let mut last_parms_id = first_parms_id;

        // Check if keyswitching is available
        let using_keyswitching = first_parms_id != key_parms_id;
        
        // If modulus switching chain is to be created, compute the remaining parameter sets as long as they are valid
        // to use (i.e., parameters_set() == true).
        if expand_mod_chain && context_data_map.get(&first_parms_id).unwrap().qualifiers.parameters_set() {
            let mut prev_parms_id = first_parms_id;
            while context_data_map.get(&prev_parms_id).unwrap().parms.coeff_modulus().len() > 1 {
                let next_parms_id = Self::create_next_context_data(&mut context_data_map, &prev_parms_id, sec_level);
                if next_parms_id == PARMS_ID_ZERO {
                    break;
                }
                prev_parms_id = next_parms_id;
                last_parms_id = next_parms_id;
            }
        }

        // Set the chain_index for each context_data
        let mut parms_count = context_data_map.len();
        let mut context_data_ptr = context_data_map.get(&key_parms_id).unwrap().clone();
        loop {
            unsafe {
                let ptr = Arc::as_ptr(&context_data_ptr).cast_mut();
                (*ptr).chain_index = parms_count - 1;
            }
            parms_count -= 1;
            let retrieved_ptr;
            if let Some(ptr) = &(context_data_ptr.next_context_data) {
                retrieved_ptr = ptr.clone();
            } else {
                break;
            }
            context_data_ptr = retrieved_ptr;
        }

        Arc::new(HeContext {
            context_data_map,
            key_parms_id,
            first_parms_id,
            last_parms_id,
            sec_level,
            using_keyswitching,
            random_generator_factory: BlakeRNGFactory::new()
        })

    }
    
    /// Create [HeContext] with the given parameters and default [SecurityLevel::Tc128]
    /// security. `expand_mod_chain` is enabled. See [HeContext::new] for more details.
    pub fn new_default(parms: EncryptionParameters) -> Arc<Self> {
        Self::new(parms, true, SecurityLevel::Tc128)
    }

    /// Get a [BlakeRNG] random generator.
    pub(crate) fn create_random_generator(&self) -> BlakeRNG {
        self.random_generator_factory.get_rng_rc()
    }

}


#[cfg(test)]
mod tests {
    use crate::{encryption_parameters::ErrorType, Modulus};
    use super::*;

    #[test]
    fn test_bfv_context_constructor() {

        let scheme = SchemeType::BFV;
        let parms = EncryptionParameters::new(scheme);

        let to_moduli = |m: Vec<u64>| m.into_iter().map(Modulus::new).collect::<Vec<_>>();
        let judge = |
            context: &HeContext, 
            result: ErrorType, 
            parameters_set: bool,
            fft: bool, ntt: bool, 
            batching: bool, fast_plain_lift: bool, 
            descending_chain: bool, 
            sec_level: SecurityLevel, 
            keyswitching: bool,
            key_descend: bool,
        | {
            let qualifier = &context.first_context_data().unwrap().qualifiers;
            assert_eq!(qualifier.parameters_set(), parameters_set);
            assert_eq!(qualifier.parameter_error, result);
            assert_eq!(qualifier.using_fft, fft);
            assert_eq!(qualifier.using_ntt, ntt);
            assert_eq!(qualifier.using_batching, batching);
            assert_eq!(qualifier.using_fast_plain_lift, fast_plain_lift);
            if !key_descend {
                assert_eq!(qualifier.using_descending_modulus_chain, descending_chain);
            } else {
                let key_qualifier = &context.key_context_data().unwrap().qualifiers;
                assert_eq!(key_qualifier.using_descending_modulus_chain, 
                    descending_chain);
            }
            assert_eq!(qualifier.sec_level, sec_level);
            assert_eq!(context.using_keyswitching, keyswitching);
        };

        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        judge(&context, ErrorType::InvalidCoeffModulusSize, 
            false, false, false, false, false, false, SecurityLevel::None, false, false);

        let parms = parms
            .set_poly_modulus_degree(4)
            .set_coeff_modulus(&to_moduli(vec![2, 30]))
            .set_plain_modulus_u64(2);
        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        judge(&context, ErrorType::FailedCreatingRNSBase, 
            false, true, false, false, false, false, SecurityLevel::None, false, false);

        let parms = parms
            .set_poly_modulus_degree(4)
            .set_coeff_modulus(&to_moduli(vec![17, 41]))
            .set_plain_modulus_u64(34)
        ;
        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        judge(&context, ErrorType::InvalidPlainModulusCoprimality, 
            false, true, true, false, false, false, SecurityLevel::None, false, false
        );

        let parms = parms
            .set_poly_modulus_degree(4)
            .set_coeff_modulus(&to_moduli(vec![17]))
            .set_plain_modulus_u64(41)
        ;
        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        assert_eq!(context.first_context_data().unwrap().total_coeff_modulus[0], 17);
        judge(&context, ErrorType::InvalidPlainModulusTooLarge, 
            false, true, true, false, false, false, SecurityLevel::None, false, false
        );
        
        let parms = parms
            .set_poly_modulus_degree(4)
            .set_coeff_modulus(&to_moduli(vec![3]))
            .set_plain_modulus_u64(2)
        ;
        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        assert_eq!(context.first_context_data().unwrap().total_coeff_modulus[0], 3);
        judge(&context, ErrorType::InvalidCoeffModulusNoNTT, 
            false, true, false, false, false, false, SecurityLevel::None, false, false
        );

        let parms = parms
            .set_poly_modulus_degree(4)
            .set_coeff_modulus(&to_moduli(vec![17, 41]))
            .set_plain_modulus_u64(18)
        ;
        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        assert_eq!(context.first_context_data().unwrap().total_coeff_modulus[0], 697);
        judge(&context, ErrorType::Success, 
            true, true, true, false, false, false, SecurityLevel::None, false, false
        );

        let parms = parms
            .set_poly_modulus_degree(4)
            .set_coeff_modulus(&to_moduli(vec![17, 41]))
            .set_plain_modulus_u64(16)
        ;
        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        assert_eq!(context.first_context_data().unwrap().total_coeff_modulus[0], 17);
        assert_eq!(context.key_context_data().unwrap().total_coeff_modulus[0], 697);
        judge(&context, ErrorType::Success, 
            true, true, true, false, true, false, SecurityLevel::None, true, true
        );
        
        let parms = parms
            .set_poly_modulus_degree(4)
            .set_coeff_modulus(&to_moduli(vec![17, 41]))
            .set_plain_modulus_u64(49)
        ;
        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        assert_eq!(context.first_context_data().unwrap().total_coeff_modulus[0], 697);
        judge(&context, ErrorType::Success, 
            true, true, true, false, false, false, SecurityLevel::None, false, false
        );
        
        let parms = parms
            .set_poly_modulus_degree(4)
            .set_coeff_modulus(&to_moduli(vec![17, 41]))
            .set_plain_modulus_u64(73)
        ;
        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        assert_eq!(context.first_context_data().unwrap().total_coeff_modulus[0], 697);
        judge(&context, ErrorType::Success, 
            true, true, true, true, false, false, SecurityLevel::None, false, false
        );
        
        let parms = parms
            .set_poly_modulus_degree(4)
            .set_coeff_modulus(&to_moduli(vec![137, 193]))
            .set_plain_modulus_u64(73)
        ;
        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        assert_eq!(context.first_context_data().unwrap().total_coeff_modulus[0], 137);
        assert_eq!(context.key_context_data().unwrap().total_coeff_modulus[0], 26441);
        judge(&context, ErrorType::Success, 
            true, true, true, true, true, false, SecurityLevel::None, true, true
        );
        
        let parms = parms
            .set_poly_modulus_degree(4)
            .set_coeff_modulus(&to_moduli(vec![137, 193]))
            .set_plain_modulus_u64(73)
        ;
        let context = HeContext::new(parms.clone(), false, SecurityLevel::Tc128);
        judge(&context, ErrorType::InvalidParametersInsecure, 
            false, true, false, false, false, false, SecurityLevel::None, false, false
        );
        
        let parms = parms
            .set_poly_modulus_degree(2048)
            .set_coeff_modulus(&CoeffModulus::bfv_default(4096, SecurityLevel::Tc128))
            .set_plain_modulus_u64(73)
        ;
        let context = HeContext::new(parms.clone(), false, SecurityLevel::Tc128);
        judge(&context, ErrorType::InvalidParametersInsecure, 
            false, true, false, false, false, false, SecurityLevel::None, false, false
        );
        
        let parms = parms
            .set_poly_modulus_degree(4096)
            .set_coeff_modulus(&to_moduli(vec![0xffffee001, 0xffffc4001]))
            .set_plain_modulus_u64(73)
        ;
        let context = HeContext::new(parms.clone(), false, SecurityLevel::Tc128);
        judge(&context, ErrorType::Success, 
            true, true, true, false, true, true, SecurityLevel::Tc128, true, false
        );

        let parms = parms
            .set_poly_modulus_degree(2048)
            .set_coeff_modulus(&to_moduli(vec![0x1ffffe0001, 0xffffee001, 0xffffc4001]))
            .set_plain_modulus_u64(73)
        ;
        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        judge(&context, ErrorType::Success, 
            true, true, true, false, true, true, SecurityLevel::None, true, true
        );
        
        let parms = parms
            .set_poly_modulus_degree(2048)
            .set_coeff_modulus(&CoeffModulus::create(2048, vec![40]))
            .set_plain_modulus_u64(65537)
        ;
        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        judge(&context, ErrorType::Success, 
            true, true, true, true, true, true, SecurityLevel::None, false, false
        );
    }

    fn assert_none<T>(x: &Option<T>) {
        if x.is_none() {return;}
        unreachable!();
    }

    #[test]
    fn test_modulus_chain_expansion() {
        let to_moduli = |m: Vec<u64>| m.into_iter().map(Modulus::new).collect::<Vec<_>>();
        
        // BFV
        let parms = EncryptionParameters::new(SchemeType::BFV)
            .set_poly_modulus_degree(4)
            .set_coeff_modulus(&to_moduli(vec![41, 137, 193, 65537]))
            .set_plain_modulus_u64(73)
        ;
        let context = HeContext::new(parms.clone(), true, SecurityLevel::None);
        let context_data = context.key_context_data().unwrap();
        assert_eq!(context_data.chain_index, 2);
        assert_eq!(context_data.total_coeff_modulus[0], 71047416497);
        assert_none(&context_data.prev_context_data());
        assert_eq!(context_data.parms_id(), context.key_parms_id());
        let prev_context_data = context_data;
        let context_data = prev_context_data.next_context_data().unwrap();
        assert_eq!(context_data.chain_index, 1);
        assert_eq!(context_data.total_coeff_modulus[0], 1084081);
        assert_eq!(
            context_data.prev_context_data().unwrap().parms_id(), 
            prev_context_data.parms_id()
        );
        let prev_context_data = context_data;
        let context_data = prev_context_data.next_context_data().unwrap();
        assert_eq!(context_data.chain_index, 0);
        assert_eq!(context_data.total_coeff_modulus[0], 5617);
        assert_eq!(
            context_data.prev_context_data().unwrap().parms_id(), 
            prev_context_data.parms_id()
        );
        assert_none(&context_data.next_context_data());
        assert_eq!(context_data.parms_id(), context.last_parms_id());

        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        assert_eq!(context.key_context_data().unwrap().chain_index, 1);
        assert_eq!(context.first_context_data().unwrap().chain_index, 0);
        assert_eq!(context.key_context_data().unwrap().total_coeff_modulus[0], 71047416497);
        assert_eq!(context.first_context_data().unwrap().total_coeff_modulus[0], 1084081);
        
        // BGV
        let parms = EncryptionParameters::new(SchemeType::BGV)
            .set_poly_modulus_degree(4)
            .set_coeff_modulus(&to_moduli(vec![41, 137, 193, 65537]))
            .set_plain_modulus_u64(73)
        ;
        let context = HeContext::new(parms.clone(), true, SecurityLevel::None);
        let context_data = context.key_context_data().unwrap();
        assert_eq!(context_data.chain_index, 2);
        assert_eq!(context_data.total_coeff_modulus[0], 71047416497);
        assert_none(&context_data.prev_context_data());
        assert_eq!(context_data.parms_id(), context.key_parms_id());
        let prev_context_data = context_data;
        let context_data = prev_context_data.next_context_data().unwrap();
        assert_eq!(context_data.chain_index, 1);
        assert_eq!(context_data.total_coeff_modulus[0], 1084081);
        assert_eq!(
            context_data.prev_context_data().unwrap().parms_id(), 
            prev_context_data.parms_id()
        );
        let prev_context_data = context_data;
        let context_data = prev_context_data.next_context_data().unwrap();
        assert_eq!(context_data.chain_index, 0);
        assert_eq!(context_data.total_coeff_modulus[0], 5617);
        assert_eq!(
            context_data.prev_context_data().unwrap().parms_id(), 
            prev_context_data.parms_id()
        );
        assert_none(&context_data.next_context_data());
        assert_eq!(context_data.parms_id(), context.last_parms_id());

        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        assert_eq!(context.key_context_data().unwrap().chain_index, 1);
        assert_eq!(context.first_context_data().unwrap().chain_index, 0);
        assert_eq!(context.key_context_data().unwrap().total_coeff_modulus[0], 71047416497);
        assert_eq!(context.first_context_data().unwrap().total_coeff_modulus[0], 1084081);
        
        // CKKS
        let parms = EncryptionParameters::new(SchemeType::CKKS)
            .set_poly_modulus_degree(4)
            .set_coeff_modulus(&to_moduli(vec![41, 137, 193, 65537]))
        ;
        let context = HeContext::new(parms.clone(), true, SecurityLevel::None);
        let context_data = context.key_context_data().unwrap();
        assert_eq!(context_data.chain_index, 3);
        assert_eq!(context_data.total_coeff_modulus[0], 71047416497);
        assert_none(&context_data.prev_context_data());
        assert_eq!(context_data.parms_id(), context.key_parms_id());
        let prev_context_data = context_data;
        let context_data = prev_context_data.next_context_data().unwrap();
        assert_eq!(context_data.chain_index, 2);
        assert_eq!(context_data.total_coeff_modulus[0], 1084081);
        assert_eq!(
            context_data.prev_context_data().unwrap().parms_id(), 
            prev_context_data.parms_id()
        );
        let prev_context_data = context_data;
        let context_data = prev_context_data.next_context_data().unwrap();
        assert_eq!(context_data.chain_index, 1);
        assert_eq!(context_data.total_coeff_modulus[0], 5617);
        assert_eq!(
            context_data.prev_context_data().unwrap().parms_id(), 
            prev_context_data.parms_id()
        );
        let prev_context_data = context_data;
        let context_data = prev_context_data.next_context_data().unwrap();
        assert_eq!(context_data.chain_index, 0);
        assert_eq!(context_data.total_coeff_modulus[0], 41);
        assert_eq!(
            context_data.prev_context_data().unwrap().parms_id(), 
            prev_context_data.parms_id()
        );
        assert_none(&context_data.next_context_data());
        assert_eq!(context_data.parms_id(), context.last_parms_id());

        let context = HeContext::new(parms.clone(), false, SecurityLevel::None);
        assert_eq!(context.key_context_data().unwrap().chain_index, 1);
        assert_eq!(context.first_context_data().unwrap().chain_index, 0);
        assert_eq!(context.key_context_data().unwrap().total_coeff_modulus[0], 71047416497);
        assert_eq!(context.first_context_data().unwrap().total_coeff_modulus[0], 1084081);
    }
}
