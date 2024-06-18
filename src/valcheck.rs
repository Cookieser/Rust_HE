
use crate::{
    Plaintext, Ciphertext, SecretKey, PublicKey, RelinKeys, GaloisKeys, KSwitchKeys,
    HeContext, util,
};

/// Provide methods for checking the validity of an HE objects
pub trait ValCheck {
    /// Check whether the metadata is valid.
    fn is_metadata_valid_for(&self, context: &HeContext, allow_pure_key_levels: bool) -> bool;
    /// Check whether the buffer is valid.
    fn is_buffer_valid(&self) -> bool;
    /// Check whether the data is valid.
    fn is_data_valid_for(&self, context: &HeContext) -> bool;
    /// Check whether the object is valid. 
    /// Shortcut for [ValCheck::is_data_valid_for] plus [ValCheck::is_buffer_valid].
    fn is_valid_for(&self, context: &HeContext) -> bool {
        self.is_data_valid_for(context) && self.is_buffer_valid()
    }
}

impl ValCheck for Plaintext {

    fn is_buffer_valid(&self) -> bool {
        self.data().len() == self.coeff_count()
    }

    fn is_metadata_valid_for(&self, context: &HeContext, allow_pure_key_levels: bool) -> bool {
        if !context.parameters_set() {return false;}
        if self.is_ntt_form() {
            // Are the parameters valid for the plaintext?
            let context_data = context.get_context_data(self.parms_id());
            if context_data.is_none() {return false;}
            let context_data = context_data.unwrap();

            // Check whether the parms_id is in the pure key range
            let is_params_pure_key = context_data.chain_index() > context.first_context_data().unwrap().chain_index();
            if !allow_pure_key_levels && is_params_pure_key {return false;}

            let parms = context_data.parms();
            let coeff_modulus_size = parms.coeff_modulus().len();
            let poly_modulus_degree = parms.poly_modulus_degree();
            if self.coeff_count() != coeff_modulus_size * poly_modulus_degree {return false;}
        } else {
            let context_data = context.first_context_data().unwrap();
            let parms = context_data.parms();
            let poly_modulus_degree = parms.poly_modulus_degree();
            if self.coeff_count() > poly_modulus_degree {return false;}
        }
        true
    }

    fn is_data_valid_for(&self, context: &HeContext) -> bool {
        if !self.is_metadata_valid_for(context, false) {return false;}
        if self.is_ntt_form() {
            let context_data_ptr = context.get_context_data(self.parms_id()).unwrap();
            let parms = context_data_ptr.parms();
            let coeff_modulus = parms.coeff_modulus();
            let coeff_modulus_size = coeff_modulus.len();
            let poly_modulus_degree = parms.poly_modulus_degree();
            let mut offset = 0;
            for j in 0..coeff_modulus_size {
                let modulus = coeff_modulus[j].value();
                for i in 0..poly_modulus_degree {
                    if self.data_at(offset + i) >= modulus {return false;}
                }
                offset += poly_modulus_degree;
            }
        } else {
            let context_data = context.first_context_data().unwrap();
            let parms = context_data.parms();
            let modulus = parms.plain_modulus().value();
            let size = self.coeff_count();
            for k in 0..size {
                if self.data_at(k) >= modulus {return false;}
            }
        }
        true
    }

}

impl ValCheck for Ciphertext {

    fn is_metadata_valid_for(&self, context: &HeContext, allow_pure_key_levels: bool) -> bool {
        if !context.parameters_set() {return false;}

        // Are the parameters valid for the ciphertext?
        let context_data = context.get_context_data(self.parms_id());
        if context_data.is_none() {return false;}
        let context_data = context_data.unwrap();

        // Check whether the parms_id is in the pure key range
        let is_params_pure_key = context_data.chain_index() > context.first_context_data().unwrap().chain_index();
        if !allow_pure_key_levels && is_params_pure_key {return false;}

        // Check the metadata matches
        let parms = context_data.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let poly_modulus_degree = parms.poly_modulus_degree();
        if self.coeff_modulus_size() != coeff_modulus_size {return false;}
        if self.poly_modulus_degree() != poly_modulus_degree {return false;}

        // Check that size is either 0 or within right bounds
        if self.size() < util::HE_CIPHERTEXT_SIZE_MIN && self.size() != 0 {return false;}
        if self.size() > util::HE_CIPHERTEXT_SIZE_MAX {return false;}

        // Check that scale is 1.0 in BFV and BGV or not 0.0 in CKKS
        if context_data.is_bfv() || context_data.is_bgv() {
            if self.scale() != 1.0 {return false;}
        } else if context_data.is_ckks() && self.scale() == 0.0 {return false;}
        
        // Check that correction factor is 1 in BFV and CKKS or within the right bound in BGV
        let correction_factor = self.correction_factor();
        let plain_modulus = parms.plain_modulus();
        if context_data.is_bfv() || context_data.is_ckks() {
            if correction_factor != 1 {return false;}
        } else if context_data.is_bgv() && (correction_factor == 0 || correction_factor > plain_modulus.value()) {return false;}
        
        true
    }

    fn is_buffer_valid(&self) -> bool {
        self.data().len() == self.coeff_modulus_size() * self.size() * self.poly_modulus_degree()
    }

    fn is_data_valid_for(&self, context: &HeContext) -> bool {
        if !self.is_metadata_valid_for(context, false) {return false;}
        let context_data_ptr = context.get_context_data(self.parms_id()).unwrap();
        let parms = context_data_ptr.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let poly_modulus_degree = parms.poly_modulus_degree();
        let mut offset = 0;
        for _ in 0..self.size() {
            for j in 0..coeff_modulus_size {
                let modulus = coeff_modulus[j].value();
                for k in 0..poly_modulus_degree {
                    if self.data_at(offset + k) >= modulus {return false;}
                }
                offset += poly_modulus_degree;
            }
        }
        true
    }

}

impl ValCheck for SecretKey {

    fn is_metadata_valid_for(&self, context: &HeContext, allow_pure_key_levels: bool) -> bool {
        assert!(allow_pure_key_levels, "[Invalid argument] Must allow pure key levels");
        let key_parms_id = context.key_parms_id();
        self.as_plaintext().is_metadata_valid_for(context, true) && self.parms_id() == key_parms_id
    }

    fn is_buffer_valid(&self) -> bool {
        self.as_plaintext().is_buffer_valid()
    }

    fn is_data_valid_for(&self, context: &HeContext) -> bool {
        if !self.is_metadata_valid_for(context, true) {return false;}
        // let plaintext = self.as_plaintext();

        let context_data_ptr = context.key_context_data().unwrap();
        let parms = context_data_ptr.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let poly_modulus_degree = parms.poly_modulus_degree();
        let mut offset = 0;
        for j in 0..coeff_modulus_size {
            let modulus = coeff_modulus[j].value();
            for i in 0..poly_modulus_degree {
                if self.data_at(offset + i) >= modulus {
                    return false;
                }
            }
            offset += poly_modulus_degree;
        }

        true
    }

}

impl ValCheck for PublicKey {

    fn is_metadata_valid_for(&self, context: &HeContext, allow_pure_key_levels: bool) -> bool {
        assert!(allow_pure_key_levels, "[Invalid argument] Must allow pure key levels");
        let key_parms_id = context.key_parms_id();
        // println!("{}, {}, {}, {}", 
        //     self.as_ciphertext().is_metadata_valid_for(context, true), 
        //     self.parms_id() == key_parms_id, 
        //     self.as_ciphertext().is_ntt_form(), 
        //     self.as_ciphertext().size() == util::HE_CIPHERTEXT_SIZE_MIN);
        self.as_ciphertext().is_metadata_valid_for(context, true) 
            && self.parms_id() == key_parms_id
            && self.as_ciphertext().is_ntt_form()
            && self.as_ciphertext().size() == util::HE_CIPHERTEXT_SIZE_MIN
    }

    fn is_buffer_valid(&self) -> bool {
        self.as_ciphertext().is_buffer_valid()
    }

    fn is_data_valid_for(&self, context: &HeContext) -> bool {
        if !self.is_metadata_valid_for(context, true) {
            return false;
        }
        let context_data_ptr = context.get_context_data(self.parms_id()).unwrap();
        let parms = context_data_ptr.parms();
        let coeff_modulus = parms.coeff_modulus();
        let coeff_modulus_size = coeff_modulus.len();
        let poly_modulus_degree = parms.poly_modulus_degree();
        let mut offset = 0;
        let cipher = self.as_ciphertext();
        for _ in 0..cipher.size() {
            for j in 0..coeff_modulus_size {
                let modulus = coeff_modulus[j].value();
                for k in 0..poly_modulus_degree {
                    if self.data_at(offset + k) >= modulus {
                        return false;
                    }
                }
                offset += poly_modulus_degree;
            }
        }
        true
    }

}

impl ValCheck for KSwitchKeys {

    fn is_metadata_valid_for(&self, context: &HeContext, allow_pure_key_levels: bool) -> bool {
        assert!(allow_pure_key_levels, "[Invalid argument] Must allow pure key levels");
        self.data().iter().all(|keys| {
            keys.iter().all(|key| {
                key.is_metadata_valid_for(context, true)
            })
        })
    }

    fn is_buffer_valid(&self) -> bool {
        self.data().iter().all(|keys| {
            keys.iter().all(|key| {
                key.is_buffer_valid()
            })
        })
    }

    fn is_data_valid_for(&self, context: &HeContext) -> bool {
        self.data().iter().all(|keys| {
            keys.iter().all(|key| {
                key.is_data_valid_for(context)
            })
        })
    }

}

impl ValCheck for RelinKeys {

    fn is_metadata_valid_for(&self, context: &HeContext, allow_pure_key_levels: bool) -> bool {
        self.as_kswitch_keys().is_metadata_valid_for(context, allow_pure_key_levels)
    }

    fn is_buffer_valid(&self) -> bool {
        self.as_kswitch_keys().is_buffer_valid()
    }

    fn is_data_valid_for(&self, context: &HeContext) -> bool {
        self.as_kswitch_keys().is_data_valid_for(context)
    }

}

impl ValCheck for GaloisKeys {

    fn is_metadata_valid_for(&self, context: &HeContext, allow_pure_key_levels: bool) -> bool {
        self.as_kswitch_keys().is_metadata_valid_for(context, allow_pure_key_levels)
    }

    fn is_buffer_valid(&self) -> bool {
        self.as_kswitch_keys().is_buffer_valid()
    }

    fn is_data_valid_for(&self, context: &HeContext) -> bool {
        self.as_kswitch_keys().is_data_valid_for(context)
    }

}