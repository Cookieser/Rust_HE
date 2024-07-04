use crate::Evaluator;
use super::{
    RnspHeContext, RnspCiphertext, RnspPlaintext,
    RnspRelinKeys
};

pub struct RnspEvaluator {
    pub components: Vec<Evaluator>,
}

impl RnspEvaluator {

    pub fn new(context: &RnspHeContext) -> Self {
        let components = context.components
            .iter()
            .map(|c| 
                Evaluator::new(c.clone())
            )
            .collect();
        Self { components }
    }

    pub fn negate_inplace(&self, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(destination.components.iter_mut()).for_each(|(evaluator, destination)| {
            evaluator.negate_inplace(destination)
        });
    }

    pub fn negate_new(&self, source: &RnspCiphertext) -> RnspCiphertext {
        assert_eq!(self.components.len(), source.components.len());
        let components = self.components.iter().zip(source.components.iter()).map(|(evaluator, source)| {
            evaluator.negate_new(source)
        }).collect();
        RnspCiphertext::from_raw_parts(components)
    }

    pub fn add_inplace(&self, destination: &mut RnspCiphertext, source: &RnspCiphertext) {
        assert_eq!(self.components.len(), destination.components.len());
        assert_eq!(self.components.len(), source.components.len());
        self.components.iter().zip(destination.components.iter_mut().zip(source.components.iter())).for_each(|(evaluator, (destination, source))| {
            evaluator.add_inplace(destination, source)
        });
    }

    pub fn add(&self, ciphertext1: &RnspCiphertext, ciphertext2: &RnspCiphertext, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), ciphertext1.components.len());
        assert_eq!(self.components.len(), ciphertext2.components.len());
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(ciphertext1.components.iter().zip(ciphertext2.components.iter().zip(destination.components.iter_mut()))).for_each(|(evaluator, (ciphertext1, (ciphertext2, destination)))| {
            evaluator.add(ciphertext1, ciphertext2, destination)
        });
    }

    pub fn add_new(&self, ciphertext1: &RnspCiphertext, ciphertext2: &RnspCiphertext) -> RnspCiphertext {
        assert_eq!(self.components.len(), ciphertext1.components.len());
        assert_eq!(self.components.len(), ciphertext2.components.len());
        let components = self.components.iter().zip(ciphertext1.components.iter().zip(ciphertext2.components.iter())).map(|(evaluator, (ciphertext1, ciphertext2))| {
            evaluator.add_new(ciphertext1, ciphertext2)
        }).collect();
        RnspCiphertext::from_raw_parts(components)
    }

    pub fn sub_inplace(&self, destination: &mut RnspCiphertext, source: &RnspCiphertext) {
        assert_eq!(self.components.len(), destination.components.len());
        assert_eq!(self.components.len(), source.components.len());
        self.components.iter().zip(destination.components.iter_mut().zip(source.components.iter())).for_each(|(evaluator, (destination, source))| {
            evaluator.sub_inplace(destination, source)
        });
    }

    pub fn sub(&self, ciphertext1: &RnspCiphertext, ciphertext2: &RnspCiphertext, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), ciphertext1.components.len());
        assert_eq!(self.components.len(), ciphertext2.components.len());
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(ciphertext1.components.iter().zip(ciphertext2.components.iter().zip(destination.components.iter_mut()))).for_each(|(evaluator, (ciphertext1, (ciphertext2, destination)))| {
            evaluator.sub(ciphertext1, ciphertext2, destination)
        });
    }

    pub fn sub_new(&self, ciphertext1: &RnspCiphertext, ciphertext2: &RnspCiphertext) -> RnspCiphertext {
        assert_eq!(self.components.len(), ciphertext1.components.len());
        assert_eq!(self.components.len(), ciphertext2.components.len());
        let components = self.components.iter().zip(ciphertext1.components.iter().zip(ciphertext2.components.iter())).map(|(evaluator, (ciphertext1, ciphertext2))| {
            evaluator.sub_new(ciphertext1, ciphertext2)
        }).collect();
        RnspCiphertext::from_raw_parts(components)
    }

    pub fn multiply_inplace(&self, destination: &mut RnspCiphertext, source: &RnspCiphertext) {
        assert_eq!(self.components.len(), destination.components.len());
        assert_eq!(self.components.len(), source.components.len());
        self.components.iter().zip(destination.components.iter_mut().zip(source.components.iter())).for_each(|(evaluator, (destination, source))| {
            evaluator.multiply_inplace(destination, source)
        });
    }

    pub fn multiply(&self, ciphertext1: &RnspCiphertext, ciphertext2: &RnspCiphertext, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), ciphertext1.components.len());
        assert_eq!(self.components.len(), ciphertext2.components.len());
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(ciphertext1.components.iter().zip(ciphertext2.components.iter().zip(destination.components.iter_mut()))).for_each(|(evaluator, (ciphertext1, (ciphertext2, destination)))| {
            evaluator.multiply(ciphertext1, ciphertext2, destination)
        });
    }

    pub fn multiply_new(&self, ciphertext1: &RnspCiphertext, ciphertext2: &RnspCiphertext) -> RnspCiphertext {
        assert_eq!(self.components.len(), ciphertext1.components.len());
        assert_eq!(self.components.len(), ciphertext2.components.len());
        let components = self.components.iter().zip(ciphertext1.components.iter().zip(ciphertext2.components.iter())).map(|(evaluator, (ciphertext1, ciphertext2))| {
            evaluator.multiply_new(ciphertext1, ciphertext2)
        }).collect();
        RnspCiphertext::from_raw_parts(components)
    }

    pub fn square_inplace(&self, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(destination.components.iter_mut()).for_each(|(evaluator, destination)| {
            evaluator.square_inplace(destination)
        });
    }

    pub fn square(&self, source: &RnspCiphertext, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), source.components.len());
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(source.components.iter().zip(destination.components.iter_mut())).for_each(|(evaluator, (source, destination))| {
            evaluator.square(source, destination)
        });
    }

    pub fn square_new(&self, source: &RnspCiphertext) -> RnspCiphertext {
        assert_eq!(self.components.len(), source.components.len());
        let components = self.components.iter().zip(source.components.iter()).map(|(evaluator, source)| {
            evaluator.square_new(source)
        }).collect();
        RnspCiphertext::from_raw_parts(components)
    }

    pub fn relinearize_inplace(&self, destination: &mut RnspCiphertext, relin_keys: &RnspRelinKeys) {
        assert_eq!(self.components.len(), destination.components.len());
        assert_eq!(self.components.len(), relin_keys.components.len());
        self.components.iter().zip(destination.components.iter_mut().zip(relin_keys.components.iter())).for_each(|(evaluator, (destination, relin_keys))| {
            evaluator.relinearize_inplace(destination, relin_keys)
        });
    }

    pub fn relinearize(&self, source: &RnspCiphertext, relin_keys: &RnspRelinKeys, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), source.components.len());
        assert_eq!(self.components.len(), relin_keys.components.len());
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(source.components.iter().zip(relin_keys.components.iter().zip(destination.components.iter_mut()))).for_each(|(evaluator, (source, (relin_keys, destination)))| {
            evaluator.relinearize(source, relin_keys, destination)
        });
    }

    pub fn relinearize_new(&self, source: &RnspCiphertext, relin_keys: &RnspRelinKeys) -> RnspCiphertext {
        assert_eq!(self.components.len(), source.components.len());
        assert_eq!(self.components.len(), relin_keys.components.len());
        let components = self.components.iter().zip(source.components.iter().zip(relin_keys.components.iter())).map(|(evaluator, (source, relin_keys))| {
            evaluator.relinearize_new(source, relin_keys)
        }).collect();
        RnspCiphertext::from_raw_parts(components)
    }

    pub fn mod_switch_to_next(&self, source: &RnspCiphertext, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), source.components.len());
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(source.components.iter().zip(destination.components.iter_mut())).for_each(|(evaluator, (source, destination))| {
            evaluator.mod_switch_to_next(source, destination)
        });
    }

    pub fn mod_switch_to_next_inplace(&self, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(destination.components.iter_mut()).for_each(|(evaluator, destination)| {
            evaluator.mod_switch_to_next_inplace(destination)
        });
    }

    pub fn mod_switch_to_next_new(&self, source: &RnspCiphertext) -> RnspCiphertext {
        assert_eq!(self.components.len(), source.components.len());
        let components = self.components.iter().zip(source.components.iter()).map(|(evaluator, source)| {
            evaluator.mod_switch_to_next_new(source)
        }).collect();
        RnspCiphertext::from_raw_parts(components)
    }

    pub fn mod_switch_to_next_plain(&self, source: &RnspPlaintext, destination: &mut RnspPlaintext) {
        assert_eq!(self.components.len(), source.components.len());
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(source.components.iter().zip(destination.components.iter_mut())).for_each(|(evaluator, (source, destination))| {
            evaluator.mod_switch_to_next_plain(source, destination)
        });
    }

    pub fn mod_switch_to_next_plain_inplace(&self, destination: &mut RnspPlaintext) {
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(destination.components.iter_mut()).for_each(|(evaluator, destination)| {
            evaluator.mod_switch_to_next_plain_inplace(destination)
        });
    }

    pub fn rescale_to_next_inplace(&self, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(destination.components.iter_mut()).for_each(|(evaluator, destination)| {
            evaluator.rescale_to_next_inplace(destination)
        });
    }

    pub fn rescale_to_next_new(&self, source: &RnspCiphertext) -> RnspCiphertext {
        assert_eq!(self.components.len(), source.components.len());
        let components = self.components.iter().zip(source.components.iter()).map(|(evaluator, source)| {
            evaluator.rescale_to_next_new(source)
        }).collect();
        RnspCiphertext::from_raw_parts(components)
    }

    pub fn add_plain_inplace(&self, destination: &mut RnspCiphertext, plain: &RnspPlaintext) {
        assert_eq!(self.components.len(), destination.components.len());
        assert_eq!(self.components.len(), plain.components.len());
        self.components.iter().zip(destination.components.iter_mut().zip(plain.components.iter())).for_each(|(evaluator, (destination, plain))| {
            evaluator.add_plain_inplace(destination, plain)
        });
    }

    pub fn add_plain(&self, ciphertext: &RnspCiphertext, plain: &RnspPlaintext, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), ciphertext.components.len());
        assert_eq!(self.components.len(), plain.components.len());
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(ciphertext.components.iter().zip(plain.components.iter().zip(destination.components.iter_mut()))).for_each(|(evaluator, (ciphertext, (plain, destination)))| {
            evaluator.add_plain(ciphertext, plain, destination)
        });
    }

    pub fn add_plain_new(&self, ciphertext: &RnspCiphertext, plain: &RnspPlaintext) -> RnspCiphertext {
        assert_eq!(self.components.len(), ciphertext.components.len());
        assert_eq!(self.components.len(), plain.components.len());
        let components = self.components.iter().zip(ciphertext.components.iter().zip(plain.components.iter())).map(|(evaluator, (ciphertext, plain))| {
            evaluator.add_plain_new(ciphertext, plain)
        }).collect();
        RnspCiphertext::from_raw_parts(components)
    }

    pub fn sub_plain_inplace(&self, destination: &mut RnspCiphertext, plain: &RnspPlaintext) {
        assert_eq!(self.components.len(), destination.components.len());
        assert_eq!(self.components.len(), plain.components.len());
        self.components.iter().zip(destination.components.iter_mut().zip(plain.components.iter())).for_each(|(evaluator, (destination, plain))| {
            evaluator.sub_plain_inplace(destination, plain)
        });
    }

    pub fn sub_plain(&self, ciphertext: &RnspCiphertext, plain: &RnspPlaintext, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), ciphertext.components.len());
        assert_eq!(self.components.len(), plain.components.len());
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(ciphertext.components.iter().zip(plain.components.iter().zip(destination.components.iter_mut()))).for_each(|(evaluator, (ciphertext, (plain, destination)))| {
            evaluator.sub_plain(ciphertext, plain, destination)
        });
    }

    pub fn sub_plain_new(&self, ciphertext: &RnspCiphertext, plain: &RnspPlaintext) -> RnspCiphertext {
        assert_eq!(self.components.len(), ciphertext.components.len());
        assert_eq!(self.components.len(), plain.components.len());
        let components = self.components.iter().zip(ciphertext.components.iter().zip(plain.components.iter())).map(|(evaluator, (ciphertext, plain))| {
            evaluator.sub_plain_new(ciphertext, plain)
        }).collect();
        RnspCiphertext::from_raw_parts(components)
    }

    pub fn multiply_plain_inplace(&self, destination: &mut RnspCiphertext, plain: &RnspPlaintext) {
        assert_eq!(self.components.len(), destination.components.len());
        assert_eq!(self.components.len(), plain.components.len());
        self.components.iter().zip(destination.components.iter_mut().zip(plain.components.iter())).for_each(|(evaluator, (destination, plain))| {
            evaluator.multiply_plain_inplace(destination, plain)
        });
    }

    pub fn multiply_plain(&self, ciphertext: &RnspCiphertext, plain: &RnspPlaintext, destination: &mut RnspCiphertext) {
        assert_eq!(self.components.len(), ciphertext.components.len());
        assert_eq!(self.components.len(), plain.components.len());
        assert_eq!(self.components.len(), destination.components.len());
        self.components.iter().zip(ciphertext.components.iter().zip(plain.components.iter().zip(destination.components.iter_mut()))).for_each(|(evaluator, (ciphertext, (plain, destination)))| {
            evaluator.multiply_plain(ciphertext, plain, destination)
        });
    }

    pub fn multiply_plain_new(&self, ciphertext: &RnspCiphertext, plain: &RnspPlaintext) -> RnspCiphertext {
        assert_eq!(self.components.len(), ciphertext.components.len());
        assert_eq!(self.components.len(), plain.components.len());
        let components = self.components.iter().zip(ciphertext.components.iter().zip(plain.components.iter())).map(|(evaluator, (ciphertext, plain))| {
            evaluator.multiply_plain_new(ciphertext, plain)
        }).collect();
        RnspCiphertext::from_raw_parts(components)
    }

}