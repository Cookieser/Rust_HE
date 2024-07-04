
/**
Provides an interface to all necessary arithmetic of the number structure that specializes a DWTHandler.
*/
pub trait Arithmetic: Clone {

    type Value;
    type Root;
    type Scalar;

    fn add(&self, a: &Self::Value, b: &Self::Value) -> Self::Value;
    fn sub(&self, a: &Self::Value, b: &Self::Value) -> Self::Value;
    fn mul_root(&self, a: &Self::Value, r: &Self::Root) -> Self::Value;
    fn mul_scalar(&self, a: &Self::Value, s: &Self::Scalar) -> Self::Value;
    // fn mul_root_scalar(&self, a: &Self::RootType, b: &Self::ScalarType) -> Self::RootType;
    fn guard(&self, a: &Self::Value) -> Self::Value;

}



/**
Provides an interface that performs the fast discrete weighted transform (DWT) and its inverse that are used to
accelerate polynomial multiplications, batch multiple messages into a single plaintext polynomial. This class
template is specialized with integer modular arithmetic for DWT over integer quotient rings, and is used in
polynomial multiplications and BatchEncoder. It is also specialized with double-precision complex arithmetic for
DWT over the complex field, which is used in CKKSEncoder.

@par The discrete weighted transform (DWT) is a variantion on the discrete Fourier transform (DFT) over
arbitrary rings involving weighing the input before transforming it by multiplying element-wise by a weight
vector, then weighing the output by another vector. The DWT can be used to perform negacyclic convolution on
vectors just like how the DFT can be used to perform cyclic convolution. The DFT of size n requires a primitive
n-th root of unity, while the DWT for negacyclic convolution requires a primitive 2n-th root of unity, \psi.
In the forward DWT, the input is multiplied element-wise with an incrementing power of \psi, the forward DFT
transform uses the 2n-th primitve root of unity \psi^2, and the output is not weighed. In the backward DWT, the
input is not weighed, the backward DFT transform uses the 2n-th primitve root of unity \psi^{-2}, and the output
is multiplied element-wise with an incrementing power of \psi^{-1}.

@par A fast Fourier transform is an algorithm that computes the DFT or its inverse. The Cooley-Tukey FFT reduces
the complexity of the DFT from O(n^2) to O(n\log{n}). The DFT can be interpretted as evaluating an (n-1)-degree
polynomial at incrementing powers of a primitive n-th root of unity, which can be accelerated by FFT algorithms.
The DWT evaluates incrementing odd powers of a primitive 2n-th root of unity, and can also be accelerated by
FFT-like algorithms implemented in this class.

@par Algorithms implemented in this class are based on algorithms 1 and 2 in the paper by Patrick Longa and
Michael Naehrig (https://eprint.iacr.org/2016/504.pdf) with three modifications. First, we generalize in this
class the algorithms to DWT over arbitrary rings. Second, the powers of \psi^{-1} used by the IDWT are stored
in a scrambled order (in contrast to bit-reversed order in paper) to create coalesced memory accesses. Third,
the multiplication with 1/n in the IDWT is merged to the last iteration, saving n/2 multiplications. Last, we
unroll the loops to create coalesced memory accesses to input and output vectors. In earlier versions of SEAL,
the mutiplication with 1/n is done by merging a multiplication of 1/2 in all interations, which is slower than
the current method on CPUs but more efficient on some hardware architectures.

@par The order in which the powers of \psi^{-1} used by the IDWT are stored is unnatural but efficient:
the i-th slot stores the (reverse_bits(i - 1, log_n) + 1)-th power of \psi^{-1}.
*/
#[derive(Clone)]
pub struct DWTHandler<ArithmeticType: Arithmetic> {
    arithmetic: ArithmeticType
}

impl<ArithmeticType: Arithmetic> DWTHandler<ArithmeticType> {

    pub fn new(num_struct: &ArithmeticType) -> Self {
        Self {arithmetic: num_struct.clone()}
    }

    pub fn transform_to_rev(
        &self, 
        values: &mut [ArithmeticType::Value], 
        log_n: usize, 
        roots: &[ArithmeticType::Root],
        scalar: Option<&ArithmeticType::Scalar>
    ) {
        let n = 1 << log_n;
        for layer in 0..log_n {
            let m = 1 << layer; let gap = n >> (1 + layer);
            let mut offset = 0;
            roots[m..2*m].iter().enumerate().for_each(|(_i, r)| {
                let (left, right) = values[offset..offset + 2 * gap].split_at_mut(gap);
                for (x, y) in left.iter_mut().zip(right.iter_mut()) {
                    let u = self.arithmetic.guard(x);
                    let v = self.arithmetic.mul_root(y, r);
                    *x = self.arithmetic.add(&u, &v);
                    *y = self.arithmetic.sub(&u, &v);
                }
                offset += gap << 1;
            });
        }
        if let Some(scalar) = scalar {
            for value in values.iter_mut() {
                *value = self.arithmetic.mul_scalar(value, scalar);
            }
        }
    }

    pub fn transform_from_rev(
        &self, 
        values: &mut [ArithmeticType::Value], 
        log_n: usize, 
        roots: &[ArithmeticType::Root],
        scalar: Option<&ArithmeticType::Scalar>
    ) {
        let n = 1 << log_n;
        for layer in 0..log_n {
            let gap = 1 << layer; let m = n >> (1 + layer);
            let mut offset = 0;
            roots[n-2*m+1 .. n-m+1].iter().enumerate().for_each(|(_i, r)| {
                let (left, right) = values[offset..offset + 2 * gap].split_at_mut(gap);
                for (x, y) in left.iter_mut().zip(right.iter_mut()) {
                    let u = self.arithmetic.guard(&self.arithmetic.add(x, y));
                    let v = self.arithmetic.sub(x, y);
                    *x = u;
                    *y = self.arithmetic.mul_root(&v, r);
                }
                offset += gap << 1;
            });
        }
        if let Some(scalar) = scalar {
            for value in values.iter_mut() {
                *value = self.arithmetic.mul_scalar(&*value, scalar);
            }
        }
    }

}

impl<ArithmeticType> Default for DWTHandler<ArithmeticType>
where
    ArithmeticType: Arithmetic + Default
{
    fn default() -> Self {
        Self { arithmetic: Default::default() }
    }
}