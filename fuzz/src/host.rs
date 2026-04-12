use std::fmt;

use rustc_apfloat::{Round, Status, StatusAnd};

/// Abstraction over host float operations. If the requested rounding mode is not supported,
/// return `None`.
pub trait HostFloat: Copy + Sized + fmt::Debug {
    type UInt: Copy + fmt::LowerHex;
    fn from_bits(bits: Self::UInt) -> Self;
    fn to_bits(self) -> Self::UInt;
    fn neg(self) -> Self;
    fn add_r(self, other: Self, rm: Round) -> Option<StatusAnd<Self>>;
    fn sub_r(self, other: Self, rm: Round) -> Option<StatusAnd<Self>>;
    fn mul_r(self, other: Self, rm: Round) -> Option<StatusAnd<Self>>;
    fn div_r(self, other: Self, rm: Round) -> Option<StatusAnd<Self>>;
    fn rem(self, other: Self) -> Self;
    fn mul_add_r(self, mul: Self, add: Self, rm: Round) -> Option<StatusAnd<Self>>;
    fn to_i128_r(self, rm: Round) -> Option<StatusAnd<i128>>;
    fn from_i128_r(x: i128, rm: Round) -> Option<StatusAnd<Self>>;
    fn to_u128_r(self, rm: Round) -> Option<StatusAnd<u128>>;
    fn from_u128_r(x: u128, rm: Round) -> Option<StatusAnd<Self>>;
    fn to_double_r(self, rm: Round) -> Option<StatusAnd<f64>>;
    fn from_double_r(x: f64, rm: Round) -> Option<StatusAnd<Self>>;
    fn to_single_r(self, rm: Round) -> Option<StatusAnd<f32>>;
    fn from_single_r(x: f32, rm: Round) -> Option<StatusAnd<Self>>;
}

macro_rules! impl_host_float {
    ($ty:ty, $ity:ty) => {
        impl HostFloat for $ty {
            type UInt = $ity;
            fn from_bits(bits: Self::UInt) -> Self {
                Self::from_bits(bits)
            }
            fn to_bits(self) -> Self::UInt {
                self.to_bits()
            }
            fn neg(self) -> Self {
                -self
            }
            fn add_r(self, other: Self, rm: Round) -> Option<StatusAnd<Self>> {
                match rm {
                    Round::NearestTiesToEven => Some(Status::OK.and(self + other)),
                    _ => None,
                }
            }
            fn sub_r(self, other: Self, rm: Round) -> Option<StatusAnd<Self>> {
                match rm {
                    Round::NearestTiesToEven => Some(Status::OK.and(self - other)),
                    _ => None,
                }
            }
            fn mul_r(self, other: Self, rm: Round) -> Option<StatusAnd<Self>> {
                match rm {
                    Round::NearestTiesToEven => Some(Status::OK.and(self * other)),
                    _ => None,
                }
            }
            fn div_r(self, other: Self, rm: Round) -> Option<StatusAnd<Self>> {
                match rm {
                    Round::NearestTiesToEven => Some(Status::OK.and(self / other)),
                    _ => None,
                }
            }
            fn rem(self, other: Self) -> Self {
                self % other
            }
            fn mul_add_r(self, mul: Self, add: Self, rm: Round) -> Option<StatusAnd<Self>> {
                match rm {
                    Round::NearestTiesToEven => Some(Status::OK.and(self.mul_add(mul, add))),
                    _ => None,
                }
            }

            /* float->int casts are toward zero */
            fn to_i128_r(self, rm: Round) -> Option<StatusAnd<i128>> {
                match rm {
                    Round::TowardZero => Some(Status::OK.and(self as i128)),
                    _ => None,
                }
            }
            fn to_u128_r(self, rm: Round) -> Option<StatusAnd<u128>> {
                match rm {
                    Round::TowardZero => Some(Status::OK.and(self as u128)),
                    _ => None,
                }
            }

            fn from_i128_r(x: i128, rm: Round) -> Option<StatusAnd<Self>> {
                match rm {
                    Round::NearestTiesToEven => Some(Status::OK.and(x as Self)),
                    _ => None,
                }
            }
            fn from_u128_r(x: u128, rm: Round) -> Option<StatusAnd<Self>> {
                match rm {
                    Round::NearestTiesToEven => Some(Status::OK.and(x as Self)),
                    _ => None,
                }
            }
            fn to_double_r(self, rm: Round) -> Option<StatusAnd<f64>> {
                match rm {
                    Round::NearestTiesToEven => Some(Status::OK.and(self as f64)),
                    _ => None,
                }
            }
            fn from_double_r(x: f64, rm: Round) -> Option<StatusAnd<Self>> {
                match rm {
                    Round::NearestTiesToEven => Some(Status::OK.and(x as Self)),
                    _ => None,
                }
            }
            fn to_single_r(self, rm: Round) -> Option<StatusAnd<f32>> {
                match rm {
                    Round::NearestTiesToEven => Some(Status::OK.and(self as f32)),
                    _ => None,
                }
            }
            fn from_single_r(x: f32, rm: Round) -> Option<StatusAnd<Self>> {
                match rm {
                    Round::NearestTiesToEven => Some(Status::OK.and(x as Self)),
                    _ => None,
                }
            }
        }
    };
}

#[cfg(target_has_reliable_f16)]
impl_host_float!(f16, u16);
impl_host_float!(f32, u32);
impl_host_float!(f64, u64);
#[cfg(target_has_reliable_f128)]
impl_host_float!(f128, u128);
