//! Fuzzing "ops" are a small set of floating-point operations (available both
//! natively and via `llvm::APFloat`/`rustc_apfloat`), represented in code as a
//! generic `FuzzOp` `enum` (with each variant also carrying that op's inputs),
//! with a straight-forward binary serialization (for fuzzing to operate on),
//! and a defined ABI (which Rust code can use to call into the C++ wrapper).

/// A testable operation, which can be encoded as a byte.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Op {
    Neg = 0,
    Add = 1,
    Sub = 2,
    Mul = 3,
    Div = 4,
    Rem = 5,
    MulAdd = 6,
    FToI128ToF = 7,
    FToU128ToF = 8,
    FToSingleToF = 9,
    FToDoubleToF = 10,
}

impl Op {
    pub const ALL: &[Self] = &[
        Self::Neg,
        Self::Add,
        Self::Sub,
        Self::Mul,
        Self::Div,
        Self::Rem,
        Self::MulAdd,
        Self::FToI128ToF,
        Self::FToU128ToF,
        Self::FToSingleToF,
        Self::FToDoubleToF,
    ];

    pub fn from_u8(tag: u8) -> Option<Self> {
        let v = match tag {
            x if x == Self::Neg.to_u8() => Self::Neg,
            x if x == Self::Add.to_u8() => Self::Add,
            x if x == Self::Sub.to_u8() => Self::Sub,
            x if x == Self::Mul.to_u8() => Self::Mul,
            x if x == Self::Div.to_u8() => Self::Div,
            x if x == Self::Rem.to_u8() => Self::Rem,
            x if x == Self::MulAdd.to_u8() => Self::MulAdd,
            x if x == Self::FToI128ToF.to_u8() => Self::FToI128ToF,
            x if x == Self::FToU128ToF.to_u8() => Self::FToU128ToF,
            x if x == Self::FToSingleToF.to_u8() => Self::FToSingleToF,
            x if x == Self::FToDoubleToF.to_u8() => Self::FToDoubleToF,
            _ => return None,
        };
        Some(v)
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn airity(self) -> Arity {
        match self {
            Op::Neg => Arity::Unary,
            Op::Add => Arity::Binary,
            Op::Sub => Arity::Binary,
            Op::Mul => Arity::Binary,
            Op::Div => Arity::Binary,
            Op::Rem => Arity::Binary,
            Op::MulAdd => Arity::Ternary,
            Op::FToI128ToF => Arity::Unary,
            Op::FToU128ToF => Arity::Unary,
            Op::FToSingleToF => Arity::Unary,
            Op::FToDoubleToF => Arity::Unary,
        }
    }
}

/// Number of inputs to an operation.
#[derive(Copy, Clone, Debug)]
pub enum Arity {
    Unary = 1,
    Binary = 2,
    Ternary = 3,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Check that `ALL` actually contains all variants.
    #[test]
    fn op_all_list() {
        let all_computed = (0u8..)
            .map(Op::from_u8)
            .take_while(|op| op.is_some())
            .filter_map(|x| x)
            .collect::<Vec<_>>();
        assert_eq!(all_computed, Op::ALL);
    }
}
