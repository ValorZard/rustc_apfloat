///! Fuzzing "ops" are a small set of floating-point operations (available both
/// natively and via `llvm::APFloat`/`rustc_apfloat`), represented in code as a
/// generic `FuzzOp` `enum` (with each variant also carrying that op's inputs),
/// with a straight-forward binary serialization (for fuzzing to operate on),
/// and a defined ABI (which Rust code can use to call into the C++ wrapper).
///
/// This file contains the definitions used to generate both Rust and C++ code.

// HACK(eddyb) newtypes to make it easy to tell apart Rust vs C++ specifics.
struct Rust<T>(T);

use self::OpKind::*;
enum OpKind {
    Unary(char),
    Binary(char),
    Ternary(Rust<&'static str>),

    // HACK(eddyb) all other ops have floating-point inputs *and* outputs, so
    // the easiest way to fuzz conversions from/to other types, even if it won't
    // cover *all possible* inputs, is to do a round-trip through the other type.
    Roundtrip(Type),
}

enum Type {
    SInt(usize),
    UInt(usize),
    Float(usize),
}

impl Type {
    fn rust_type(&self) -> String {
        match self {
            Type::SInt(w) => format!("i{w}"),
            Type::UInt(w) => format!("u{w}"),
            Type::Float(w) => format!("f{w}"),
        }
    }
}

impl OpKind {
    fn inputs<'a, T>(&self, all_inputs: &'a [T; 3]) -> &'a [T] {
        match self {
            Unary(_) | Roundtrip(_) => &all_inputs[..1],
            Binary(_) => &all_inputs[..2],
            Ternary(..) => &all_inputs[..3],
        }
    }
}

const OPS: &[(&str, OpKind)] = &[
    // Unary (`F -> F`) ops.
    ("Neg", Unary('-')),
    // Binary (`(F, F) -> F`) ops.
    ("Add", Binary('+')),
    ("Sub", Binary('-')),
    ("Mul", Binary('*')),
    ("Div", Binary('/')),
    ("Rem", Binary('%')),
    // Ternary (`(F, F) -> F`) ops.
    ("MulAdd", Ternary(Rust("mul_add"))),
    // Roundtrip (`F -> T -> F`) ops.
    ("FToI128ToF", Roundtrip(Type::SInt(128))),
    ("FToU128ToF", Roundtrip(Type::UInt(128))),
    ("FToSingleToF", Roundtrip(Type::Float(32))),
    ("FToDoubleToF", Roundtrip(Type::Float(64))),
];

fn all_ops_map_concat(f: impl Fn(usize, &'static str, &OpKind) -> String) -> String {
    OPS.iter()
        .enumerate()
        .map(|(tag, (name, kind))| f(tag, name, kind))
        .collect()
}

pub fn generate_rust() -> String {
    String::new()
        + "
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
enum FuzzOp<T> {"
        + &all_ops_map_concat(|tag, name, kind| {
            format!(
                "
    {name}({input_types}) = {tag},",
                input_types = kind.inputs(&["T", "T", "T"]).join(", ")
            )
        })
        + "
}

impl FuzzOp<()> {
    fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {"
        + &all_ops_map_concat(|tag, name, kind| {
            format!(
                "
            {tag} => FuzzOp::{name}({inputs}),",
                inputs = kind.inputs(&["()", "()", "()"]).join(", ")
            )
        })
        + "
            _ => return None,
        })
    }
}

impl<T> FuzzOp<T> {
    fn tag(self) -> u8 {
        match self {"
        + &all_ops_map_concat(|tag, name, _op| {
            format!(
                "
            FuzzOp::{name}(..) => {tag},",
            )
        })
        + "
        }
    }

    fn map<U>(self, mut f: impl FnMut(T) -> U) -> FuzzOp<U> {
        match self {
" + &all_ops_map_concat(|_tag, name, kind| {
        format!(
            "
            FuzzOp::{name}({inputs}) => FuzzOp::{name}({f_inputs}),",
            inputs = kind.inputs(&["a", "b", "c"]).join(", "),
            f_inputs = kind.inputs(&["f(a)", "f(b)", "f(c)"]).join(", "),
        )
    }) + "
        }
    }
}

impl<HF> FuzzOp<HF>
    where
        HF: num_traits::Float
            + num_traits::AsPrimitive<i128>
            + num_traits::AsPrimitive<u128>
            + num_traits::AsPrimitive<f32>
            + num_traits::AsPrimitive<f64>,
        i128: num_traits::AsPrimitive<HF>,
        u128: num_traits::AsPrimitive<HF>,
        f32: num_traits::AsPrimitive<HF>,
        f64: num_traits::AsPrimitive<HF>,
{
    fn eval_hard(self) -> HF {
        match self {
" + &all_ops_map_concat(|_tag, name, kind| {
        let inputs = kind.inputs(&["a", "b", "c"]);
        let expr = match kind {
            Unary(op) => format!("{op}{}", inputs[0]),
            Binary(op) => format!("{} {op} {}", inputs[0], inputs[1]),
            Ternary(Rust(method)) => {
                format!("{}.{method}({}, {})", inputs[0], inputs[1], inputs[2])
            }
            Roundtrip(ty) => format!(
                "<{ty} as num_traits::AsPrimitive::<HF>>::as_(
                    <HF as num_traits::AsPrimitive::<{ty}>>::as_({}))",
                inputs[0],
                ty = ty.rust_type()
            ),
        };
        format!(
            "
            FuzzOp::{name}({inputs}) => {expr},",
            inputs = inputs.join(", "),
        )
    }) + "
        }
    }
}

impl<F> FuzzOp<F>
    where
        F: rustc_apfloat::Float
           + rustc_apfloat::FloatConvert<rustc_apfloat::ieee::Single>
           + rustc_apfloat::FloatConvert<rustc_apfloat::ieee::Double>,
        rustc_apfloat::ieee::Single: rustc_apfloat::FloatConvert<F>,
        rustc_apfloat::ieee::Double: rustc_apfloat::FloatConvert<F>,
{
    fn eval_rs_apf(self) -> F {
        match self {
" + &all_ops_map_concat(|_tag, name, kind| {
        let inputs = kind.inputs(&["a", "b", "c"]);
        let expr = match kind {
            Unary(op) => format!("{op}{}", inputs[0]),
            Binary(op) => format!("({} {op} {}).value", inputs[0], inputs[1]),
            Ternary(Rust(method)) => {
                format!("{}.{method}({}).value", inputs[0], inputs[1..].join(", "))
            }
            Roundtrip(ty @ (Type::SInt(_) | Type::UInt(_))) => {
                let (w, i_or_u) = match ty {
                    Type::SInt(w) => (w, "i"),
                    Type::UInt(w) => (w, "u"),
                    Type::Float(_) => unreachable!(),
                };
                format!(
                    "F::from_{i_or_u}128({}.to_{i_or_u}128({w}).value).value",
                    inputs[0],
                )
            }
            Roundtrip(Type::Float(w)) => {
                let rs_apf_type = match w {
                    32 => "rustc_apfloat::ieee::Single",
                    64 => "rustc_apfloat::ieee::Double",
                    _ => unreachable!(),
                };
                format!(
                    "rustc_apfloat::FloatConvert
                        ::convert(rustc_apfloat::FloatConvert::<{rs_apf_type}>
                            ::convert({}, &mut false).value, &mut false).value",
                    inputs[0],
                )
            }
        };
        format!(
            "
            FuzzOp::{name}({inputs}) => {expr},",
            inputs = inputs.join(", "),
        )
    }) + "
        }
    }
}"
}
