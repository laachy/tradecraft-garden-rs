pub mod tcg {
	use crate::types::*;
	include!(concat!(env!("OUT_DIR"), "/tcg_bindings.rs"));
}

