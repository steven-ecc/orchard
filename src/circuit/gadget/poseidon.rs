//! Gadget and chips for the Poseidon algebraic hash function.

use std::fmt;

use halo2::{
    circuit::{Chip, Layouter},
    plonk::Error,
};

mod pow5t3;
pub use pow5t3::{Pow5T3Chip, Pow5T3Config};

use crate::primitives::poseidon::{Spec, State};

/// The set of circuit instructions required to use the Poseidon permutation.
pub trait PoseidonInstructions<S: Spec<Self::Field, T, RATE>, const T: usize, const RATE: usize>:
    Chip
{
    /// Variable representing the word over which the Poseidon permutation operates.
    type Word: fmt::Debug;

    /// Applies the Poseidon permutation to the given state.
    fn permute(
        layouter: &mut impl Layouter<Self>,
        initial_state: &State<Self::Word, T>,
    ) -> Result<State<Self::Word, T>, Error>;
}
