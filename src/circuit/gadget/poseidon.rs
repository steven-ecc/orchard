//! Gadget and chips for the Poseidon algebraic hash function.

use std::fmt;

use halo2::{
    circuit::{Chip, Layouter},
    plonk::Error,
};

/// The set of circuit instructions required to use the [`Poseidon`] gadget.
pub trait PoseidonInstructions: Chip {
    /// Variable representing the state over which the Poseidon permutation operates.
    type State: fmt::Debug;

    /// Applies the Poseidon permutation to the given state.
    fn permute(
        layouter: &mut impl Layouter<Self>,
        initial_state: &Self::State,
    ) -> Result<Self::State, Error>;
}
