//! Gadget and chips for the Poseidon algebraic hash function.

use std::array;
use std::fmt;

use halo2::{
    circuit::{Chip, Layouter},
    plonk::Error,
};

mod pow5t3;
pub use pow5t3::{Pow5T3Chip, Pow5T3Config};

use crate::primitives::poseidon::{ConstantLength, Domain, Spec, Sponge, SpongeState, State};

/// The set of circuit instructions required to use the Poseidon permutation.
pub trait PoseidonInstructions<S: Spec<Self::Field, T, RATE>, const T: usize, const RATE: usize>:
    Chip
{
    /// Variable representing the word over which the Poseidon permutation operates.
    type Word: Copy + fmt::Debug;

    /// Applies the Poseidon permutation to the given state.
    fn permute(
        layouter: &mut impl Layouter<Self>,
        initial_state: &State<Self::Word, T>,
    ) -> Result<State<Self::Word, T>, Error>;
}

/// The set of circuit instructions required to use the [`Duplex`] and [`Hash`] gadgets.
///
/// [`Hash`]: self::Hash
pub trait PoseidonDuplexInstructions<
    S: Spec<Self::Field, T, RATE>,
    const T: usize,
    const RATE: usize,
>: PoseidonInstructions<S, T, RATE>
{
    /// Returns the initial empty state for the given domain.
    fn initial_state(
        layouter: &mut impl Layouter<Self>,
        domain: &impl Domain<Self::Field, S, T, RATE>,
    ) -> Result<State<Self::Word, T>, Error>;

    /// Pads the given input (according to the specified domain) and adds it to the state.
    fn pad_and_add(
        layouter: &mut impl Layouter<Self>,
        domain: &impl Domain<Self::Field, S, T, RATE>,
        initial_state: &State<Self::Word, T>,
        input: &SpongeState<Self::Word, RATE>,
    ) -> Result<State<Self::Word, T>, Error>;

    /// Extracts sponge output from the given state.
    fn get_output(state: &State<Self::Word, T>) -> SpongeState<Self::Word, RATE>;
}

/// A word over which the Poseidon permutation operates.
pub struct Word<
    PoseidonChip: PoseidonInstructions<S, T, RATE>,
    S: Spec<PoseidonChip::Field, T, RATE>,
    const T: usize,
    const RATE: usize,
> {
    inner: PoseidonChip::Word,
}

fn poseidon_duplex<
    PoseidonChip: PoseidonDuplexInstructions<S, T, RATE>,
    S: Spec<PoseidonChip::Field, T, RATE>,
    D: Domain<PoseidonChip::Field, S, T, RATE>,
    const T: usize,
    const RATE: usize,
>(
    mut layouter: impl Layouter<PoseidonChip>,
    domain: &D,
    state: &mut State<PoseidonChip::Word, T>,
    input: &SpongeState<PoseidonChip::Word, RATE>,
) -> Result<SpongeState<PoseidonChip::Word, RATE>, Error> {
    *state = PoseidonChip::pad_and_add(&mut layouter, domain, state, input)?;
    *state = PoseidonChip::permute(&mut layouter, state)?;
    Ok(PoseidonChip::get_output(state))
}

/// A Poseidon duplex sponge.
pub struct Duplex<
    PoseidonChip: PoseidonDuplexInstructions<S, T, RATE>,
    S: Spec<PoseidonChip::Field, T, RATE>,
    D: Domain<PoseidonChip::Field, S, T, RATE>,
    const T: usize,
    const RATE: usize,
> {
    sponge: Sponge<PoseidonChip::Word, RATE>,
    state: State<PoseidonChip::Word, T>,
    domain: D,
}

impl<
        PoseidonChip: PoseidonDuplexInstructions<S, T, RATE>,
        S: Spec<PoseidonChip::Field, T, RATE>,
        D: Domain<PoseidonChip::Field, S, T, RATE>,
        const T: usize,
        const RATE: usize,
    > Duplex<PoseidonChip, S, D, T, RATE>
{
    /// Constructs a new duplex sponge for the given Poseidon specification.
    pub fn new(mut layouter: impl Layouter<PoseidonChip>, domain: D) -> Result<Self, Error> {
        PoseidonChip::initial_state(&mut layouter, &domain).map(|state| Duplex {
            sponge: Sponge::Absorbing([None; RATE]),
            state,
            domain,
        })
    }

    /// Absorbs an element into the sponge.
    pub fn absorb(
        &mut self,
        mut layouter: impl Layouter<PoseidonChip>,
        value: Word<PoseidonChip, S, T, RATE>,
    ) -> Result<(), Error> {
        match self.sponge {
            Sponge::Absorbing(ref mut input) => {
                for entry in input.iter_mut() {
                    if entry.is_none() {
                        *entry = Some(value.inner);
                        return Ok(());
                    }
                }

                // We've already absorbed as many elements as we can
                let _ = poseidon_duplex(
                    layouter.namespace(|| "PoseidonDuplex"),
                    &self.domain,
                    &mut self.state,
                    &input,
                )?;
                self.sponge = Sponge::absorb(value.inner);
            }
            Sponge::Squeezing(_) => {
                // Drop the remaining output elements
                self.sponge = Sponge::absorb(value.inner);
            }
        }

        Ok(())
    }

    /// Squeezes an element from the sponge.
    pub fn squeeze(
        &mut self,
        mut layouter: impl Layouter<PoseidonChip>,
    ) -> Result<Word<PoseidonChip, S, T, RATE>, Error> {
        loop {
            match self.sponge {
                Sponge::Absorbing(ref input) => {
                    self.sponge = Sponge::Squeezing(poseidon_duplex(
                        layouter.namespace(|| "PoseidonDuplex"),
                        &self.domain,
                        &mut self.state,
                        &input,
                    )?);
                }
                Sponge::Squeezing(ref mut output) => {
                    for entry in output.iter_mut() {
                        if let Some(inner) = entry.take() {
                            return Ok(Word { inner });
                        }
                    }

                    // We've already squeezed out all available elements
                    self.sponge = Sponge::Absorbing([None; RATE]);
                }
            }
        }
    }
}

/// A Poseidon hash function, built around a duplex sponge.
pub struct Hash<
    PoseidonChip: PoseidonDuplexInstructions<S, T, RATE>,
    S: Spec<PoseidonChip::Field, T, RATE>,
    D: Domain<PoseidonChip::Field, S, T, RATE>,
    const T: usize,
    const RATE: usize,
> {
    duplex: Duplex<PoseidonChip, S, D, T, RATE>,
}

impl<
        PoseidonChip: PoseidonDuplexInstructions<S, T, RATE>,
        S: Spec<PoseidonChip::Field, T, RATE>,
        D: Domain<PoseidonChip::Field, S, T, RATE>,
        const T: usize,
        const RATE: usize,
    > Hash<PoseidonChip, S, D, T, RATE>
{
    /// Initializes a new hasher.
    pub fn init(layouter: impl Layouter<PoseidonChip>, domain: D) -> Result<Self, Error> {
        Duplex::new(layouter, domain).map(|duplex| Hash { duplex })
    }
}

impl<
        PoseidonChip: PoseidonDuplexInstructions<S, T, RATE>,
        S: Spec<PoseidonChip::Field, T, RATE>,
        const T: usize,
        const RATE: usize,
        const L: usize,
    > Hash<PoseidonChip, S, ConstantLength<L>, T, RATE>
{
    /// Hashes the given input.
    pub fn hash(
        mut self,
        mut layouter: impl Layouter<PoseidonChip>,
        message: [Word<PoseidonChip, S, T, RATE>; L],
    ) -> Result<Word<PoseidonChip, S, T, RATE>, Error> {
        for (i, value) in array::IntoIter::new(message).enumerate() {
            self.duplex
                .absorb(layouter.namespace(|| format!("absorb_{}", i)), value)?;
        }
        self.duplex.squeeze(layouter.namespace(|| "squeeze"))
    }
}
