//! Gadget and chips for the Sinsemilla hash function.
use crate::circuit::{
    cores::sinsemilla::{SinsemillaChip, SinsemillaConfig},
    gadgets::ecc::{self, EccInstructions},
};
use halo2::{
    arithmetic::CurveAffine,
    circuit::{Chip, Layouter},
    plonk::Error,
};
use std::fmt;

/// Trait allowing circuit's Sinsemilla HashDomains to be enumerated.
pub trait HashDomains<C: CurveAffine>: Clone + fmt::Debug {}

/// The set of circuit instructions required to use the [`Sinsemilla`](https://zcash.github.io/halo2/design/gadgets/sinsemilla.html) gadget.
pub trait SinsemillaHashInstructions<C: CurveAffine>: Chip<Field = C::Base> {
    /// Witnessed message.
    type Message: Clone + fmt::Debug;
    /// Variable representing the set of HashDomains in the circuit.
    type HashDomains: HashDomains<C>;
    /// Variable representing the output of a hash.
    type Point: Clone + fmt::Debug;

    /// Gets the Q constant for the given domain.
    #[allow(non_snake_case)]
    fn get_Q(
        layouter: &mut impl Layouter<Self>,
        domain: &Self::HashDomains,
    ) -> Result<Self::Point, Error>;

    /// Witnesses a message in the form of a bitstring.
    fn witness_message(
        layouter: &mut impl Layouter<Self>,
        message: Vec<bool>,
    ) -> Result<Self::Message, Error>;

    /// Hashes a message to an ECC curve point.
    #[allow(non_snake_case)]
    fn hash_to_point(
        layouter: &mut impl Layouter<Self>,
        Q: &<Ch::Core as EccInstructions<C, Ch>>::Point,
        message: Self::Message,
    ) -> Result<Self::Point, Error>;
}

#[allow(non_snake_case)]
pub struct HashDomain<
    C: CurveAffine,
    SinsemillaChip: SinsemillaHashInstructions<C>,
> {
    Q: SinsemillaChip::Point,
}

impl<
        C: CurveAffine,
        SinsemillaChip: SinsemillaHashInstructions<C>,
    > HashDomain<C>
{
    #[allow(non_snake_case)]
    /// Constructs a new `HashDomain` for the given domain.
    pub fn new(
        mut layouter: impl Layouter<SinsemillaChip>,
        domain: &SinsemillaChip::HashDomains,
    ) -> Result<Self, Error> {
        SinsemillaChip::get_Q(&mut layouter, domain).map(|Q| HashDomain { Q })
    }

    /// $\mathsf{SinsemillaHashToPoint}$ from [§ 5.4.1.9][concretesinsemillahash].
    ///
    /// [concretesinsemillahash]: https://zips.z.cash/protocol/nu5.pdf#concretesinsemillahash
    pub fn hash_to_point(
        &self,
        mut layouter: impl Layouter<SinsemillaChip>,
        message: <SinsemillaChip as SinsemillaHashInstructions<C>>::Message,
    ) -> Result<SinsemillaChip::Point, Error> {
        SinsemillaChip::hash_to_point(&mut layouter, &self.Q, message)
    }
}

