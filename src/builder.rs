//! Logic for building Orchard components of transactions.

use std::iter;

use ff::Field;
use nonempty::NonEmpty;
use pasta_curves::pallas;
use rand::RngCore;

use crate::{
    bundle::{Action, Authorization, Authorized, Bundle, Flags},
    circuit::{Circuit, Proof, ProvingKey},
    keys::{
        FullViewingKey, OutgoingViewingKey, SpendAuthorizingKey, SpendValidatingKey, SpendingKey,
    },
    primitives::redpallas::{self, Binding, SpendAuth},
    tree::{Anchor, MerklePath},
    value::{self, NoteValue, ValueCommitTrapdoor, ValueCommitment, ValueSum},
    Address, EncryptedNote, Note,
};

const MIN_ACTIONS: usize = 2;

#[derive(Debug)]
pub enum Error {
    MissingSignatures,
    Proof(halo2::plonk::Error),
    ValueSum(value::OverflowError),
}

impl From<halo2::plonk::Error> for Error {
    fn from(e: halo2::plonk::Error) -> Self {
        Error::Proof(e)
    }
}

impl From<value::OverflowError> for Error {
    fn from(e: value::OverflowError) -> Self {
        Error::ValueSum(e)
    }
}

/// Information about a specific note to be spent in an [`Action`].
#[derive(Debug)]
struct SpendInfo {
    fvk: FullViewingKey,
    note: Note,
    merkle_path: MerklePath,
}

impl SpendInfo {
    /// Defined in [Zcash Protocol Spec § 4.8.3: Dummy Notes (Orchard)][orcharddummynotes].
    ///
    /// [orcharddummynotes]: https://zips.z.cash/protocol/nu5.pdf#orcharddummynotes
    fn dummy(rng: &mut impl RngCore) -> Self {
        let (fvk, note) = Note::dummy(rng, None);
        let merkle_path = MerklePath::dummy(rng);

        SpendInfo {
            fvk,
            note,
            merkle_path,
        }
    }
}

/// Information about a specific recipient to receive funds in an [`Action`].
#[derive(Debug)]
struct RecipientInfo {
    ovk: Option<OutgoingViewingKey>,
    recipient: Address,
    value: NoteValue,
    memo: Option<()>,
}

impl RecipientInfo {
    /// Defined in [Zcash Protocol Spec § 4.8.3: Dummy Notes (Orchard)][orcharddummynotes].
    ///
    /// [orcharddummynotes]: https://zips.z.cash/protocol/nu5.pdf#orcharddummynotes
    fn dummy(rng: &mut impl RngCore) -> Self {
        let fvk: FullViewingKey = (&SpendingKey::random(rng)).into();
        let recipient = fvk.default_address();

        RecipientInfo {
            ovk: None,
            recipient,
            value: NoteValue::default(),
            memo: None,
        }
    }
}

/// Information about a specific [`Action`] we plan to build.
#[derive(Debug)]
struct ActionInfo {
    spend: SpendInfo,
    output: RecipientInfo,
    rcv: ValueCommitTrapdoor,
}

impl ActionInfo {
    fn new(spend: SpendInfo, output: RecipientInfo, rng: impl RngCore) -> Self {
        ActionInfo {
            spend,
            output,
            rcv: ValueCommitTrapdoor::random(rng),
        }
    }

    /// Returns the value sum for this action.
    fn value_sum(&self) -> Result<ValueSum, value::OverflowError> {
        self.spend.note.value() - self.output.value
    }

    /// Builds the action.
    ///
    /// Defined in [Zcash Protocol Spec § 4.7.3: Sending Notes (Orchard)][orchardsend].
    ///
    /// [orchardsend]: https://zips.z.cash/protocol/nu5.pdf#orchardsend
    fn build(self, mut rng: impl RngCore) -> (Action<SpendValidatingKey>, Circuit) {
        let v_net = self.value_sum().expect("already checked this");
        let cv_net = ValueCommitment::derive(v_net, self.rcv);

        let nf_old = self.spend.note.nullifier(&self.spend.fvk);
        let ak: SpendValidatingKey = self.spend.fvk.into();
        let alpha = pallas::Scalar::random(&mut rng);
        let rk = ak.randomize(&alpha);

        let note = Note::new(
            self.output.recipient,
            self.output.value,
            nf_old.clone(),
            rng,
        );
        let cm_new = note.commitment();

        // TODO: Note encryption
        let encrypted_note = EncryptedNote;

        (
            Action::from_parts(nf_old, rk, cm_new, encrypted_note, cv_net, ak),
            Circuit {},
        )
    }
}

/// A builder that constructs a [`Bundle`] from a set of notes to be spent, and recipients
/// to receive funds.
pub struct Builder {
    spends: Vec<SpendInfo>,
    recipients: Vec<RecipientInfo>,
    flags: Flags,
    anchor: Anchor,
}

impl Builder {
    pub fn new(flags: Flags, anchor: Anchor) -> Self {
        Builder {
            spends: vec![],
            recipients: vec![],
            flags,
            anchor,
        }
    }

    /// Adds a note to be spent in this transaction.
    ///
    /// Returns an error if the given Merkle path does not have the required anchor for
    /// the given note.
    pub fn add_spend(
        &mut self,
        fvk: FullViewingKey,
        note: Note,
        merkle_path: MerklePath,
    ) -> Result<(), &'static str> {
        // Consistency check: all anchors must be equal.
        let cm = note.commitment();
        // TODO: Once we have tree logic.
        // let path_root: bls12_381::Scalar = merkle_path.root(cmu).into();
        // if path_root != anchor {
        //     return Err(Error::AnchorMismatch);
        // }

        self.spends.push(SpendInfo {
            fvk,
            note,
            merkle_path,
        });

        Ok(())
    }

    /// Adds an address which will receive funds in this transaction.
    pub fn add_recipient(
        &mut self,
        ovk: Option<OutgoingViewingKey>,
        recipient: Address,
        value: NoteValue,
        memo: Option<()>,
    ) {
        self.recipients.push(RecipientInfo {
            ovk,
            recipient,
            value,
            memo,
        });
    }

    /// Builds a bundle containing the given spent notes and recipients.
    ///
    /// This API assumes that none of the notes being spent are controlled by (threshold)
    /// multisignatures, and immediately constructs the bundle proof.
    fn build(
        mut self,
        mut rng: impl RngCore,
        pk: &ProvingKey,
    ) -> Result<Bundle<Unauthorized>, Error> {
        // Pair up the spends and recipients, extending with dummy values as necessary.
        //
        // TODO: Do we want to shuffle the order like we do for Sapling? And if we do, do
        // we need the extra logic for mapping the user-provided input order to the
        // shuffled order?
        let pre_actions: Vec<_> = {
            let num_spends = self.spends.len();
            let num_recipients = self.recipients.len();
            let num_actions = [num_spends, num_recipients, MIN_ACTIONS]
                .iter()
                .max()
                .cloned()
                .unwrap();

            self.spends.extend(
                iter::repeat_with(|| SpendInfo::dummy(&mut rng)).take(num_actions - num_spends),
            );
            self.recipients.extend(
                iter::repeat_with(|| RecipientInfo::dummy(&mut rng))
                    .take(num_actions - num_recipients),
            );

            self.spends
                .into_iter()
                .zip(self.recipients.into_iter())
                .map(|(spend, recipient)| ActionInfo::new(spend, recipient, &mut rng))
                .collect()
        };

        // Move some things out of self that we will need.
        let flags = self.flags;
        let anchor = self.anchor;

        // Determine the value balance for this bundle, ensuring it is valid.
        let value_balance: ValueSum = pre_actions
            .iter()
            .fold(Ok(ValueSum::default()), |acc, action| {
                acc? + action.value_sum()?
            })?;

        // Compute the transaction binding signing key.
        let bsk = pre_actions
            .iter()
            .map(|a| &a.rcv)
            .sum::<ValueCommitTrapdoor>()
            .into_bsk();

        // Create the actions.
        let (actions, circuits): (Vec<_>, Vec<_>) =
            pre_actions.into_iter().map(|a| a.build(&mut rng)).unzip();

        // Verify that bsk and bvk are consistent.
        let bvk = (actions.iter().map(|a| a.cv_net()).sum::<ValueCommitment>()
            - ValueCommitment::derive(value_balance, ValueCommitTrapdoor::zero()))
        .into_bvk();
        assert_eq!(redpallas::VerificationKey::from(&bsk), bvk);

        // Create the proof.
        let instances: Vec<_> = actions
            .iter()
            .map(|a| a.to_instance(flags, anchor.clone()))
            .collect();
        let proof = Proof::create(pk, &circuits, &instances)?;

        Ok(Bundle::from_parts(
            NonEmpty::from_vec(actions).unwrap(),
            flags,
            value_balance,
            anchor,
            Unauthorized { proof, bsk },
        ))
    }
}

/// Marker for an unauthorized bundle, with a proof but no signatures.
#[derive(Debug)]
pub struct Unauthorized {
    proof: Proof,
    bsk: redpallas::SigningKey<Binding>,
}

impl Authorization for Unauthorized {
    type SpendAuth = SpendValidatingKey;
}

/// Marker for a partially-authorized bundle, in the process of being signed.
#[derive(Debug)]
pub struct PartiallyAuthorized {
    proof: Proof,
    binding_signature: redpallas::Signature<Binding>,
    sighash: [u8; 32],
}

impl Authorization for PartiallyAuthorized {
    type SpendAuth = (Option<redpallas::Signature<SpendAuth>>, SpendValidatingKey);
}

impl Bundle<Unauthorized> {
    /// Loads the sighash into this bundle, preparing it for signing.
    ///
    /// This API ensures that all signatures are created over the same sighash.
    pub fn prepare<R: rand_7::RngCore + rand_7::CryptoRng>(
        self,
        rng: R,
        sighash: [u8; 32],
    ) -> Bundle<PartiallyAuthorized> {
        self.map(
            |_, ak| (None, ak),
            |unauth| PartiallyAuthorized {
                proof: unauth.proof,
                binding_signature: unauth.bsk.sign(rng, &sighash),
                sighash,
            },
        )
    }

    /// Applies signatures to this bundle, in order to authorize it.
    pub fn apply_signatures<R: rand_7::RngCore + rand_7::CryptoRng>(
        self,
        mut rng: R,
        sighash: [u8; 32],
        signing_keys: &[SpendAuthorizingKey],
    ) -> Result<Bundle<Authorized>, Error> {
        signing_keys
            .iter()
            .fold(self.prepare(&mut rng, sighash), |partial, ask| {
                partial.sign(&mut rng, ask)
            })
            .finalize()
    }
}

impl Bundle<PartiallyAuthorized> {
    /// Signs this bundle with the given [`SpendAuthorizingKey`].
    ///
    /// This will apply signatures for all notes controlled by this spending key.
    pub fn sign<R: rand_7::RngCore + rand_7::CryptoRng>(
        self,
        mut rng: R,
        ask: &SpendAuthorizingKey,
    ) -> Self {
        let expected_ak = ask.into();
        self.map(
            |partial, (sig, ak)| {
                (
                    sig.or_else(|| {
                        if ak == expected_ak {
                            Some(ask.sign(&mut rng, &partial.sighash))
                        } else {
                            None
                        }
                    }),
                    ak,
                )
            },
            |partial| partial,
        )
    }

    /// Finalizes this bundle, enabling it to be included in a transaction.
    ///
    /// Returns an error if any signatures are missing.
    pub fn finalize(self) -> Result<Bundle<Authorized>, Error> {
        self.try_map(
            |_, (sig, _)| match sig {
                Some(sig) => Ok(sig),
                None => Err(Error::MissingSignatures),
            },
            |partial| {
                Ok(Authorized {
                    proof: partial.proof,
                    binding_signature: partial.binding_signature,
                })
            },
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn simple_bundle() {}
}
