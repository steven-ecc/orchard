//! Structs related to bundles of Orchard actions.

use nonempty::NonEmpty;

use crate::{
    circuit::{Instance, Proof},
    note::{EncryptedNote, NoteCommitment, Nullifier},
    primitives::redpallas::{self, Binding, SpendAuth},
    tree::Anchor,
    value::{ValueCommitment, ValueSum},
};

/// An action applied to the global ledger.
///
/// Externally, this both creates a note (adding a commitment to the global ledger),
/// and consumes some note created prior to this action (adding a nullifier to the
/// global ledger).
///
/// Internally, this may both consume a note and create a note, or it may do only one of
/// the two. TODO: Determine which is more efficient (circuit size vs bundle size).
#[derive(Debug)]
pub struct Action<T> {
    /// The nullifier of the note being spent.
    nf_old: Nullifier,
    /// The randomized verification key for the note being spent.
    rk: redpallas::VerificationKey<SpendAuth>,
    /// A commitment to the new note being created.
    cm_new: NoteCommitment,
    /// The encrypted output note.
    encrypted_note: EncryptedNote,
    /// A commitment to the net value created or consumed by this action.
    cv_net: ValueCommitment,
    /// The authorization for this action.
    authorization: T,
}

impl<T> Action<T> {
    /// TODO: Decide whether to expose this, or only allow constructing actions that are
    /// not `Action<redpallas::Signature<SpendAuth>>` via the builder.
    pub(crate) fn from_parts(
        nf_old: Nullifier,
        rk: redpallas::VerificationKey<SpendAuth>,
        cm_new: NoteCommitment,
        encrypted_note: EncryptedNote,
        cv_net: ValueCommitment,
        authorization: T,
    ) -> Self {
        Action {
            nf_old,
            rk,
            cm_new,
            encrypted_note,
            cv_net,
            authorization,
        }
    }

    /// Returns the commitment to the net value of this action.
    pub fn cv_net(&self) -> &ValueCommitment {
        &self.cv_net
    }

    pub(crate) fn to_instance(&self, flags: Flags, anchor: Anchor) -> Instance {
        Instance {
            anchor,
            cv_net: self.cv_net.clone(),
            nf_old: self.nf_old.clone(),
            rk: self.rk.clone(),
            cmx: self.cm_new.to_cmx(),
            enable_spend: flags.spends_enabled,
            enable_output: flags.outputs_enabled,
        }
    }

    /// Transitions this action from one authorization state to another.
    pub fn map<P: Authorization<SpendAuth = T>, U>(
        self,
        parent: &P,
        step: impl FnOnce(&P, T) -> U,
    ) -> Action<U> {
        Action {
            nf_old: self.nf_old,
            rk: self.rk,
            cm_new: self.cm_new,
            encrypted_note: self.encrypted_note,
            cv_net: self.cv_net,
            authorization: step(parent, self.authorization),
        }
    }

    /// Transitions this action from one authorization state to another.
    pub fn try_map<P: Authorization<SpendAuth = T>, U, E>(
        self,
        parent: &P,
        step: impl FnOnce(&P, T) -> Result<U, E>,
    ) -> Result<Action<U>, E> {
        Ok(Action {
            nf_old: self.nf_old,
            rk: self.rk,
            cm_new: self.cm_new,
            encrypted_note: self.encrypted_note,
            cv_net: self.cv_net,
            authorization: step(parent, self.authorization)?,
        })
    }
}

/// Orchard-specific flags.
#[derive(Clone, Copy, Debug)]
pub struct Flags {
    spends_enabled: bool,
    outputs_enabled: bool,
}

/// Defines the authorization type of an Orchard bundle.
pub trait Authorization {
    /// The authorization type of an Orchard action.
    type SpendAuth;
}

/// A bundle of actions to be applied to the ledger.
#[derive(Debug)]
pub struct Bundle<T: Authorization> {
    actions: NonEmpty<Action<T::SpendAuth>>,
    flags: Flags,
    value_balance: ValueSum,
    anchor: Anchor,
    authorization: T,
}

impl<T: Authorization> Bundle<T> {
    /// TODO: Decide whether to expose this, or only allow constructing bundles that are
    /// not `Bundle<Authorized>` via the builder.
    pub(crate) fn from_parts(
        actions: NonEmpty<Action<T::SpendAuth>>,
        flags: Flags,
        value_balance: ValueSum,
        anchor: Anchor,
        authorization: T,
    ) -> Self {
        Bundle {
            actions,
            flags,
            value_balance,
            anchor,
            authorization,
        }
    }

    /// Computes a commitment to the effects of this bundle, suitable for inclusion within
    /// a transaction ID.
    pub fn commitment(&self) -> BundleCommitment {
        todo!()
    }

    /// Transitions this bundle from one authorization state to another.
    pub fn map<U: Authorization>(
        self,
        mut spend_auth: impl FnMut(&T, T::SpendAuth) -> U::SpendAuth,
        step: impl FnOnce(T) -> U,
    ) -> Bundle<U> {
        let authorization = self.authorization;
        Bundle {
            actions: self.actions.map(|a| a.map(&authorization, &mut spend_auth)),
            flags: self.flags,
            value_balance: self.value_balance,
            anchor: self.anchor,
            authorization: step(authorization),
        }
    }

    /// Transitions this bundle from one authorization state to another.
    pub fn try_map<U: Authorization, E>(
        self,
        mut spend_auth: impl FnMut(&T, T::SpendAuth) -> Result<U::SpendAuth, E>,
        step: impl FnOnce(T) -> Result<U, E>,
    ) -> Result<Bundle<U>, E> {
        let authorization = self.authorization;
        let new_actions = self
            .actions
            .into_iter()
            .map(|a| a.try_map(&authorization, &mut spend_auth))
            .collect::<Result<Vec<_>, E>>()?;

        Ok(Bundle {
            actions: NonEmpty::from_vec(new_actions).unwrap(),
            flags: self.flags,
            value_balance: self.value_balance,
            anchor: self.anchor,
            authorization: step(authorization)?,
        })
    }
}

/// Authorizing data for a bundle of actions, ready to be committed to the ledger.
#[derive(Debug)]
pub struct Authorized {
    pub(crate) proof: Proof,
    pub(crate) binding_signature: redpallas::Signature<Binding>,
}

impl Authorization for Authorized {
    type SpendAuth = redpallas::Signature<SpendAuth>;
}

impl Bundle<Authorized> {
    /// Computes a commitment to the authorizing data within for this bundle.
    ///
    /// This together with `Bundle::commitment` bind the entire bundle.
    pub fn authorizing_commitment(&self) -> BundleAuthorizingCommitment {
        todo!()
    }
}

/// A commitment to a bundle of actions.
///
/// This commitment is non-malleable, in the sense that a bundle's commitment will only
/// change if the effects of the bundle are altered.
#[derive(Debug)]
pub struct BundleCommitment;

/// A commitment to the authorizing data within a bundle of actions.
#[derive(Debug)]
pub struct BundleAuthorizingCommitment;
