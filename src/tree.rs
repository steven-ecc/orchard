use rand::RngCore;

/// The root of an Orchard commitment tree.
#[derive(Clone, Debug)]
pub struct Anchor;

#[derive(Debug)]
pub struct MerklePath;

impl MerklePath {
    /// Generates a dummy Merkle path for use in dummy spent notes.
    pub(crate) fn dummy(rng: &mut impl RngCore) -> Self {
        let pos = 0;
        todo!()
    }
}
