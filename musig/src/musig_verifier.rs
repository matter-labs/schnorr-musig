use crate::musig_hasher::MusigHasher;
use franklin_crypto::eddsa::{PublicKey, Signature};
use franklin_crypto::jubjub::{FixedGenerators, JubjubEngine};
use std::marker::PhantomData;

/// This struct allows to verify musig
pub struct MusigVerifier<E: JubjubEngine, H: MusigHasher<E>> {
    hasher: H,
    generator: FixedGenerators,
    phantom: PhantomData<E>,
}

impl<E: JubjubEngine, H: MusigHasher<E>> MusigVerifier<E, H> {
    /// Creates new verifier
    ///
    /// # Arguments
    /// * `hasher` - trait object responsible for hashing. Only message hash is used here. Should be the same as in MusigSession.
    /// * `generator` - Generator used for elliptic curves operations. Should be the same as in MusigSession.
    pub fn new(hasher: H, generator: FixedGenerators) -> Self {
        MusigVerifier {
            hasher,
            generator,
            phantom: PhantomData,
        }
    }

    /// Verifies musig.
    ///
    /// Please be aware that upon musig verification one should check that given set of static
    /// public keys indeed gives exactly the same aggregated public key as one passed here.
    pub fn verify_signature(
        &self,
        signature: &Signature<E>,
        msg: &[u8],
        aggregated_public_key: &PublicKey<E>,
        params: &E::Params,
    ) -> bool {
        let msg_hash = self.hasher.message_hash(msg);

        // TODO: Works only with sha256

        aggregated_public_key.verify_musig_sha256(&msg_hash, signature, self.generator, params)
    }
}
