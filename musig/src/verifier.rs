use crate::aggregated_pubkey::AggregatedPublicKey;
use crate::errors::MusigError;
use crate::jubjub::JubJubWrapper;
use bellman::Field;
use franklin_crypto::eddsa::{PublicKey, Signature};
use franklin_crypto::jubjub::edwards::Point;
use franklin_crypto::jubjub::{FixedGenerators, JubjubEngine, Unknown};
use franklin_crypto::rescue::RescueEngine;
use std::marker::PhantomData;
pub struct MuSigVerifier<E: JubjubEngine + RescueEngine> {
    marker: PhantomData<E>,
}

impl<E: JubjubEngine + RescueEngine> MuSigVerifier<E> {
    /// Verifies an aggregated signature according to its public keys.
    pub fn verify(
        message: &[u8],
        pubkeys: &[PublicKey<E>],
        signature: &Signature<E>,
        jubjub_params: &<E as JubjubEngine>::Params,
        generator: FixedGenerators,
        rescue_params: &<E as RescueEngine>::Params,
    ) -> Result<bool, MusigError> {
        let (aggregated_pubkey, _) =
            AggregatedPublicKey::compute_from_pubkeys(pubkeys, jubjub_params)?;

        Ok(aggregated_pubkey.verify_musig_rescue(
            message,
            &signature,
            generator,
            &rescue_params,
            &jubjub_params,
        ))
    }

    pub(crate) fn verify_share(
        signature_share: &E::Fs,
        R_i: &Point<E, Unknown>,
        challenge: &E::Fs,
        a_i: &E::Fs,
        pubkey: &PublicKey<E>,
        jubjub_wrapper: &JubJubWrapper<E>,
    ) -> bool {
        // s_i * G = R_i + (c * a_i) * X_i
        let lhs = jubjub_wrapper.mul_by_generator(*signature_share);
        let mut c_i = challenge.clone();
        c_i.mul_assign(&a_i);
        let rhs = jubjub_wrapper.add(&jubjub_wrapper.mul(&pubkey.0, c_i), &R_i);

        lhs.eq(&rhs)
    }
}
