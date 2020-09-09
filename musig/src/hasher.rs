use crate::encoder::Encoder;
use blake2::{Blake2b, Digest as Blake2Digest};
use franklin_crypto::eddsa::PublicKey;
use franklin_crypto::jubjub::edwards::Point;
use franklin_crypto::jubjub::{JubjubEngine, Unknown};
use franklin_crypto::rescue::RescueEngine;
use franklin_crypto::util::rescue_hash_to_scalar;
use sha2::{Digest, Sha256};
use std::marker::PhantomData;
pub struct Hasher<E: JubjubEngine> {
    marker: PhantomData<E>,
}

impl<E: JubjubEngine> Hasher<E> {
    // H_agg(L, X_i)
    pub fn hash_aggregated(pubkeys: &[PublicKey<E>], position: usize) -> Vec<u8> {
        // sha256 produces 32bytes output we use blake2b instead
        let encoded_data = Encoder::encode_aggregated_data(pubkeys, position);

        let mut blake2b = Blake2b::new();
        blake2b.update(encoded_data);
        let result = blake2b.finalize();

        assert_eq!(result.len(), 64);

        result.to_vec()
    }

    // H_comm(R_i)
    pub fn hash_commitment(commitment: &Point<E, Unknown>) -> Vec<u8> {
        Sha256::digest(&Encoder::encode_commitment_data(commitment)).to_vec()
    }

    // H_sig(X', R, m)
    pub fn hash_signature_data<R: JubjubEngine + RescueEngine>(
        aggregated_pubkey: &PublicKey<E>,
        aggregated_commitment: &Point<E, Unknown>,
        message: &[u8],
        params: &<R as RescueEngine>::Params,
    ) -> R::Fs {
        let (a, b) =
            Encoder::encode_signature_data(&aggregated_pubkey, &aggregated_commitment, message);

        rescue_hash_to_scalar::<R>(&[], &a, &b, params)
    }
}
