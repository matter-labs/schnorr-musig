use franklin_crypto::eddsa::PublicKey;
use franklin_crypto::jubjub::{JubjubEngine,Unknown};
use franklin_crypto::jubjub::edwards::Point;
use franklin_crypto::util::rescue_hash_to_scalar;
use franklin_crypto::rescue::RescueEngine;
use sha2::{Sha256, Digest};
use std::marker::PhantomData;
use crate::encoder::Encoder;
pub struct Hasher<E: JubjubEngine>{
    marker: PhantomData<E>
}

impl<E: JubjubEngine> Hasher<E>{
    // H_agg(L, X_i)
    pub fn hash_aggregated(pubkeys: &[PublicKey<E>], position: usize) -> Vec<u8> {        
        Sha256::digest(
            &Encoder::encode_aggregated_data(pubkeys, position)
        ).to_vec()
    }
    
    // H_comm(R_i)
    pub fn hash_commitment(commitment: &Point<E, Unknown>) -> Vec<u8>{
        Sha256::digest(
            &Encoder::encode_commitment_data(commitment)
        ).to_vec()
    }

    // H_sig(X', R, m)
    pub fn hash_signature_data<R: JubjubEngine + RescueEngine>(
        aggregated_pubkey: &PublicKey<E>,
        aggregated_commitment: &Point<E, Unknown>,
        message: &[u8],
        params: &<R as RescueEngine>::Params,
    ) -> R::Fs {

        let (a, b) = Encoder::encode_signature_data(
            &aggregated_pubkey, 
            &aggregated_commitment, 
            message
        );

        rescue_hash_to_scalar::<R>(&[], &a, &b, params)
    }
}