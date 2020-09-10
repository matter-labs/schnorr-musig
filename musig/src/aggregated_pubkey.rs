use crate::errors::MusigError;
use crate::hasher::Hasher;
use bellman::{Field, PrimeField};
use franklin_crypto::eddsa::PublicKey;
use franklin_crypto::jubjub::edwards::Point;
use franklin_crypto::jubjub::{JubjubEngine, ToUniform};

pub struct AggregatedPublicKey;

impl AggregatedPublicKey {
    pub(crate) fn compute_from_pubkeys<E: JubjubEngine>(
        pubkeys: &[PublicKey<E>],
        position: usize,
        jubjub_params: &<E as JubjubEngine>::Params,
    ) -> Result<(PublicKey<E>, Vec<E::Fs>), MusigError> {
        if pubkeys.is_empty() {
            return Err(MusigError::InvalidPubkeyLength);
        }

        if position >= pubkeys.len() {
            return Err(MusigError::InvalidParticipantPosition);
        }
        for pubkey in pubkeys {
            // check that pubkey is in correct subgroup
            if pubkey.0.mul(E::Fs::char(), jubjub_params) != Point::zero() {
                return Err(MusigError::InvalidPublicKey);
            }
        }

        // TODO: sort pubkeys
        // L sorted lexicographical order

        // aggregated pubkey and pubkey needs to be equal
        if pubkeys.len() == 1 {
            return Ok((pubkeys[0].clone(), vec![E::Fs::one()]));
        }
        // L = {X_1, X_2, .. X_n}
        let mut a_values = vec![];
        let mut acc = Point::zero();

        // X' = \sum{1<=i<=n}{ a_i * X_i}
        for (i, pubkey) in pubkeys.iter().enumerate() {
            let a_i = E::Fs::to_uniform(&Hasher::hash_aggregated(&pubkeys, i));
            a_values.push(a_i);

            acc = acc.add(&pubkey.0.mul(a_i, jubjub_params), jubjub_params);
        }

        let aggregated_pubkey = PublicKey(acc);

        Ok((aggregated_pubkey, a_values))
    }
}
