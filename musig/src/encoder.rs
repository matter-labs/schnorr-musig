use bellman::{PrimeField, PrimeFieldRepr};
use franklin_crypto::eddsa::PublicKey;
use franklin_crypto::jubjub::edwards::Point;
use franklin_crypto::jubjub::{JubjubEngine, Unknown};
use std::marker::PhantomData;

// each encoded elements(point, scalar, pubkey) needs to have 32byte size
pub const STANDARD_ENCODING_LENGTH: usize = 32;

pub fn write_point<E: JubjubEngine>(point: &Point<E, Unknown>, dest: &mut Vec<u8>) {
    let (x, _) = point.into_xy();
    let mut x_bytes = [0u8; STANDARD_ENCODING_LENGTH];
    x.into_repr()
        .write_le(&mut x_bytes[..])
        .expect("has serialized pk_x");

    dest.extend_from_slice(&x_bytes);
}

pub struct Encoder<E: JubjubEngine> {
    marker: PhantomData<E>,
}

impl<E: JubjubEngine> Encoder<E> {
    // H_agg(L, X_i)
    pub(crate) fn encode_aggregated_data(pubkeys: &[PublicKey<E>], position: usize) -> Vec<u8> {
        let mut buf = vec![];
        for pubkey in pubkeys {
            write_point(&pubkey.0, &mut buf);
        }
        // append pubkey of actual signer
        write_point(&pubkeys[position].0, &mut buf);

        buf
    }

    // H_comm(R_i)
    pub(crate) fn encode_commitment_data(commitment: &Point<E, Unknown>) -> Vec<u8> {
        let mut buf = vec![];
        write_point(&commitment, &mut buf);

        buf
    }

    // H_sig(X', R, m)
    pub(crate) fn encode_signature_data(
        aggregated_pubkey: &PublicKey<E>,
        aggregated_commitment: &Point<E, Unknown>,
        message: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        let mut buf = vec![];

        let aggregated_pubkey = aggregated_pubkey.0;

        write_point(&aggregated_pubkey, &mut buf);
        write_point(&aggregated_commitment, &mut buf);

        let mut msg_padded: Vec<u8> = message.to_vec();
        msg_padded.resize(STANDARD_ENCODING_LENGTH, 0u8);

        (buf, msg_padded)
    }
}
