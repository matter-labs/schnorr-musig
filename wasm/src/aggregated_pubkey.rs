use crate::decoder::{Decoder, STANDARD_ENCODING_LENGTH};
use crate::errors::MusigABIError;
use franklin_crypto::alt_babyjubjub::AltJubjubBn256;
use musig::aggregated_pubkey::AggregatedPublicKey;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct MusigBN256WasmAggregatedPubkey;

#[wasm_bindgen]
impl MusigBN256WasmAggregatedPubkey {
    #[wasm_bindgen]
    pub fn compute(encoded_pubkeys: &[u8]) -> Result<Vec<u8>, JsValue> {
        let jubjub_params = AltJubjubBn256::new();

        let pubkeys = Decoder::decode_pubkey_list(encoded_pubkeys)?;

        let (agg_pubkey, _) =
            AggregatedPublicKey::compute_for_each_party(&pubkeys, &jubjub_params).unwrap();

        let mut encoded_agg_pubkey = vec![0u8; STANDARD_ENCODING_LENGTH];

        agg_pubkey
            .write(&mut encoded_agg_pubkey[..])
            .map_err(|_| MusigABIError::EncodingError)?;

        Ok(encoded_agg_pubkey)
    }
}
