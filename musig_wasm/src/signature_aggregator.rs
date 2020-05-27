use bellman::pairing::bn256::Bn256;
use franklin_crypto::alt_babyjubjub::fs::Fs;
use franklin_crypto::eddsa::PublicKey;
use musig::musig::MusigSession;
use musig::musig_hasher::DefaultHasher;
use wasm_bindgen::prelude::*;

use crate::wasm_formats::WasmFormats;

/// This struct is responsible for aggregating participants signatures into final musig.
#[wasm_bindgen(js_name = "MusigWasmSignatureAggregator")]
pub struct SignatureAggregator {
    musig: MusigSession<Bn256, DefaultHasher<Bn256>>,
    signatures: Vec<Fs>,
    aggregated_public_key: PublicKey<Bn256>,
}

#[wasm_bindgen(js_class = "MusigWasmSignatureAggregator")]
impl SignatureAggregator {
    pub(crate) fn new(
        musig: MusigSession<Bn256, DefaultHasher<Bn256>>,
        aggregated_public_key: PublicKey<Bn256>,
    ) -> Self {
        SignatureAggregator {
            musig,
            signatures: Vec::new(),
            aggregated_public_key,
        }
    }

    /// Adds signature from one of participants.
    #[wasm_bindgen(js_name = "addSignature")]
    pub fn add_signature(&mut self, signature: &[u8]) -> Result<(), JsValue> {
        let s = WasmFormats::read_fs_le(signature)?;

        self.signatures.push(s);

        Ok(())
    }

    /// Returns signature after aggregating all participants' signatures.
    #[wasm_bindgen(js_name = "getSignature")]
    pub fn get_signature(&self) -> Result<Vec<u8>, JsValue> {
        let signature = self
            .musig
            .aggregate_signature(&self.signatures)
            .map_err(WasmFormats::map_musig_error_to_js)?;

        let mut vec = Vec::new();

        WasmFormats::write_public_key(&self.aggregated_public_key, &mut vec)?;
        WasmFormats::write_point(&signature.r, &mut vec)?;
        WasmFormats::write_fs_le(&signature.s, &mut vec)?;

        Ok(vec)
    }
}
