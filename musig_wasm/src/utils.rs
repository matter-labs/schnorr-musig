use bellman::pairing::bn256::Bn256;
use franklin_crypto::alt_babyjubjub::FixedGenerators;
use franklin_crypto::eddsa::{PrivateKey, PublicKey};
use rand::{Rng, SeedableRng, StdRng};
use wasm_bindgen::prelude::*;

use crate::musig_wasm::JUBJUB_PARAMS;
use crate::musig_wasm::{FS_SIZE, PACKED_POINT_SIZE};
use crate::wasm_formats::WasmFormats;

/// This struct responsible for utils operations that do not belong to musig process, but are
/// required to perform full flow. Do not use for production.
#[wasm_bindgen(js_name = "MusigWasmUtils")]
pub struct Utils {}

#[wasm_bindgen(js_class = "MusigWasmUtils")]
impl Utils {
    /// Generates private key from seed.
    #[wasm_bindgen(js_name = "generatePrivateKey")]
    pub fn generate_private_key(seed: &[usize]) -> Result<Vec<u8>, JsValue> {
        let mut rng = StdRng::from_seed(seed);

        let private_key = PrivateKey::<Bn256>(rng.gen());

        let mut vec = Vec::<u8>::with_capacity(FS_SIZE);

        WasmFormats::write_private_key(&private_key, &mut vec)?;

        Ok(vec)
    }

    /// Extracts public key from private key.
    #[wasm_bindgen(js_name = "extractPublicKey")]
    pub fn extract_public_key(private_key: &[u8]) -> Result<Vec<u8>, JsValue> {
        let private_key = WasmFormats::read_private_key(private_key)?;

        let public_key = PublicKey::<Bn256>::from_private(
            &private_key,
            FixedGenerators::SpendingKeyGenerator,
            &JUBJUB_PARAMS,
        );

        let mut vec = Vec::<u8>::with_capacity(PACKED_POINT_SIZE);

        WasmFormats::write_public_key(&public_key, &mut vec)?;

        Ok(vec)
    }
}
