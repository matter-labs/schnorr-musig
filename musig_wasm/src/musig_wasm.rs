use bellman::pairing::bn256::Bn256;
use franklin_crypto::alt_babyjubjub::AltJubjubBn256;
use lazy_static::lazy_static;
use musig::musig::MusigSession;
use wasm_bindgen::prelude::*;

use crate::signature_aggregator::SignatureAggregator;
use crate::wasm_formats::WasmFormats;
use musig::musig_hasher::DefaultHasher;

pub const PACKED_POINT_SIZE: usize = 32;
pub const FS_SIZE: usize = 32;

lazy_static! {
    pub static ref JUBJUB_PARAMS: AltJubjubBn256 = AltJubjubBn256::new();
}

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Should be called before any other interaction with library.
#[wasm_bindgen]
pub fn init() {
    set_panic_hook();
    lazy_static::initialize(&JUBJUB_PARAMS);
}

/// This struct allows to create musig.
#[wasm_bindgen]
pub struct MusigWasm {
    musig: MusigSession<Bn256, DefaultHasher<Bn256>>,
}

#[wasm_bindgen]
impl MusigWasm {
    pub(crate) fn new(musig: MusigSession<Bn256, DefaultHasher<Bn256>>) -> Self {
        MusigWasm { musig }
    }

    /// Returns self index.
    #[wasm_bindgen(js_name = "getSelfIndex")]
    pub fn get_self_index(&self) -> usize {
        self.musig.get_self_index()
    }

    /// Returns commitment.
    ///
    /// Commitments exchange should happen is the first step of creating musig.
    /// Commitment should be sent to all other participants and should be set using set_t fn.
    #[wasm_bindgen(js_name = "getT")]
    pub fn get_t(&self) -> Vec<u8> {
        self.musig.get_t().to_vec()
    }

    /// Returns R.
    ///
    /// R is a public value from which commitment is generated.
    /// Participants should exchange their R with each other as a second step of musig process.
    /// Use set_r_pub to set R from other participants.
    #[wasm_bindgen(js_name = "getRPub")]
    pub fn get_r_pub(&self) -> Result<Vec<u8>, JsValue> {
        let mut vec = Vec::<u8>::with_capacity(PACKED_POINT_SIZE);

        WasmFormats::write_public_key(self.musig.get_r_pub(), &mut vec)?;

        Ok(vec)
    }

    /// Returns aggregated public key which can be used to verify musig.
    ///
    /// Please be aware that upon musig verification one should check that given set of static
    /// public keys indeed gives exactly the same aggregated public key as one used for verification.
    #[wasm_bindgen(js_name = "getAggregatedPublicKey")]
    pub fn get_aggregated_public_key(&self) -> Result<Vec<u8>, JsValue> {
        let mut vec = Vec::<u8>::with_capacity(PACKED_POINT_SIZE);

        WasmFormats::write_public_key(self.musig.get_aggregated_public_key(), &mut vec)?;

        Ok(vec)
    }

    /// Sets commitment from participant with given index.
    #[wasm_bindgen(js_name = "setT")]
    pub fn set_t(&mut self, t: &[u8], index: usize) -> Result<(), JsValue> {
        self.musig
            .set_t(t, index)
            .map_err(WasmFormats::map_musig_error_to_js)
    }

    /// Sets R value from participant with given index.
    ///
    /// After setting R values for all participants sign method can be called.
    #[wasm_bindgen(js_name = "setRPub")]
    pub fn set_r_pub(&mut self, r_pub: &[u8], index: usize) -> Result<(), JsValue> {
        let key = WasmFormats::read_public_key(r_pub, &JUBJUB_PARAMS)?;

        self.musig
            .set_r_pub(key, index, &JUBJUB_PARAMS)
            .map_err(WasmFormats::map_musig_error_to_js)
    }

    /// Produces signature part for current participant for message m using participant's static
    /// private key sk. Signature parts should be aggregated in the end.
    #[wasm_bindgen]
    pub fn sign(&mut self, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsValue> {
        let key = WasmFormats::read_private_key(sk)?;

        let res = self
            .musig
            .sign(&key, msg)
            .map_err(WasmFormats::map_musig_error_to_js)?;

        let mut vec: Vec<u8> = Vec::new();

        WasmFormats::write_fs_le(&res, &mut vec).map(|_| vec)
    }

    /// Builds signature aggregator.
    #[wasm_bindgen(js_name = "buildSignatureAggregator")]
    pub fn build_signature_aggregator(self) -> SignatureAggregator {
        let aggregated_public_key = self.musig.get_aggregated_public_key().clone();

        SignatureAggregator::new(self.musig, aggregated_public_key)
    }
}
