use bellman::pairing::bn256::Bn256;
use franklin_crypto::alt_babyjubjub::FixedGenerators;
use franklin_crypto::eddsa::{PublicKey, Seed};
use musig::musig::MusigSession;
use musig::musig_hasher::{create_default_hasher, DefaultHasher};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

use crate::musig_wasm::{MusigWasm, JUBJUB_PARAMS};
use crate::wasm_formats::WasmFormats;

pub const PACKED_POINT_SIZE: usize = 32;
pub const FS_SIZE: usize = 32;

/// Class used to Build MusigSession.
#[wasm_bindgen(js_name = "MusigWasmBuilder")]
pub struct Builder {
    participants: Vec<PublicKey<Bn256>>,
    seed: Option<Seed<Bn256>>,
    self_index: usize,
    set_self_index: bool,
}

#[wasm_bindgen(js_class = "MusigWasmBuilder")]
impl Builder {
    /// Creates empty builder.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Builder {
            participants: Vec::new(),
            seed: None,
            self_index: 0,
            set_self_index: false,
        }
    }

    /// Derives deterministic seed from statis private key sk and message to be signed msg.
    #[wasm_bindgen(js_name = "deriveSeed")]
    pub fn derive_seed(&mut self, sk: &[u8], msg: &[u8]) -> Result<(), JsValue> {
        let sk = WasmFormats::read_private_key(sk)?;

        let hashed_msg = Sha256::digest(msg).to_vec();

        self.seed = Some(Seed::deterministic_seed(&sk, &hashed_msg));

        Ok(())
    }

    /// Adds participant.
    ///
    /// Participants should be strictly ordered.
    #[wasm_bindgen(js_name = "addParticipant")]
    pub fn add_participant(
        &mut self,
        participant_public_key: &[u8],
        is_me: bool,
    ) -> Result<(), JsValue> {
        if is_me && self.set_self_index {
            return Err(JsValue::from("Second self key"));
        }

        let key = WasmFormats::read_public_key(participant_public_key, &JUBJUB_PARAMS)?;

        if is_me {
            self.self_index = self.participants.len();
            self.set_self_index = true;
        }

        self.participants.push(key);

        Ok(())
    }

    /// Builds MusigWasm.
    #[wasm_bindgen]
    pub fn build(self) -> Result<MusigWasm, JsValue> {
        if !self.set_self_index {
            return Err(JsValue::from("No self index"));
        }

        let seed = self.seed.ok_or_else(|| JsValue::from("No seed"))?;

        let generator = FixedGenerators::SpendingKeyGenerator;

        let hasher = create_default_hasher();

        let session = MusigSession::<Bn256, DefaultHasher<Bn256>>::new(
            hasher,
            generator,
            &JUBJUB_PARAMS,
            self.participants,
            seed,
            self.self_index,
        )
        .map_err(WasmFormats::map_error_to_js)?;

        Ok(MusigWasm::new(session))
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}
