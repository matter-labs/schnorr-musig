use bellman::{PrimeField, PrimeFieldRepr};
use bellman::pairing::bn256::{Bn256};
use franklin_crypto::alt_babyjubjub::{AltJubjubBn256};
use franklin_crypto::eddsa::Seed;
use franklin_crypto::jubjub::FixedGenerators;
// use rand::{XorShiftRng, SeedableRng};
use musig::signer::MuSigSigner;
use wasm_bindgen::prelude::*;
use crate::errors::MusigABIError;
use crate::decoder::Decoder;

#[wasm_bindgen]
pub struct MusigBN256WasmSigner{
    musig_signer: MuSigSigner<Bn256>
}

impl From<MusigABIError> for JsValue{
    fn from(err: MusigABIError) -> Self {
        JsValue::from(err.to_string())
    }
}


#[wasm_bindgen]
impl MusigBN256WasmSigner{
    #[wasm_bindgen]
    pub fn new(
        input: &[u8], // concatenation of all pubkeys
        position: usize,
    ) -> Result<MusigBN256WasmSigner, JsValue>{
        let pubkeys = Decoder::decode_pubkey_list(input)?;

        let jubjub_params = AltJubjubBn256::new();
        let generator = FixedGenerators::SpendingKeyGenerator;
        
        let signer = MuSigSigner::new(&pubkeys[..], position, jubjub_params, generator)
            .map_err(|e| JsValue::from(format!("{}", e)))?;

        Ok(MusigBN256WasmSigner{
            musig_signer: signer,
        })
    }

    // #[wasm_bindgen]
    // fn compute_precommitment_with_rng(        
    //     &mut self,        
    // ) -> Vec<u8> {
    //     let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    //     let pre_commitment = self.musig_signer.compute_precommitment(rng).unwrap();

    //     pre_commitment
    // }

    #[wasm_bindgen]
    pub fn compute_precommitment(        
        &mut self,        
        private_key_bytes: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, JsValue> {    
        let private_key = Decoder::decode_private_key(private_key_bytes)?;

        let seed = Seed::deterministic_seed(&private_key, message);

        let pre_commitment = self.musig_signer.compute_precommitment_with_seed(seed)
            .map_err(|e| JsValue::from(format!("{}", e)))?;

        Ok(pre_commitment)
    }

    #[wasm_bindgen]
    pub fn receive_precommitments(
        &mut self,
        input: &[u8],
    ) -> Result<Vec<u8>, JsValue>{
        let pre_commitments = Decoder::decode_pre_commitments(input)?;

        let nonce_commitment = self.musig_signer.receive_precommitments(&pre_commitments)
            .map_err(|e| JsValue::from(format!("{}", e)))?;

        let mut encoded_nonce_commitment = vec![0u8; crate::decoder::STANDARD_ENCODING_LENGTH];

        nonce_commitment.write(&mut encoded_nonce_commitment[..])
            .map_err(|_| MusigABIError::EncodingError)?;
        
        Ok(encoded_nonce_commitment)
    }

    #[wasm_bindgen]
    pub fn receive_commitments(
        &mut self,
        input: &[u8],
    ) -> Result<Vec<u8>, JsValue>{
        let commitments = Decoder::decode_commitments(input)?;

        let aggregated_commitment = self.musig_signer.receive_commitments(&commitments)
            .map_err(|e| JsValue::from(format!("{}", e)))?;

        let mut encoded_agg_commitment = vec![0u8; crate::decoder::STANDARD_ENCODING_LENGTH];

        aggregated_commitment.write(&mut encoded_agg_commitment[..])
            .map_err(|_| MusigABIError::EncodingError)?;
        
        Ok(encoded_agg_commitment)
    }

    #[wasm_bindgen]
    pub fn sign(
        &mut self,
        private_key_bytes: &[u8],
        message: &[u8],        
    ) -> Result<Vec<u8>, JsValue>{  
        let rescue_params = franklin_crypto::rescue::bn256::Bn256RescueParams::new_checked_2_into_1();

        let private_key = Decoder::decode_private_key(private_key_bytes)?;

        let signature_share = self.musig_signer.sign(&private_key, message, &rescue_params)
            .map_err(|e| JsValue::from(format!("{}", e)))?;

        let mut encoded_sig_share = vec![0u8; crate::decoder::STANDARD_ENCODING_LENGTH];

        signature_share.into_repr().write_be(&mut encoded_sig_share[..])
            .map_err(|_| MusigABIError::EncodingError)?;

        Ok(encoded_sig_share)
    }

    #[wasm_bindgen]
    pub fn receive_signature_shares(
        &self,
        input: &[u8], 
    ) -> Result<Vec<u8>, JsValue>{
        let signature_shares = Decoder::decode_signature_shares(input)?;

        let signature = self.musig_signer.receive_signatures(&signature_shares)
            .map_err(|e| JsValue::from(format!("{}", e)))?;
        
        // (R, s)
        let mut encoded_sig = vec![0u8; 2*crate::decoder::STANDARD_ENCODING_LENGTH];
        signature.r.write(&mut encoded_sig[..crate::decoder::STANDARD_ENCODING_LENGTH])
            .map_err(|_| MusigABIError::EncodingError)?;

        signature.s.into_repr().write_be(&mut encoded_sig[crate::decoder::STANDARD_ENCODING_LENGTH..])
            .map_err(|_| MusigABIError::EncodingError)?;

        Ok(encoded_sig)
    }

}
