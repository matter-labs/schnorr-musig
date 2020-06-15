#[cfg(test)]
mod tests{
    use wasm_bindgen_test::*;
    use bellman::{Field, PrimeField, PrimeFieldRepr};
    use franklin_crypto::alt_babyjubjub::AltJubjubBn256;
    use franklin_crypto::alt_babyjubjub::fs::{Fs, FsRepr};
    use franklin_crypto::eddsa::{PrivateKey, PublicKey, Signature};
    use franklin_crypto::jubjub::{FixedGenerators};
    use musig::verifier::MuSigVerifier;
    use bellman::pairing::bn256::{Bn256};
    use franklin_crypto::jubjub::edwards::Point;
    use musig::errors::MusigError;
    use crate::signer::MusigBN256WasmSigner;
    use crate::errors::MusigABIError;
    use crate::decoder::STANDARD_ENCODING_LENGTH;

    fn musig_wasm_bn256_deterministic_setup(
        number_of_participants: usize,
        generator: FixedGenerators,
    ) -> Result<(Vec<PrivateKey<Bn256>>, Vec<PublicKey<Bn256>>), MusigError> {
        let jubjub_params = AltJubjubBn256::new();
    
        let mut privkeys = vec![];
        let mut pubkeys = vec![];

        let mut privkey = Fs::zero();
        for i in 0..number_of_participants{
            privkey.add_assign(&Fs::one());
            privkeys.push(                
                PrivateKey::<Bn256>(privkey)
            );
            pubkeys.push(
                PublicKey::from_private(&privkeys[i], generator, &jubjub_params)
            );        
        }

    
        Ok((privkeys, pubkeys))
    }

    fn musig_wasm_multiparty_full_round(){
        let number_of_parties = 2;
        let jubjub_params = AltJubjubBn256::new();
        let rescue_params = franklin_crypto::rescue::bn256::Bn256RescueParams::new_checked_2_into_1();
        let generator = FixedGenerators::SpendingKeyGenerator;

        let message = vec![1,2,3,4,5];

        let (privkeys, pubkeys) = musig_wasm_bn256_deterministic_setup(number_of_parties, FixedGenerators::SpendingKeyGenerator).unwrap();

        let pubkey_len = STANDARD_ENCODING_LENGTH;

        let mut encoded_pubkeys = vec![0u8; number_of_parties*pubkey_len];

        for (position, pubkey) in pubkeys.iter().enumerate(){
            let offset = position * pubkey_len;
            pubkey.write(&mut encoded_pubkeys[offset..(offset + pubkey_len)]).unwrap();
        }        
        
        let mut wasm_signers = vec![];
        for position in 0..pubkeys.len(){
            let signer = MusigBN256WasmSigner::new(&encoded_pubkeys, position).unwrap();
            wasm_signers.push(signer);
        }
        assert!(wasm_signers.len() == number_of_parties);        
        
        let mut pre_commitments = vec![];
        for (position, wasm_signer) in wasm_signers.iter_mut().enumerate(){
            let mut encoded_privkey = vec![0u8;STANDARD_ENCODING_LENGTH];
            privkeys[position].0.into_repr().write_be(&mut encoded_privkey[..]).unwrap();

            let pre_commitment =  wasm_signer.compute_precommitment(&encoded_privkey, &message).unwrap();
            pre_commitments.extend_from_slice(&pre_commitment);
        }
        assert!(pre_commitments.len() == number_of_parties*pubkey_len);

        let mut commitments = vec![];
        for wasm_signer in wasm_signers.iter_mut(){
            let commitment = wasm_signer.receive_precommitments(&pre_commitments).unwrap();
            commitments.extend_from_slice(&commitment);
        }
        assert!(commitments.len() == number_of_parties*pubkey_len);

        let mut aggregated_commitments = vec![];
        for wasm_signer in wasm_signers.iter_mut(){
            let agg_commitment = wasm_signer.receive_commitments(&commitments).unwrap();
            aggregated_commitments.extend_from_slice(&agg_commitment);
        }

        assert!(aggregated_commitments.len() == number_of_parties*pubkey_len);
        let first_agg_commitment = aggregated_commitments[0..STANDARD_ENCODING_LENGTH].to_vec();
        for position in (0..pubkeys.len()).skip(1){
            let offset = position * pubkey_len;
            assert_eq!(first_agg_commitment[..STANDARD_ENCODING_LENGTH], aggregated_commitments[offset..(offset + pubkey_len)]);
        }
        
        
        let mut signature_shares = vec![];
        for (position,  wasm_signer) in wasm_signers.iter_mut().enumerate(){
            let mut encoded_privkey = vec![0u8;STANDARD_ENCODING_LENGTH];
            privkeys[position].0.into_repr().write_be(&mut encoded_privkey[..]).unwrap();
            let sig_share = wasm_signer.sign(&encoded_privkey, &message).unwrap();


            signature_shares.extend_from_slice(&sig_share);
        }
        assert!(signature_shares.len() == number_of_parties*pubkey_len);
        
        let mut aggregated_signatures = vec![];
        for wasm_signer in wasm_signers.iter_mut(){

            let agg_sig = wasm_signer.receive_signature_shares(&signature_shares).unwrap();            

            aggregated_signatures.extend_from_slice(&agg_sig);
        }

        assert!(aggregated_signatures.len() == 2*number_of_parties*pubkey_len);
        
        let first_agg_sig = aggregated_signatures[..(2*pubkey_len)].to_vec();
        
        for position in (0..pubkeys.len()).skip(1){
            let offset = position * (pubkey_len*2);
            let sig = aggregated_signatures[(offset)..(offset + pubkey_len)].to_vec();
            assert_eq!(first_agg_sig[..STANDARD_ENCODING_LENGTH], sig[..]);
        }


        let signature_r = Point::read(&first_agg_sig[..STANDARD_ENCODING_LENGTH], &jubjub_params).unwrap();

        let mut repr = FsRepr::default();        
        repr.read_be(&first_agg_sig[STANDARD_ENCODING_LENGTH..]).unwrap();        
        let signature_s = Fs::from_repr(repr).unwrap();
        
        let actual_signature = Signature{r: signature_r, s: signature_s};

        let is_verified = MuSigVerifier::<Bn256>::verify(
            &message, 
            &pubkeys, 
            &actual_signature, 
            0, 
            &jubjub_params,
            generator, 
            &rescue_params,
        ).unwrap();

        assert!(is_verified);
    }

    #[test]
    fn test_musig_wasm_multiparty_full_round(){
        musig_wasm_multiparty_full_round()
    }

    #[wasm_bindgen_test]
    fn test_musig_wasm(){        
        musig_wasm_multiparty_full_round();
    }

    #[wasm_bindgen_test]
    fn test_invalid_pubkey_length(){
        let number_of_parties = 2;

        let (_, pubkeys) = musig_wasm_bn256_deterministic_setup(number_of_parties, FixedGenerators::SpendingKeyGenerator).unwrap();

        let pubkey_len = STANDARD_ENCODING_LENGTH;

        let mut encoded_pubkeys = vec![0u8; number_of_parties*pubkey_len];

        for (position, pubkey) in pubkeys.iter().enumerate(){
            let offset = position * pubkey_len;
            pubkey.write(&mut encoded_pubkeys[offset..(offset + pubkey_len)]).unwrap();
        }        
        

        encoded_pubkeys.remove(1); // make pubkey list invalid

        for position in 0..pubkeys.len(){
            match MusigBN256WasmSigner::new(&encoded_pubkeys, position) {
                Err(e) => assert_eq!(e, MusigABIError::InvalidInputData.to_string()),
                _ => unreachable!(),
            }
        }
    }
}