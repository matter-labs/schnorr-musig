use bellman::pairing::ff::Field;
use franklin_crypto::jubjub::{JubjubEngine, FixedGenerators, Unknown};
use franklin_crypto::eddsa::{PrivateKey, PublicKey, Signature, Seed};
use franklin_crypto::jubjub::edwards::Point;
use rand::{Rng, Rand};
use franklin_crypto::rescue::RescueEngine;
use crate::errors::MusigError;
use crate::jubjub::JubJubWrapper;
use crate::aggregated_pubkey::AggregatedPublicKey;
use crate::hasher::Hasher;
use crate::verifier::MuSigVerifier;

pub struct MuSigSigner<E: JubjubEngine + RescueEngine>{
    position: usize,
    nonce: Option<E::Fs>,
    nonce_commitment: Option<Point<E, Unknown>>,
    nonce_commitments: Vec<Point<E, Unknown>>,
    aggregated_commitment: Option<Point<E, Unknown>>,
    aggregated_pubkey: PublicKey<E>,
    a_values: Vec<E::Fs>,
    pre_commitments: Option<Vec<Vec<u8>>>,
    signature: E::Fs,
    challenge: Option<E::Fs>,
    pubkeys: Vec<PublicKey<E>>,
    jubjub_wrapper: JubJubWrapper<E>,
}

impl<E: JubjubEngine + RescueEngine> MuSigSigner<E>{
    pub fn new(
        pubkeys: &[PublicKey<E>], 
        position: usize, 
        params: <E as JubjubEngine>::Params,
        generator: FixedGenerators,
    ) -> Result<Self, MusigError>{
        let jubjub_wrapper = JubJubWrapper::new(params, generator);

        // we need each a_i values for signature share verification
        let (aggregated_pubkey, a_values) = AggregatedPublicKey::compute_from_pubkeys(
            pubkeys, 
            position,
            &jubjub_wrapper.params,
        )?;

        Ok(Self{
            position,
            nonce: None,
            nonce_commitment: None,
            nonce_commitments: vec![],
            aggregated_commitment: None,
            aggregated_pubkey,
            a_values,
            pre_commitments: None,
            signature: E::Fs::zero(),
            challenge: None,
            pubkeys: pubkeys.to_vec(),
            jubjub_wrapper: jubjub_wrapper,
        })
    }   

    pub fn compute_precommitment(
        &mut self,
        rng: &mut impl Rng,     
    ) -> Result<Vec<u8>, MusigError> {
        let r = E::Fs::rand(rng);
        // R = r*G        
        // constant-time multiplication
        let R = self.jubjub_wrapper.mul_by_generator_ct(r);
        {
            // check R_i has correct order
            if !self.jubjub_wrapper.is_in_correct_subgroup(&R){
                return Err(MusigError::InvalidCommitment)
            }
        }

        // t = H_comm(R)
        let pre_commitment  = Hasher::hash_commitment(&R);

        self.nonce = Some(r);
        self.nonce_commitment = Some(R);
        
        Ok(pre_commitment)
    }

    pub fn compute_precommitment_with_seed(
        &mut self,
        seed: Seed<E>,
    ) -> Result<Vec<u8>, MusigError> {
        // R = r*G    
        // constant-time multiplication    
        let R = self.jubjub_wrapper.mul_by_generator_ct(seed.0);
        {
            // check R_i has correct order
            if !self.jubjub_wrapper.is_in_correct_subgroup(&R){
                return Err(MusigError::InvalidCommitment)
            }
        }

        // t = H_comm(R)
        let pre_commitment  = Hasher::hash_commitment(&R);

        self.nonce = Some(seed.0);
        self.nonce_commitment = Some(R);
        Ok(pre_commitment)
    }

    pub fn receive_precommitments(
        &mut self,
        pre_commitments: &[Vec<u8>],
    ) -> Result<Point<E, Unknown>, MusigError> {
        // check that whether previous step passed or not
        if self.nonce_commitment.is_none(){
            return Err(MusigError::NonceCommitmentNotGenerated);
        }

        if pre_commitments.len() != self.pubkeys.len(){
            return Err(MusigError::NoncePreCommitmentsAndParticipantsNotMatch);
        }

        let nonce_commitment = self.nonce_commitment.clone().unwrap();

        self.pre_commitments = Some(pre_commitments.to_vec());
            
        Ok(nonce_commitment)
    }

    pub fn receive_commitments(
        &mut self,
        commitments: &[Point<E, Unknown>],
    ) -> Result<Point<E, Unknown>, MusigError> {
        // check that whether previous step passed or not
        if self.pre_commitments.is_none(){
            return Err(MusigError::NoncePreCommitmentsNotReceived)
        }

        if commitments.len() != self.pubkeys.len(){
            return Err(MusigError::NonceCommitmentsAndParticipantsNotMatch);
        }

        let pre_commitments = self.pre_commitments.clone().unwrap();

        // check that t_i == H_comm(R_i)
        for (commitment, pre_commitment) in commitments.iter().zip(pre_commitments.iter()){
            let t_i  = Hasher::hash_commitment(&commitment);
            if !self.jubjub_wrapper.is_in_correct_subgroup(&commitment){
                return Err(MusigError::CommitmentIsNotInCorrectSubgroup);
            }            
            if *pre_commitment != t_i{
                return Err(MusigError::InvalidCommitment)
            }
        }        

        // R = \sum{1<=i<=n}{R_i}
        let mut acc = Point::zero();
        for commitment in commitments{
            acc = self.jubjub_wrapper.add(&acc, &commitment);
        }
        self.aggregated_commitment = Some(acc.clone());
        self.nonce_commitments = commitments.to_vec();

        Ok(acc)
    }

    pub fn sign(
        &mut self,
        private_key: &PrivateKey<E>,
        message: &[u8],
        rescue_params: &<E as RescueEngine>::Params,
    ) -> Result<E::Fs, MusigError>{      
        // check that whether previous step passed or not        
        if self.aggregated_commitment.is_none(){
            return Err(MusigError::NonceCommitmentsNotReceived)
        }

        let aggregated_commitment = self.aggregated_commitment
            .clone()
            .unwrap();
        // since aggregated commitment has already generated 
        // we can safely unwrap nonce
        let r = self.nonce.unwrap(); 
                    
        let aggregated_pubkey = self.aggregated_pubkey.clone();

        let a_i = self.a_values[self.position].clone();

        // c = H_sig(X', R, m)
        // this computes fiat-shamir challenge
        let c = Hasher::hash_signature_data::<E>(
            &aggregated_pubkey, 
            &aggregated_commitment, 
            message,
            rescue_params
        );

        self.challenge = Some(c);
        // s = r + c * a_i * x_i  
        let mut s = c.clone();
        s.mul_assign(&a_i);
        s.mul_assign(&private_key.0);
        s.add_assign(&r);

        Ok(s)
    }

    pub fn receive_signatures(
        &self,
        signature_shares: &[E::Fs],
    ) -> Result<Signature<E>, MusigError> {        
        // check that whether previous step passed or not
        if self.challenge.is_none(){
            return Err(MusigError::ChallengeNotGenerated)
        }

        if signature_shares.len() != self.pubkeys.len(){
            return Err(MusigError::SignatureShareAndParticipantsNotMatch);
        }

        let mut aggregated_signature = self.signature.clone();     
        // s = \sum{1<=i<=n}{s_i}
        for (position, signature) in signature_shares.iter().enumerate(){
            // verify each signature share
            // s*G = R_i + (c * a_i) * X_i   
            self.verify_share(signature, position)?;
            aggregated_signature.add_assign(&signature);
        }

        let aggregated_commitment = self.aggregated_commitment
        .clone()
        .unwrap();  

        // σ = (R, s)
        Ok(Signature{
            r: aggregated_commitment, 
            s: aggregated_signature,
        })
    }    

    fn verify_share(
        &self,
        signature_share: &E::Fs,
        position: usize,
    ) -> Result<(), MusigError>{
        let challenge = self.challenge
            .clone()
            .unwrap();
        
        if !MuSigVerifier::verify_share(
            signature_share,
            &self.nonce_commitments[position],
            &challenge, 
            &self.a_values[position], 
            &self.pubkeys[position],
            &self.jubjub_wrapper,
        ){
            return Err(MusigError::InvalidSignatureShare);
        }
        Ok(())
    }
}
