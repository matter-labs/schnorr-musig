use crate::aggregated_pubkey::AggregatedPublicKey;
use crate::errors::MusigError;
use crate::hasher::Hasher;
use crate::jubjub::JubJubWrapper;
use crate::verifier::MuSigVerifier;
use bellman::pairing::ff::Field;
use franklin_crypto::eddsa::{PrivateKey, PublicKey, Signature};
use franklin_crypto::jubjub::edwards::Point;
use franklin_crypto::jubjub::{FixedGenerators, JubjubEngine, Unknown};
use franklin_crypto::rescue::RescueEngine;
use rand::{Rand, Rng};
/// MuSig signer party holds required data for protocol run
pub struct MuSigSigner<E: JubjubEngine + RescueEngine> {
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

impl<E: JubjubEngine + RescueEngine> MuSigSigner<E> {
    /// Initializes new party
    /// All pubkeys required for computation of aggregated public key
    pub fn new(
        pubkeys: &[PublicKey<E>],
        position: usize,
        params: <E as JubjubEngine>::Params,
        generator: FixedGenerators,
    ) -> Result<Self, MusigError> {
        let jubjub_wrapper = JubJubWrapper::new(params, generator);

        // we need each a_i values for signature share verification
        let (aggregated_pubkey, a_values) =
            AggregatedPublicKey::compute_from_pubkeys(pubkeys, &jubjub_wrapper.params)?;

        Ok(Self {
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
            jubjub_wrapper,
        })
    }

    /// Pre-commitment is hash of serialized point which computed
    /// by multiplication of a randomly generated scalar with generator.
    /// rng must be a cryptographically secure one.
    pub fn compute_precommitment(&mut self, rng: &mut impl Rng) -> Result<Vec<u8>, MusigError> {
        let r = E::Fs::rand(rng);
        // R = r*G
        // constant-time multiplication
        let R = self.jubjub_wrapper.mul_by_generator_ct(r);

        // t = H_comm(R)
        let pre_commitment = Hasher::hash_commitment(&R);

        self.nonce = Some(r);
        self.nonce_commitment = Some(R);

        Ok(pre_commitment)
    }

    /// Receives pre-commitments of other parties and returns his revealed
    /// commitment which is a point in the group. These pre-commitments will
    /// be used to validate received revealed commitments in the next step.     
    pub fn receive_precommitments(
        &mut self,
        pre_commitments: &[Vec<u8>],
    ) -> Result<Point<E, Unknown>, MusigError> {
        // check that whether previous step passed or not
        if self.nonce_commitment.is_none() {
            return Err(MusigError::NonceCommitmentNotGenerated);
        }

        if pre_commitments.len() != self.pubkeys.len() {
            return Err(MusigError::NoncePreCommitmentsAndParticipantsNotMatch);
        }

        let nonce_commitment = self.nonce_commitment.clone().unwrap();

        self.pre_commitments = Some(pre_commitments.to_vec());

        Ok(nonce_commitment)
    }

    /// Receives revealed commitments and compare them against
    /// pre-commitments that received previous step. If all commitments
    //  are valid then returns computed aggregated commitment which is
    /// sum of all commitments. Each party must produce same aggregated
    /// commitment.
    pub fn receive_commitments(
        &mut self,
        commitments: &[Point<E, Unknown>],
    ) -> Result<Point<E, Unknown>, MusigError> {
        // check that whether previous step passed or not
        if self.pre_commitments.is_none() {
            return Err(MusigError::NoncePreCommitmentsNotReceived);
        }

        if commitments.len() != self.pubkeys.len() {
            return Err(MusigError::NonceCommitmentsAndParticipantsNotMatch);
        }

        let pre_commitments = self.pre_commitments.clone().unwrap();

        // check that t_i == H_comm(R_i)
        for (commitment, pre_commitment) in commitments.iter().zip(pre_commitments.iter()) {
            let t_i = Hasher::hash_commitment(&commitment);
            if !self.jubjub_wrapper.is_in_correct_subgroup(&commitment) {
                return Err(MusigError::CommitmentIsNotInCorrectSubgroup);
            }
            if *pre_commitment != t_i {
                return Err(MusigError::InvalidCommitment);
            }
        }

        // R = \sum{1<=i<=n}{R_i}
        let mut acc = Point::zero();
        for commitment in commitments {
            acc = self.jubjub_wrapper.add(&acc, &commitment);
        }
        self.aggregated_commitment = Some(acc);
        self.nonce_commitments = commitments.to_vec();

        Ok(acc)
    }

    /// Computes signature share with a challenge 'c'
    pub fn sign(
        &mut self,
        private_key: &PrivateKey<E>,
        message: &[u8],
        rescue_params: &<E as RescueEngine>::Params,
    ) -> Result<E::Fs, MusigError> {
        // check that whether previous step passed or not
        if self.aggregated_commitment.is_none() {
            return Err(MusigError::NonceCommitmentsNotReceived);
        }

        let aggregated_commitment = self.aggregated_commitment.clone().unwrap();
        // since aggregated commitment has already generated
        // we can safely unwrap nonce
        let r = self.nonce.unwrap();

        let aggregated_pubkey = self.aggregated_pubkey.clone();

        let a_i = self.a_values[self.position];

        // c = H_sig(X', R, m)
        // this computes fiat-shamir challenge
        let c = Hasher::hash_signature_data::<E>(
            &aggregated_pubkey,
            &aggregated_commitment,
            message,
            rescue_params,
        );

        self.challenge = Some(c);
        // s = r + c * a_i * x_i
        let mut s = c;
        s.mul_assign(&a_i);
        s.mul_assign(&private_key.0);
        s.add_assign(&r);

        Ok(s)
    }

    /// Receives signature shares and verifies them. If all signature shares
    /// are valid then returns an aggregated signature. Each party must produce
    /// same aggregated signature.
    pub fn receive_signatures(
        &self,
        signature_shares: &[E::Fs],
    ) -> Result<Signature<E>, MusigError> {
        // check that whether previous step passed or not
        if self.challenge.is_none() {
            return Err(MusigError::ChallengeNotGenerated);
        }

        if signature_shares.len() != self.pubkeys.len() {
            return Err(MusigError::SignatureShareAndParticipantsNotMatch);
        }

        let mut aggregated_signature = self.signature;
        // s = \sum{1<=i<=n}{s_i}
        for (position, signature) in signature_shares.iter().enumerate() {
            // verify each signature share
            // s*G = R_i + (c * a_i) * X_i
            self.verify_share(signature, position)?;
            aggregated_signature.add_assign(&signature);
        }

        let aggregated_commitment = self.aggregated_commitment.clone().unwrap();

        // σ = (R, s)
        Ok(Signature {
            r: aggregated_commitment,
            s: aggregated_signature,
        })
    }

    /// Verifies asignature share of a single party.
    fn verify_share(&self, signature_share: &E::Fs, position: usize) -> Result<(), MusigError> {
        let challenge = self.challenge.unwrap();

        if !MuSigVerifier::verify_share(
            signature_share,
            &self.nonce_commitments[position],
            &challenge,
            &self.a_values[position],
            &self.pubkeys[position],
            &self.jubjub_wrapper,
        ) {
            return Err(MusigError::InvalidSignatureShare);
        }
        Ok(())
    }
}
