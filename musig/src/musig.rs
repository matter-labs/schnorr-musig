use crate::musig_error::MusigError;
use crate::musig_hasher::MusigHasher;
use bellman::pairing::ff::Field;
use franklin_crypto::eddsa::{PrivateKey, PublicKey, Seed, Signature};
use franklin_crypto::jubjub::edwards::Point;
use franklin_crypto::jubjub::{FixedGenerators, JubjubEngine, Unknown};

/// This struct allows to perform simple schnorr multi-signature.
///
/// Paper that describes algorithm can be found here: https://eprint.iacr.org/2018/068.pdf.
/// New MusigSession should be created for each signature.
/// This class is not thread-safe.
pub struct MusigSession<E: JubjubEngine, H: MusigHasher<E>> {
    hasher: H,
    participants: Vec<PublicKey<E>>,
    self_index: usize,
    aggregated_public_key: PublicKey<E>,
    a_self: E::Fs,

    r_self: PrivateKey<E>,
    r_pub_aggregated: PublicKey<E>,

    t_others: Vec<Option<Vec<u8>>>,
    t_self: Vec<u8>,
    t_count: usize,

    r_pub_others: Vec<Option<PublicKey<E>>>,
    r_pub_self: PublicKey<E>,
    r_pub_count: usize,

    performed_sign: bool,
}

impl<E: JubjubEngine, H: MusigHasher<E>> MusigSession<E, H> {
    /// Creates new MusigSession
    ///
    /// # Arguments
    /// * `hasher` - trait object responsible for hashing.
    /// * `generator` - Generator used for elliptic curves operations.
    /// * `params` - Curve parameters.
    /// * `participants` - Static public keys of signature participants. Should be strictly ordered.
    /// * `seed` - Seed used for r. Could be either randomly generated per session or derived from static private key and message.
    /// * `self_index` - Index of current participant in participants vector.
    pub fn new(
        mut hasher: H,
        generator: FixedGenerators,
        params: &E::Params,
        participants: Vec<PublicKey<E>>,
        seed: Seed<E>,
        self_index: usize,
    ) -> Result<Self, MusigError> {
        let number_of_participants = participants.len();

        if self_index >= number_of_participants {
            return Err(MusigError::SelfIndexOutOfBounds);
        }

        let (aggregated_public_key, a_self) = MusigSession::<E, H>::compute_aggregated_public_key(
            &participants,
            &mut hasher,
            self_index,
            params,
        );

        let (r_self, r_pub_self, t) =
            MusigSession::<E, H>::generate_commitment(seed, &hasher, params, generator);

        let session = MusigSession {
            hasher,
            participants,
            self_index,
            aggregated_public_key,
            a_self,
            r_self,
            r_pub_aggregated: r_pub_self.clone(),
            t_others: vec![None; number_of_participants],
            t_self: t,
            t_count: 1,
            r_pub_others: vec![None; number_of_participants],
            r_pub_self,
            r_pub_count: 1,
            performed_sign: false,
        };

        Ok(session)
    }

    fn compute_aggregated_public_key(
        participants: &[PublicKey<E>],
        hasher: &mut H,
        self_index: usize,
        params: &E::Params,
    ) -> (PublicKey<E>, E::Fs) {
        let mut x: Point<E, Unknown> = Point::zero();

        let mut a_self = None;

        hasher.aggregate_hash_set_pubs(&participants);

        for (i, participant) in participants.iter().enumerate() {
            let ai = hasher.aggregate_hash(participant);

            x = x.add(&participant.0.mul(ai, params), params);

            if i == self_index {
                a_self = Some(ai);
            }
        }

        let a_self = a_self.expect("Self index not in range");

        (PublicKey(x), a_self)
    }

    fn generate_commitment(
        seed: Seed<E>,
        hasher: &H,
        params: &E::Params,
        generator: FixedGenerators,
    ) -> (PrivateKey<E>, PublicKey<E>, Vec<u8>) {
        let r = PrivateKey::<E>(seed.0);

        let r_pub = PublicKey::from_private(&r, generator, params);

        let t = hasher.commitment_hash(&r_pub);

        (r, r_pub, t)
    }

    /// Returns self index.
    pub fn get_self_index(&self) -> usize {
        self.self_index
    }

    /// Returns commitment.
    ///
    /// Commitments exchange should happen is the first step of creating musig.
    /// Commitment should be sent to all other participants and should be set using set_t fn.
    pub fn get_t(&self) -> &[u8] {
        &self.t_self
    }

    /// Returns R.
    ///
    /// R is a public value from which commitment is generated.
    /// Participants should exchange their R with each other as a second step of musig process.
    /// Use set_r_pub to set R from other participants.
    pub fn get_r_pub(&self) -> &PublicKey<E> {
        &self.r_pub_self
    }

    /// Returns aggregated public key which can be used to verify musig.
    ///
    /// Please be aware that upon musig verification one should check that given set of static
    /// public keys indeed gives exactly the same aggregated public key as one used for verification.
    pub fn get_aggregated_public_key(&self) -> &PublicKey<E> {
        &self.aggregated_public_key
    }

    /// Sets commitment from participant with given index.
    pub fn set_t(&mut self, t: &[u8], index: usize) -> Result<(), MusigError> {
        if self.self_index == index {
            return Err(MusigError::AssigningCommitmentToSelfIsForbidden);
        }

        if self.t_others[index].is_some() {
            return Err(MusigError::DuplicateCommitmentAssignment);
        }

        self.t_others[index] = Some(Vec::from(t));
        self.t_count += 1;

        Ok(())
    }

    /// Sets R value from participant with given index.
    ///
    /// After setting R values for all participants sign method can be called.
    pub fn set_r_pub(
        &mut self,
        r_pub: PublicKey<E>,
        index: usize,
        params: &E::Params,
    ) -> Result<(), MusigError> {
        if self.self_index == index {
            return Err(MusigError::AssigningRPubToSelfIsForbidden);
        }

        if self.t_count != self.participants.len() {
            return Err(MusigError::AssigningRPubBeforeSettingAllCommitmentsIsForbidden);
        }

        if self.r_pub_others[index].is_some() {
            return Err(MusigError::DuplicateRPubAssignment);
        }

        let t_real = self.hasher.commitment_hash(&r_pub);

        if !self.t_others[index]
            .as_ref()
            .expect("Commitment is absent during check")
            .eq(&t_real)
        {
            return Err(MusigError::RPubDoesntMatchWithCommitment);
        }

        self.r_pub_aggregated = PublicKey {
            0: self.r_pub_aggregated.0.add(&r_pub.0, params),
        };

        self.r_pub_others[index] = Some(r_pub);
        self.r_pub_count += 1;

        Ok(())
    }

    /// Produces signature part for current participant for message m using participant's static
    /// private key sk. Signature parts should be aggregated in the end.
    pub fn sign(&mut self, sk: &PrivateKey<E>, m: &[u8]) -> Result<E::Fs, MusigError> {
        if self.r_pub_count != self.participants.len() {
            return Err(MusigError::SigningBeforeSettingAllRPubIsForbidden);
        }

        if self.performed_sign {
            return Err(MusigError::SigningShouldHappenOnlyOncePerSession);
        }

        let msg_hash = self.hasher.message_hash(m);

        let mut s = self.hasher.signature_hash(
            &self.aggregated_public_key,
            &self.r_pub_aggregated,
            &msg_hash,
        );

        s.mul_assign(&self.a_self);
        s.mul_assign(&sk.0);
        s.add_assign(&self.r_self.0);

        self.performed_sign = true;

        Ok(s)
    }

    /// Aggregates participants signature parts into final musig.
    pub fn aggregate_signature(
        &self,
        participant_signatures: &[E::Fs],
    ) -> Result<Signature<E>, MusigError> {
        assert!(!participant_signatures.is_empty());

        if !self.performed_sign {
            return Err(MusigError::AggregatingSignatureBeforeSigningIsForbidden);
        }

        let mut s = E::Fs::zero();

        for s_participant in participant_signatures {
            s.add_assign(s_participant);
        }

        Ok(Signature {
            r: self.r_pub_aggregated.0.clone(),
            s,
        })
    }
}
