use crate::hash::*;
use franklin_crypto::eddsa::PublicKey;
use franklin_crypto::jubjub::JubjubEngine;
use std::marker::PhantomData;

/// Trait represents all hashes needed for musig.
pub trait MusigHasher<E: JubjubEngine> {
    fn aggregate_hash_set_pubs(&mut self, pubs: &[PublicKey<E>]);
    fn aggregate_hash(&mut self, last: &PublicKey<E>) -> E::Fs;
    fn commitment_hash(&self, r_pub: &PublicKey<E>) -> Vec<u8>;
    fn signature_hash(&self, x_pub: &PublicKey<E>, r_pub: &PublicKey<E>, msg_hash: &[u8]) -> E::Fs;
    fn message_hash(&self, m: &[u8]) -> Vec<u8>;
}

#[derive(Clone, Debug)]
/// Template implementation of MusigHasher trait implemented as aggregation of other traits.
pub struct ConfigurableMusigHasher<E, AH, CH, SH, MH>
where
    E: JubjubEngine,
    AH: AggregateHash<E>,
    CH: CommitmentHash<E>,
    SH: SignatureHash<E>,
    MH: MsgHash,
{
    aggregate_hash: AH,
    commitment_hash: CH,
    signature_hash: SH,
    message_hash: MH,
    phantom: std::marker::PhantomData<E>,
}

impl<
        E: JubjubEngine,
        AH: AggregateHash<E>,
        CH: CommitmentHash<E>,
        SH: SignatureHash<E>,
        MH: MsgHash,
    > ConfigurableMusigHasher<E, AH, CH, SH, MH>
{
    pub fn new(
        aggregate_hash: AH,
        commitment_hash: CH,
        signature_hash: SH,
        message_hash: MH,
    ) -> Self {
        ConfigurableMusigHasher {
            aggregate_hash,
            commitment_hash,
            signature_hash,
            message_hash,
            phantom: PhantomData,
        }
    }
}

pub type DefaultHasher<E> =
    ConfigurableMusigHasher<E, Sha512HStarAggregate, Sha256HStar, Sha256HStar, Sha256HStar>;

pub fn create_default_hasher<E: JubjubEngine>() -> DefaultHasher<E> {
    DefaultHasher::new(
        Sha512HStarAggregate::new(),
        Sha256HStar::new(),
        Sha256HStar::new(),
        Sha256HStar::new(),
    )
}

impl<
        E: JubjubEngine,
        AH: AggregateHash<E>,
        CH: CommitmentHash<E>,
        SH: SignatureHash<E>,
        MH: MsgHash,
    > MusigHasher<E> for ConfigurableMusigHasher<E, AH, CH, SH, MH>
{
    fn aggregate_hash_set_pubs(&mut self, pubs: &[PublicKey<E>]) {
        self.aggregate_hash.set_pubs(pubs);
    }

    fn aggregate_hash(&mut self, last: &PublicKey<E>) -> <E as JubjubEngine>::Fs {
        self.aggregate_hash.hash(last)
    }

    fn commitment_hash(&self, r_pub: &PublicKey<E>) -> Vec<u8> {
        self.commitment_hash.hash(r_pub)
    }

    fn signature_hash(
        &self,
        x_pub: &PublicKey<E>,
        r_pub: &PublicKey<E>,
        msg_hash: &[u8],
    ) -> <E as JubjubEngine>::Fs {
        self.signature_hash.hash(x_pub, r_pub, msg_hash)
    }

    fn message_hash(&self, m: &[u8]) -> Vec<u8> {
        self.message_hash.hash(m)
    }
}
