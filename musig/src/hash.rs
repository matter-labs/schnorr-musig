use bellman::pairing::ff::{PrimeField, PrimeFieldRepr};
use franklin_crypto::alt_babyjubjub::ToUniform;
use franklin_crypto::eddsa::PublicKey;
use franklin_crypto::jubjub::JubjubEngine;
use franklin_crypto::util::sha256_hash_to_scalar;
use sha2::{Digest, Sha256, Sha512};

pub const PACKED_POINT_SIZE: usize = 32;

/// Hash used for deriving aggregated public key.
pub trait AggregateHash<E: JubjubEngine> {
    fn set_pubs(&mut self, pubs: &[PublicKey<E>]);
    fn hash(&mut self, last: &PublicKey<E>) -> E::Fs;
}

/// Hash used for commitment generation.
pub trait CommitmentHash<E: JubjubEngine> {
    fn hash(&self, r_pub: &PublicKey<E>) -> Vec<u8>;
}

/// Hash used for hashing message hash and curve points into Fs during signature.
pub trait SignatureHash<E: JubjubEngine> {
    fn hash(&self, x_pub: &PublicKey<E>, r_pub: &PublicKey<E>, msg_hash: &[u8]) -> E::Fs;
}

/// Hash used to hash initial message.
pub trait MsgHash {
    fn hash(&self, m: &[u8]) -> Vec<u8>;
}

#[derive(Clone, Debug, Default)]
/// Sha256 implementation of hash traits
pub struct Sha256HStar {}

#[derive(Clone, Debug, Default)]
pub struct Sha512HStarAggregate {
    aggregate_hash_pubs: Vec<u8>,
}

impl Sha512HStarAggregate {
    pub fn new() -> Self {
        Sha512HStarAggregate {
            aggregate_hash_pubs: Vec::new(),
        }
    }
}

fn write_public_key<E: JubjubEngine>(public_key: &PublicKey<E>, dest: &mut Vec<u8>) {
    let (pk_x, _) = public_key.0.into_xy();
    let mut pk_x_bytes = [0u8; PACKED_POINT_SIZE];
    pk_x.into_repr()
        .write_le(&mut pk_x_bytes[..])
        .expect("has serialized pk_x");

    dest.extend_from_slice(&pk_x_bytes);
}

impl Sha256HStar {
    pub fn new() -> Self {
        Sha256HStar {}
    }
}

impl<E: JubjubEngine> SignatureHash<E> for Sha256HStar {
    fn hash(&self, x_pub: &PublicKey<E>, r_pub: &PublicKey<E>, msg_hash: &[u8]) -> E::Fs {
        assert!(msg_hash.len() <= 32);

        let mut concatenated: Vec<u8> = Vec::new();
        write_public_key(x_pub, &mut concatenated);
        write_public_key(r_pub, &mut concatenated);

        let mut msg_padded: Vec<u8> = msg_hash.to_vec();
        msg_padded.resize(PACKED_POINT_SIZE, 0u8);

        // FIXME: Sha256 should be replaces here with at least sha512 as sha256_hash_to_scalar results in biased output.
        sha256_hash_to_scalar::<E>(&[], &concatenated, &msg_padded)
    }
}

impl<E: JubjubEngine> AggregateHash<E> for Sha512HStarAggregate {
    fn set_pubs(&mut self, pubs: &[PublicKey<E>]) {
        self.aggregate_hash_pubs = Vec::<u8>::with_capacity(PACKED_POINT_SIZE * (pubs.len() + 1));

        for pub_key in pubs {
            write_public_key(pub_key, &mut self.aggregate_hash_pubs);
        }
    }

    fn hash(&mut self, last: &PublicKey<E>) -> <E as JubjubEngine>::Fs {
        assert!(!self.aggregate_hash_pubs.is_empty());

        write_public_key(last, &mut self.aggregate_hash_pubs);

        let res = E::Fs::to_uniform(Sha512::digest(&self.aggregate_hash_pubs).as_slice());

        self.aggregate_hash_pubs
            .resize_with(self.aggregate_hash_pubs.len() - PACKED_POINT_SIZE, || {
                panic!("sha256 aggregate_hash logic error")
            });

        res
    }
}

impl<E: JubjubEngine> CommitmentHash<E> for Sha256HStar {
    fn hash(&self, r_pub: &PublicKey<E>) -> Vec<u8> {
        let mut concatenated: Vec<u8> = Vec::new();

        write_public_key(r_pub, &mut concatenated);

        Sha256::digest(&concatenated).to_vec()
    }
}

impl MsgHash for Sha256HStar {
    fn hash(&self, m: &[u8]) -> Vec<u8> {
        Sha256::digest(m).to_vec()
    }
}
