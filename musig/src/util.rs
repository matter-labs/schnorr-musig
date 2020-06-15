use sha2::{Sha256, Digest};
use rand::Rng;

pub fn random_message_hash(rng: &mut impl Rng) -> Vec<u8> {
    let size = 32;

    let mut msg: Vec<u8> = vec![0; size];

    rng.fill_bytes(&mut msg);

    fn hash(m: &[u8]) -> Vec<u8> {
        Sha256::digest(m).to_vec()
    }

    hash(msg.as_ref())
}
