use crate::errors::MusigError;
use crate::signer::MuSigSigner;
use crate::verifier::MuSigVerifier;
use bellman::pairing::bn256::Bn256;
use bellman::Field;
use franklin_crypto::alt_babyjubjub::{fs::Fs, AltJubjubBn256};
use franklin_crypto::eddsa::{PrivateKey, PublicKey, Signature};
use franklin_crypto::jubjub::edwards::Point;
use franklin_crypto::jubjub::{FixedGenerators, JubjubEngine};
use franklin_crypto::rescue::{bn256::Bn256RescueParams, RescueEngine};
use rand::{Rng, SeedableRng, XorShiftRng};

use sha2::{Digest, Sha256};

pub fn random_message_hash(rng: &mut impl Rng) -> Vec<u8> {
    let size = 32;

    let mut msg: Vec<u8> = vec![0; size];

    rng.fill_bytes(&mut msg);

    fn hash(m: &[u8]) -> Vec<u8> {
        Sha256::digest(m).to_vec()
    }

    hash(msg.as_ref())
}

#[test]
fn test_musig_single_party() {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let jubjub_params = AltJubjubBn256::new();
    let rescue_params = Bn256RescueParams::new_checked_2_into_1();
    let generator = FixedGenerators::SpendingKeyGenerator;

    let message = random_message_hash(rng);

    let number_of_parties = 1;

    let (privkeys, pubkeys, mut signers) = musig_test_bn256_setup(number_of_parties).unwrap();

    assert!(musig_multi_party_test_runner(
        rng,
        &message,
        &pubkeys,
        &privkeys,
        &mut signers,
        &jubjub_params,
        &rescue_params,
        generator
    )
    .is_ok());
}
#[test]
fn test_musig_multiparty_full_round() {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

    let jubjub_params = AltJubjubBn256::new();
    let rescue_params = Bn256RescueParams::new_checked_2_into_1();
    let generator = FixedGenerators::SpendingKeyGenerator;

    let message = random_message_hash(rng);

    let number_of_parties = 5;

    let (privkeys, pubkeys, mut signers) = musig_test_bn256_setup(number_of_parties).unwrap();

    assert!(musig_multi_party_test_runner(
        rng,
        &message,
        &pubkeys,
        &privkeys,
        &mut signers,
        &jubjub_params,
        &rescue_params,
        generator
    )
    .is_ok());
}

#[allow(clippy::type_complexity)]
pub fn musig_test_bn256_setup(
    number_of_participants: usize,
) -> Result<
    (
        Vec<PrivateKey<Bn256>>,
        Vec<PublicKey<Bn256>>,
        Vec<MuSigSigner<Bn256>>,
    ),
    MusigError,
> {
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let generator = FixedGenerators::SpendingKeyGenerator;
    let jubjub_params = AltJubjubBn256::new();

    let mut privkeys = vec![];
    let mut pubkeys = vec![];
    let mut signers = vec![];

    for _ in 0..number_of_participants {
        let privkey = PrivateKey::<Bn256>(rng.gen());
        let pubkey = PublicKey::from_private(&privkey, generator, &jubjub_params);

        privkeys.push(privkey);
        pubkeys.push(pubkey);
    }

    for position in 0..privkeys.len() {
        let signer =
            MuSigSigner::<Bn256>::new(&pubkeys, position, AltJubjubBn256::new(), generator)?;
        signers.push(signer);
    }

    Ok((privkeys, pubkeys, signers))
}

#[allow(clippy::too_many_arguments)]
fn musig_multi_party_test_runner<E: JubjubEngine + RescueEngine>(
    rng: &mut impl Rng,
    message: &[u8],
    pubkeys: &[PublicKey<E>],
    privkeys: &[PrivateKey<E>],
    signers: &mut [MuSigSigner<E>],
    jubjub_params: &<E as JubjubEngine>::Params,
    rescue_params: &<E as RescueEngine>::Params,
    generator: FixedGenerators,
) -> Result<(), MusigError> {
    let number_of_participants = privkeys.len();

    let mut pre_commitments = vec![vec![]; number_of_participants];
    for (position, signer) in signers.iter_mut().enumerate() {
        pre_commitments[position] = signer.compute_precommitment(rng)?;
    }

    let mut commitments = vec![Point::zero(); number_of_participants];
    for (position, signer) in signers.iter_mut().enumerate() {
        commitments[position] = signer.receive_precommitments(&pre_commitments)?;
    }

    let mut aggregated_commitments = vec![Point::zero(); number_of_participants];
    for (position, signer) in signers.iter_mut().enumerate() {
        aggregated_commitments[position] = signer.receive_commitments(&commitments)?;
    }

    let first_commitment = aggregated_commitments[0];
    aggregated_commitments
        .iter()
        .for_each(|commitment| assert!(first_commitment.eq(commitment)));

    let mut signature_shares = vec![E::Fs::zero(); number_of_participants];
    for (position, signer) in signers.iter_mut().enumerate() {
        signature_shares[position] = signer.sign(&privkeys[position], &message, &rescue_params)?;
    }

    let mut aggregated_signatures = vec![
        Signature {
            r: Point::zero(),
            s: E::Fs::zero()
        };
        number_of_participants
    ];
    for (position, signer) in signers.iter_mut().enumerate() {
        aggregated_signatures[position] = signer.receive_signatures(&signature_shares)?;
    }

    let first_signature = aggregated_signatures[0].clone();
    aggregated_signatures.iter().for_each(|sig| {
        assert!(first_signature.r.eq(&sig.r));
        assert!(first_signature.s.eq(&sig.s));
    });

    for (_, signature) in aggregated_signatures.iter().enumerate() {
        let is_verified = MuSigVerifier::verify(
            &message,
            &pubkeys,
            signature,
            &jubjub_params,
            generator,
            &rescue_params,
        )?;
        assert!(is_verified);
    }

    Ok(())
}

#[test]
fn test_musig_api_errors() {
    #[derive(Debug)]
    enum ComputationRound {
        Setup,
        ReceivePreCommitmentsWithoutPreviousRound,
        ReceivePreCommitments,
        ReceiveCommitmentsWithoutPreviousRound,
        ReceiveCommitments,
        SignWithoutPreviousRound,
        ReceiveSignatureSharesWithoutPreviousRound,
        ReceiveSignatureShares,
    }

    struct TestInput<'a> {
        round: ComputationRound,
        expected_error: MusigError,
        pubkeys: &'a [PublicKey<Bn256>],
        position: usize,
        private_key: Option<&'a PrivateKey<Bn256>>,
        message: Option<&'a [u8]>,
        signature_shares: Option<&'a [Fs]>,
    }

    impl<'a> std::fmt::Debug for TestInput<'a>{
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result{
            f.debug_struct("TestInput")
            .field("round", &self.round)
            .field("expected error", &self.expected_error)
            .finish()
        }
    }

    let number_of_parties = 2;
    let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let (privkeys, pubkeys, _) = musig_test_bn256_setup(number_of_parties).unwrap();

    let generator = FixedGenerators::SpendingKeyGenerator;
    let rescue_params = franklin_crypto::rescue::bn256::Bn256RescueParams::new_checked_2_into_1();

    let inputs = vec![
        TestInput {
            round: ComputationRound::Setup,
            expected_error: MusigError::InvalidPubkeyLength,
            pubkeys: &[],
            position: 0,
            private_key: None,
            message: None,
            signature_shares: None,
        },
        TestInput {
            round: ComputationRound::Setup,
            expected_error: MusigError::InvalidParticipantPosition,
            pubkeys: &pubkeys,
            position: number_of_parties + 1,
            private_key: None,
            message: None,
            signature_shares: None,
        },
        TestInput {
            round: ComputationRound::ReceivePreCommitmentsWithoutPreviousRound,
            expected_error: MusigError::NonceCommitmentNotGenerated,
            pubkeys: &pubkeys,
            position: 0,
            private_key: None,
            message: None,
            signature_shares: None,
        },
        TestInput {
            round: ComputationRound::ReceivePreCommitments,
            expected_error: MusigError::NoncePreCommitmentsAndParticipantsNotMatch,
            pubkeys: &pubkeys,
            position: 0,
            private_key: None,
            message: None,
            signature_shares: None,
        },
        TestInput {
            round: ComputationRound::ReceiveCommitmentsWithoutPreviousRound,
            expected_error: MusigError::NoncePreCommitmentsNotReceived,
            pubkeys: &pubkeys,
            position: 0,
            private_key: None,
            message: None,
            signature_shares: None,
        },
        TestInput {
            round: ComputationRound::ReceiveCommitments,
            expected_error: MusigError::NonceCommitmentsAndParticipantsNotMatch,
            pubkeys: &pubkeys,
            position: 0,
            private_key: None,
            message: None,
            signature_shares: None,
        },
        TestInput {
            round: ComputationRound::SignWithoutPreviousRound,
            expected_error: MusigError::NonceCommitmentsNotReceived,
            pubkeys: &pubkeys,
            position: 0,
            private_key: Some(&privkeys[0]),
            message: Some(&[1, 2, 3]),
            signature_shares: None,
        },
        TestInput {
            round: ComputationRound::ReceiveSignatureSharesWithoutPreviousRound,
            expected_error: MusigError::ChallengeNotGenerated,
            pubkeys: &pubkeys,
            position: 0,
            private_key: Some(&privkeys[0]),
            message: Some(&[1, 2, 3]),
            signature_shares: Some(&[]),
        },
        TestInput {
            round: ComputationRound::ReceiveSignatureShares,
            expected_error: MusigError::SignatureShareAndParticipantsNotMatch,
            pubkeys: &pubkeys,
            position: 0,
            private_key: Some(&privkeys[0]),
            message: Some(&[1, 2, 3]),
            signature_shares: Some(&[]),
        },
    ];

    for input in inputs {
        match input.round {
            ComputationRound::Setup => {
                let result = MuSigSigner::new(
                    input.pubkeys,
                    input.position,
                    AltJubjubBn256::new(),
                    generator,
                );
                match result {
                    Err(e) => assert_eq!(e, input.expected_error),
                    _ => panic!("expected error not received for {:?} received success", input),
                }
            }
            ComputationRound::ReceivePreCommitmentsWithoutPreviousRound => {
                let mut signer = MuSigSigner::new(
                    input.pubkeys,
                    input.position,
                    AltJubjubBn256::new(),
                    generator,
                )
                .unwrap();
                let result = signer.receive_precommitments(&[]);
                match result {
                    Err(e) => assert_eq!(e, input.expected_error),
                    _ => panic!("expected error not received for {:?}", input),
                }
            }
            ComputationRound::ReceivePreCommitments => {
                let mut signer = MuSigSigner::new(
                    input.pubkeys,
                    input.position,
                    AltJubjubBn256::new(),
                    generator,
                )
                .unwrap();
                let _ = signer.compute_precommitment(rng).unwrap();
                let result = signer.receive_precommitments(&[]);
                match result {
                    Err(e) => assert_eq!(e, input.expected_error),
                    _ => panic!("expected error not received for {:?}", input),
                }
            }
            ComputationRound::ReceiveCommitmentsWithoutPreviousRound => {
                let mut signer = MuSigSigner::new(
                    input.pubkeys,
                    input.position,
                    AltJubjubBn256::new(),
                    generator,
                )
                .unwrap();
                let result = signer.receive_commitments(&[]);
                match result {
                    Err(e) => assert_eq!(e, input.expected_error),
                    _ => panic!("expected error not received for {:?}", input),
                }
            }
            ComputationRound::ReceiveCommitments => {
                let mut signer = MuSigSigner::new(
                    input.pubkeys,
                    input.position,
                    AltJubjubBn256::new(),
                    generator,
                )
                .unwrap();
                let pre_commitment = signer.compute_precommitment(rng).unwrap();
                let _ = signer
                    .receive_precommitments(&[pre_commitment.clone(), pre_commitment])
                    .unwrap();
                let result = signer.receive_commitments(&[]);
                match result {
                    Err(e) => assert_eq!(e, input.expected_error),
                    _ => panic!("expected error not received for {:?}", input),
                }
            }
            ComputationRound::SignWithoutPreviousRound => {
                let mut signer = MuSigSigner::new(
                    input.pubkeys,
                    input.position,
                    AltJubjubBn256::new(),
                    generator,
                )
                .unwrap();
                let pre_commitment = signer.compute_precommitment(rng).unwrap();
                let _ = signer
                    .receive_precommitments(&[pre_commitment.clone(), pre_commitment])
                    .unwrap();
                let result = signer.sign(
                    input.private_key.unwrap(),
                    input.message.unwrap(),
                    &rescue_params,
                );
                match result {
                    Err(e) => assert_eq!(e, input.expected_error),
                    _ => panic!("expected error not received for {:?}", input),
                }
            }
            ComputationRound::ReceiveSignatureSharesWithoutPreviousRound => {
                let mut signer = MuSigSigner::new(
                    input.pubkeys,
                    input.position,
                    AltJubjubBn256::new(),
                    generator,
                )
                .unwrap();
                let pre_commitment = signer.compute_precommitment(rng).unwrap();
                let commitment = signer
                    .receive_precommitments(&[pre_commitment.clone(), pre_commitment])
                    .unwrap();
                let _ = signer
                    .receive_commitments(&[commitment, commitment])
                    .unwrap();
                let result = signer.receive_signatures(&[]);
                match result {
                    Err(e) => assert_eq!(e, input.expected_error),
                    _ => panic!("expected error not received for {:?}", input),
                }
            }
            ComputationRound::ReceiveSignatureShares => {
                let mut signer = MuSigSigner::new(
                    input.pubkeys,
                    input.position,
                    AltJubjubBn256::new(),
                    generator,
                )
                .unwrap();
                let pre_commitment = signer.compute_precommitment(rng).unwrap();
                let commitment = signer
                    .receive_precommitments(&[pre_commitment.clone(), pre_commitment])
                    .unwrap();
                let _ = signer
                    .receive_commitments(&[commitment, commitment])
                    .unwrap();
                let _ = signer
                    .sign(
                        input.private_key.unwrap(),
                        input.message.unwrap(),
                        &rescue_params,
                    )
                    .unwrap();
                let result = signer.receive_signatures(input.signature_shares.unwrap());
                match result {
                    Err(e) => assert_eq!(e, input.expected_error),
                    _ => panic!("expected error not received for {:?}", input),
                }
            }
        }
    }
}
