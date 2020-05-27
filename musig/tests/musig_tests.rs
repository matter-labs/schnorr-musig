mod musig_tests {
    use bellman::pairing::bn256::Bn256;
    use franklin_crypto::alt_babyjubjub::{AltJubjubBn256, FixedGenerators};
    use franklin_crypto::eddsa::Signature;
    use franklin_crypto::eddsa::{PrivateKey, PublicKey, Seed};
    use musig::musig::MusigSession;
    use musig::musig_hasher::{DefaultHasher, create_default_hasher};
    use musig::musig_verifier::MusigVerifier;
    use rand::{thread_rng, Rng};

    type E = Bn256;

    fn create_sessions(
        rng: &mut impl Rng,
        n: usize,
        generator: FixedGenerators,
        params: &AltJubjubBn256,
        hasher: &DefaultHasher<E>,
    ) -> (Vec<MusigSession<E, DefaultHasher<E>>>, Vec<PrivateKey<E>>) {
        let mut participants_sk: Vec<PrivateKey<E>> = Vec::new();
        let mut participants_pk: Vec<PublicKey<E>> = Vec::new();

        // Everybody generates key pairs
        for _ in 0..n {
            let sk = PrivateKey::<E>(rng.gen());

            let pk: PublicKey<E> = PublicKey::from_private(&sk, generator, &params);

            participants_sk.push(sk);
            participants_pk.push(pk);
        }

        // Everybody creates MusigSession
        let mut sessions: Vec<MusigSession<E, DefaultHasher<E>>> = Vec::new();

        for i in 0..n {
            let participants_copy: Vec<PublicKey<E>> = participants_pk.clone();

            let seed = Seed::<Bn256>(rng.gen());

            let session: MusigSession<E, DefaultHasher<E>> = MusigSession::new(
                hasher.clone(),
                generator,
                params,
                participants_copy,
                seed,
                i,
            )
            .expect("");

            sessions.push(session);
        }

        (sessions, participants_sk)
    }

    fn sign_random_message(
        sessions: &mut [MusigSession<E, DefaultHasher<E>>],
        n: usize,
        participants_sk: &[PrivateKey<E>],
        params: &AltJubjubBn256,
    ) -> (Signature<E>, PublicKey<E>, Vec<u8>) {
        let rng = &mut thread_rng();

        let aggregated_public_key = sessions[0].get_aggregated_public_key().clone();

        // Checking that each party ended up deriving the same key
        for i in 1..n {
            let key = sessions[i].get_aggregated_public_key();

            assert!(key.0.eq(&aggregated_public_key.0))
        }

        // Commitments exchange stage
        for i in 0..n {
            let t = sessions[i].get_t().to_vec();

            for (j, session) in sessions.iter_mut().enumerate() {
                if j == i {
                    continue;
                }

                session.set_t(&t, i).expect("");
            }
        }

        // Reveal stage
        for i in 0..n {
            let r_pub = sessions[i].get_r_pub().clone();

            for (j, session) in sessions.iter_mut().enumerate() {
                if j == i {
                    continue;
                }

                session.set_r_pub(r_pub.clone(), i, &params).expect("");
            }
        }

        let mut size = rng.gen();
        size = size % 1024 + 32;

        let mut msg: Vec<u8> = vec![0; size];
        rng.fill_bytes(&mut msg);

        let mut s = Vec::new();

        for i in 0..n {
            s.push(
                (&mut sessions[i])
                    .sign(&participants_sk[i], &msg)
                    .expect(""),
            );
        }

        let signature = sessions[0].aggregate_signature(&s).expect("");

        for i in 0..n {
            let signature1 = sessions[i].aggregate_signature(&s).expect("");

            assert!(signature.r.eq(&signature1.r));
            assert!(signature.s.eq(&signature1.s));
        }

        (signature, aggregated_public_key, msg)
    }

    fn verify_message(
        hasher: &DefaultHasher<E>,
        generator: FixedGenerators,
        signature: &Signature<E>,
        aggregated_public_key: &PublicKey<E>,
        msg: &[u8],
        params: &AltJubjubBn256,
        should_verify: bool,
    ) {
        let verifier = MusigVerifier::new(hasher.clone(), generator);

        assert!(
            verifier.verify_signature(&signature, &msg, &aggregated_public_key, &params)
                == should_verify
        );
    }

    fn sign_and_verify_random_message(n: usize) {
        let hasher = create_default_hasher();

        let params = AltJubjubBn256::new();
        let generator = FixedGenerators::SpendingKeyGenerator;

        let mut rng = &mut thread_rng();

        let (mut sessions, participants_sk) =
            create_sessions(&mut rng, n, generator, &params, &hasher);

        let (signature, aggregated_public_key, msg) =
            sign_random_message(&mut sessions, n, &participants_sk, &params);

        verify_message(
            &hasher,
            generator,
            &signature,
            &aggregated_public_key,
            &msg,
            &params,
            true,
        );
    }

    fn sign_incorrect_private_key_and_verify_random_message(n: usize) {
        let hasher = create_default_hasher();

        let params = AltJubjubBn256::new();
        let generator = FixedGenerators::SpendingKeyGenerator;

        let mut rng = &mut thread_rng();

        let (mut sessions, mut participants_sk) =
            create_sessions(&mut rng, n, generator, &params, &hasher);

        participants_sk[0] = PrivateKey::<E>(rng.gen());

        let (signature, aggregated_public_key, msg) =
            sign_random_message(&mut sessions, n, &participants_sk, &params);

        verify_message(
            &hasher,
            generator,
            &signature,
            &aggregated_public_key,
            &msg,
            &params,
            false,
        );
    }

    #[test]
    fn sign_verify__5_signers__should_verify() {
        sign_and_verify_random_message(5);
    }

    #[test]
    fn sign_verify__1_signer__should_verify() {
        sign_and_verify_random_message(1);
    }

    #[test]
    fn sign_verify__1_signer_invalid_private_key__should_not_verify() {
        sign_incorrect_private_key_and_verify_random_message(1);
    }

    #[test]
    fn sign_verify__5_signers_invalid_private_key__should_not_verify() {
        sign_incorrect_private_key_and_verify_random_message(5);
    }
}
