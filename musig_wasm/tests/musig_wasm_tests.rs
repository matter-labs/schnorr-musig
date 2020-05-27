mod musig_wasm_tests {
    use byte_slice_cast::*;
    use hex;
    use musig_wasm::builder::Builder;
    use musig_wasm::musig_wasm::init;
    use musig_wasm::musig_wasm::MusigWasm;
    use musig_wasm::signature_verifier::SignatureVerifier;
    use musig_wasm::utils::Utils;
    use rand::{thread_rng, Rng};

    fn create_sessions(rng: &mut impl Rng, msg: &[u8], n: usize) -> (Vec<MusigWasm>, Vec<Vec<u8>>) {
        let mut participants_sk: Vec<Vec<u8>> = Vec::new();
        let mut participants_pk: Vec<Vec<u8>> = Vec::new();

        // Everybody generates key pairs
        for _ in 0..n {
            let mut seed = [0u8; 32];

            rng.fill_bytes(&mut seed);

            let s = seed.as_slice_of::<usize>().expect("");

            let sk = Utils::generate_private_key(s).expect("");

            let pk = Utils::extract_public_key(&sk).expect("");

            participants_sk.push(sk);
            participants_pk.push(pk);
        }

        // Everybody creates MusigSession
        let mut sessions: Vec<MusigWasm> = Vec::new();

        for i in 0..n {
            let mut builder = Builder::new();

            builder.derive_seed(&participants_sk[i], msg).expect("");

            for j in 0..n {
                builder
                    .add_participant(&participants_pk[j], i == j)
                    .expect("");
            }

            sessions.push(builder.build().expect(""));
        }

        (sessions, participants_sk)
    }

    fn sign_and_verify_random_message(n: usize) {
        init();
        let mut rng = &mut thread_rng();

        let mut size = rng.gen();
        size = size % 1024 + 32;

        let mut msg: Vec<u8> = vec![0; size];
        rng.fill_bytes(&mut msg);

        let (mut sessions, participants_sk) = create_sessions(&mut rng, &msg, n);

        let aggregated_public_key = sessions[0].get_aggregated_public_key().expect("");

        // Checking that each party ended up deriving the same key
        for i in 1..n {
            let key = sessions[i].get_aggregated_public_key().expect("");

            assert_eq!(&key, &aggregated_public_key)
        }

        // Commitments exchange stage
        for i in 0..n {
            let t = sessions[i].get_t();

            for (j, session) in sessions.iter_mut().enumerate() {
                if i == j {
                    continue;
                }

                session.set_t(&t, i).expect("");
            }
        }

        // Reveal stage
        for i in 0..n {
            let r_pub = sessions[i].get_r_pub().expect("");

            for (j, session) in sessions.iter_mut().enumerate() {
                if i == j {
                    continue;
                }
                session.set_r_pub(&r_pub, i).expect("");
            }
        }

        let mut signatures = Vec::new();

        for i in 0..n {
            signatures.push(
                (&mut sessions[i])
                    .sign(&participants_sk[i], &msg)
                    .expect(""),
            );
        }

        let mut signature_aggregator = sessions.pop().expect("").build_signature_aggregator();

        for i in 0..n {
            signature_aggregator
                .add_signature(&signatures[i])
                .expect("")
        }

        let signature = signature_aggregator.get_signature().expect("");

        let verifier = SignatureVerifier::new();

        let verified = verifier
            .verify(&msg, &aggregated_public_key, &signature)
            .expect("");

        assert!(verified);
    }

    #[test]
    fn sign_verify__5_signers__should_verify() {
        sign_and_verify_random_message(5);
    }

    #[test]
    fn sign_verify__1_signer__should_verify() {
        sign_and_verify_random_message(1);
    }

    struct TestVector {
        sk0: &'static str,
        pk0: &'static str,
        sk1: &'static str,
        pk1: &'static str,
        msg: &'static str,
        aggregated_public_key: &'static str,
        signature: &'static str,
    }

    const TEST_VECTOR: TestVector = TestVector {
        sk0: "044c156ef61990630687ebb4e548aabe4f9abd9ed167dc4c5e71cd5be03c37e8",
        pk0: "5bb0e3df7aa8d54518e48f14b111704010281548771b3df008fa558cc5c8d823",
        sk1: "05f15a1943b5aa8cc419f1e17c0273362d0f3a57e8c9d01b714c1fb5a965f4a9",
        pk1: "a3930da46c0b3498036742337b98f8cdb8dc97e8cce1699104751bbbd9f0e12b",
        msg: "66bd9927abe858eaea7f81201f101e83705c2b409dfb03c0ad2c0cda74bc13b6b9d87294fad70344131a0ea6f7f8f313c4478752774b187057063d1cc1083dc751bc6e938bd72661358012accf44bd9bfec4fef8f464f099dce83bc16b2951f13997de2da8a2fc5ce8edd0e01d23974ed18029f5085d5664a2310939058f42e7756729617ae4e9889056d71ddd734c1a59d92906c513486c1e159179d7073f874c34fac306980a6a36e36d56880a6fa097cb0eab94db02484ff69e124c29518eda0a2b7f0664607b2044448541d6c5934d40dadd694272e6f980540e3192c3476c4ad35c6934aa8bda413847687a0544fd93d4e1c725f6b98e0bb4fcc59a4d84ea4b94eb96163efe9f544ff0195b029c36d09935209d57c04850f1979b089bf4cd984492bc4d73baddd0021ae0035be0d6ed29cba36b4ddbecd89a379a35a8333e9b9284984a1c009ebbea8a0bd8335bb3303e0f5bb5f4ebfa0c6912b1597ab44ee005badf2183fa7747022b6bba1e999c92ede54f8d3bd938bd7a70e84381639c13659f23fa3270a97d27d01202180da2623b7dd9d10f33cc3d528b7a719955f6c0e376347e9ab8b828c2ff654417577e1894c0a32835ebc9fd47a3f78ea55d5b2a181a0034a2c5851ffb40c1ee22c4674307233c3032c9b968deb85014f2de499070fd12d4c3a09b541b821f1794ced1e46abbd77d0557a9347161fc817115fe63c4be5f6ba2798a08786be748ac98610e03a4e37368c5d61718cd1181bbe20904608cac1f7b804bed107c1c6c65d372cd7b80f78c6a323e4f9d2efae95205375c269766393c3fd56725154e79b3fa6d483a13",
        aggregated_public_key: "965592669ada2addb8db779e11251c5065f3ea64d798be6d78d71f8f1ff5d88a",
        signature: "965592669ada2addb8db779e11251c5065f3ea64d798be6d78d71f8f1ff5d88aa1a0689d3676dcaf41fd9bb08877e05d9745a54dc1fdfc89b17ba324c9cd22128feaf9c11620e364d2a210556095d40aa1933fbb3ea0b9852f472df13b439302",
    };

    #[test]
    fn sign__test_vectors__should_match() {
        init();

        let mut builder0 = Builder::new();
        builder0
            .derive_seed(
                &hex::decode(TEST_VECTOR.sk0).expect(""),
                &hex::decode(TEST_VECTOR.msg).expect(""),
            )
            .expect("");

        builder0
            .add_participant(&hex::decode(TEST_VECTOR.pk0).expect(""), true)
            .expect("");
        builder0
            .add_participant(&hex::decode(TEST_VECTOR.pk1).expect(""), false)
            .expect("");
        let mut session0 = builder0.build().expect("");

        let mut builder1 = Builder::new();
        builder1
            .derive_seed(
                &hex::decode(TEST_VECTOR.sk1).expect(""),
                &hex::decode(TEST_VECTOR.msg).expect(""),
            )
            .expect("");

        builder1
            .add_participant(&hex::decode(TEST_VECTOR.pk0).expect(""), false)
            .expect("");
        builder1
            .add_participant(&hex::decode(TEST_VECTOR.pk1).expect(""), true)
            .expect("");
        let mut session1 = builder1.build().expect("");

        assert_eq!(session0.get_self_index(), 0);
        assert_eq!(session1.get_self_index(), 1);

        assert_eq!(
            session0.get_aggregated_public_key().expect(""),
            hex::decode(TEST_VECTOR.aggregated_public_key).expect("")
        );
        assert_eq!(
            session0.get_aggregated_public_key().expect(""),
            session1.get_aggregated_public_key().expect("")
        );

        session1.set_t(&session0.get_t(), 0).expect("");
        session0.set_t(&session1.get_t(), 1).expect("");

        session1
            .set_r_pub(&session0.get_r_pub().expect(""), 0)
            .expect("");
        session0
            .set_r_pub(&session1.get_r_pub().expect(""), 1)
            .expect("");

        let s0 = session0
            .sign(
                &hex::decode(TEST_VECTOR.sk0).expect(""),
                &hex::decode(TEST_VECTOR.msg).expect(""),
            )
            .expect("");
        let s1 = session1
            .sign(
                &hex::decode(TEST_VECTOR.sk1).expect(""),
                &hex::decode(TEST_VECTOR.msg).expect(""),
            )
            .expect("");

        let mut aggregator0 = session0.build_signature_aggregator();
        aggregator0.add_signature(&s0).expect("");
        aggregator0.add_signature(&s1).expect("");
        let signature0 = aggregator0.get_signature().expect("");

        let mut aggregator1 = session1.build_signature_aggregator();
        aggregator1.add_signature(&s0).expect("");
        aggregator1.add_signature(&s1).expect("");
        let signature1 = aggregator1.get_signature().expect("");

        assert_eq!(signature0, signature1);
        assert_eq!(signature0, hex::decode(TEST_VECTOR.signature).expect(""));
    }
}
