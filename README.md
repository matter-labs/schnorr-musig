# Rust and Wasm Implementation of MuSig
This is a Rust implementation of [MuSig](https://eprint.iacr.org/2018/068.pdf) scheme. It also contains generated wasm code and a [typescript-example](https://github.com/matter-labs/schnorr-musig/blob/master/wasm/typescript-example/test/example.test.ts) which illustrates full multi-party signing flow. 

## MuSig 
MuSig is effectively a multi-signature and key-aggregation scheme based on Schnorr Signatures. It provides security in plain public key model.  For overview one can visit [article written by Blockstream](https://blockstream.com/2018/01/23/en-musig-key-aggregation-schnorr-signatures/).

### Protocol 
In order to produce a valid joint signature, each party needs to follow following steps:

1. Signer receives all public keys `[X_1..X_n]` and stores aggregated public key `X'`.
2. Signer generates a randomly sampled secret scalar nonce `r` and stores his committed nonce `R_i = r·B` and returns his computed precommitment `H_Ri = Hash(R_i)`
4. Signer receives pre-commitments `[H_R1..H_Rn]` and reveals his commitment `R_i`.
5. Signer receives commitments `[R_1..R_n]` and reveals aggregated commitment `R` if all pre-commitments match with commitment.
6. Signer computes a Fiat-Shamir challenge scalar c using cryptographically secure RNG
and computes his signature share by blinding the private key `x_i` using the nonce and the challenge: `s_i = r_i + c·x_i`.
7. Signer receive signature shares `[s1..sn]` and computes aggregated signature if all signature shares are valid.
8. Verifier checks the relation: `s·B  ==  R + c·X'` where `B` is group generator.


## Client Broker Communication
- Each client generate his own keypair and sends it public key to the server/broker
- Server collects each parties public-keys and sends a tuple `(list_of_all_public_keys, position)`  to all clients
- Then, signing ceremony starts as follows:
    1. client initializes signer instance by calling ` let signer = MusigBN256WasmSigner.new(all_pubkeys, position)`
    2. client generates a 128-bytes random seed and computes his pre-commitment `let pre_commitment = signers.compute_precommitment(seed)` then sends his pre commitment to the server
    3. server receives and sends all pre commitment to all clients
    4. client reveals his commitment `let commitment = signer.receive_precommitments(all_pre_commitments)` and  sends it to the server
    5. server collects and sends each commitment to all clients(does server also need to aggregate commitments?)
    6. client computes aggregated commitment by calling `let aggregated_commitment = signer.receive_commitments(all_commitments)` and sends it to the server
    7. server collects each aggregated commitment and server sends aggregated commitment ot all clients if each received aggregated commitments are same
    8. client produces signature share `let signature_share = signer.sign(privkeys[i], message)` and sends it to the server
    9. server collects all shares and sends them to all clients
    10. client computes aggregated signature `let aggregated_signature = signer.receive_signature_shares(all_signature_shares)` and sends it to the server
    11. server collects all aggregated signatures and send a "SIGNING CEREMONY FINISHED " message to all clients if all signatures are valid


## Client Broker Communication 1
Musig signing basically consists of four rounds: 
1. All signers send pre-commitments t_i
2. All signers reveal commitments, R_i and all parties verify that t_i = H(R_i)
3. All signers compute and send their signature shares s_i

### Setup
- Each client generate his own keypair and sends it public key to the server/broker
- Server collects each parties public-keys and sends a "SIGNING CEREMONY STARTED" message which containts `(list_of_all_public_keys, position)` to all clients
- Client initializes signer instance by calling `let signer = MusigBN256WasmSigner.new(all_pubkeys, position)`

### Signing

#### Round 1    

    1. client generates a 128-bytes random seed and computes his pre-commitment `let pre_commitment = signers.compute_precommitment(seed)` then sends his pre commitment to the server
    2. server receives and sends all pre commitment to all clients

#### Round 2
    1. client reveals his commitment `let commitment = signer.receive_precommitments(all_pre_commitments)` and  sends it to the server
    2. server collects and sends each commitment to all clients
    3. client computes aggregated commitment by calling `let aggregated_commitment = signer.receive_commitments(all_commitments)` and sends it to the server
    4. server collects each aggregated commitment and server sends aggregated commitment to all clients (check that each agg commitments are same)

#### Round 3
    1. client produces signature share `let signature_share = signer.sign(private_key, message)` and sends it to the server
    2. server collects all shares and sends them to all clients
    3. client computes aggregated signature `let aggregated_signature = signer.receive_signature_shares(all_signature_shares)` and sends it to the server
    11. server collects all aggregated signatures and send a "SIGNING CEREMONY FINISHED " message to all clients (check that each agg signature are same)


## Client Broker Communication 2
### Setup
- Each client generate his own keypair and sends it public key to the server/broker
- Server collects each parties public-keys and sends a message which containts `(list_of_all_public_keys, position)`  to all clients

### Signing
- Then, signing ceremony starts as follows:
    1. client initializes signer instance by calling ` let signer = MusigBN256WasmSigner.new(all_pubkeys, position)`
    2. client generates a 128-bytes random seed and computes his pre-commitment `let pre_commitment = signers.compute_precommitment(seed)` then sends his pre commitment to the server
    3. server receives and sends all pre commitment to all clients
    4. client reveals his commitment `let commitment = signer.receive_precommitments(all_pre_commitments)` and  sends it to the server
    5. **server collects and all commitments, computes aggregated commitments and sends it to all clients**
    8. client produces signature share `let signature_share = signer.sign(privkeys[i], message)` and sends it to the server
    9. server collects all shares and sends them to all clients
    10. client computes aggregated signature `let aggregated_signature = signer.receive_signature_shares(all_signature_shares)` and sends it to the server
    11. server collects all aggregated signatures and send a "SIGNING CEREMONY FINISHED " message to all clients if all signatures are valid



## Rust

### Definitions

#### MuSigSigner

` struct MuSigSigner`  Holds signer related private fields and implement functions for MPC steps.

#### Functions

- `MuSigSigner::new(..) -> Result<Self, MusigError>` instantiates MuSigSigner object.
- `MuSigSigner::compute_precommitment(&mut self, rng: &mut impl Rng) -> Result<Vec<u8>, MusigError>` Pre-commitment is hash of serialized point which computed by multiplication of a randomly generated scalar with generator. rng must be a cryptographically secure one.
- `MuSigSigner::receive_precommitments(&mut self, pre_commitments: &[Vec<u8>]) -> Result<Point<E, Unknown>, MusigError>` Receives pre-commitments of other parties and returns his revealed commitment which is a point in the group. These pre-commitments will be used to validate received revealed commitments in the next step.
- `MuSigSigner::receive_commitments(&mut self, commitments: &[Point<E, Unknown>]) -> Result<Point<E, Unknown>, MusigError>`  Receives revealed commitments and compare them against pre-commitments that received previous step. If all commitments are valid then returns computed aggregated commitment which is sum of all commitments. Each party must produce same aggregated.
 - `MuSigSigner::sign(&mut self, private_key: &PrivateKey<E>, message: &[u8], rescue_params: &<E as RescueEngine>::Params) -> Result<E::Fs, MusigError>` Computes signature share with a challenge 'c'
 - `MuSigSigner::receive_signatures(&self, signature_shares: &[E::Fs]) -> Result<Signature<E>, MusigError> ` Receives signature shares and verifies them. If all signature shares are valid then returns an aggregated signature. Each party must produce same aggregated signature.
- `MuSigSigner::receive_signatures(&self, signature_shares: &[E::Fs]) -> Result<Signature<E>, MusigError>` Receives signature shares and verifies them. If all signature shares are valid then returns an aggregated signature. Each party must produce same aggregated signature.

#### MuSigVerifier

` struct MuSigVerifier`  Implements verification functions

#### Functions

`MuSigVerifier::verify(message: &[u8], pubkeys: &[PublicKey<E>], signature: &Signature<E>, position: usize, jubjub_params: &<E as JubjubEngine>::Params, generator: FixedGenerators, rescue_params: &<E as RescueEngine>::Params) -> Result<bool, MusigError>` Verifies an aggregated signature according to its public keys.

### Tests
```
cargo test --lib -- --nocapture test_musig_multiparty_full_round
```


## WASM

It contains wasm code for MuSig. All functions same with Rust code but inputs need to be serialized.

### Build

```
cd wasm/
./build.sh
```

### Tests

```
cd wasm/
wasm-pack test --release --node
```

## TypeScript

### Build

```
cd wasm/typescript-example
yarn -D && yarn build
```

### Test

```
cd wasm/typescript-example
yarn -D && yarn test
```

### Example Code

A working full round typescript example in a e2e fashion can be found [here](https://github.com/matter-labs/schnorr-musig/blob/master/wasm/typescript-example/test/example.test.ts)

## References

- [Simple Schnorr Multi-Signatures with Applications to Bitcoin](https://eprint.iacr.org/2018/068.pdf)
- [MuSig: A New Multisignature Standard](https://blockstream.com/2018/01/23/en-musig-key-aggregation-schnorr-signatures/)
- [Key Aggregation for Schnorr Signatures](https://blockstream.com/2018/01/23/en-musig-key-aggregation-schnorr-signatures/)
