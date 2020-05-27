## Rust "Simple Schnorr Multi-Signatures"

## Paper
https://eprint.iacr.org/2018/068.pdf

## Usage

Preliminaries:
 - Each signer owns static key pair which will be used for this signature
 - Each signer knows public keys of other signers
 - Each signer is given unique index (0 <= index < n, n - number of signers)
 - Signers agreed on common storage (further - server)
 - Signers agreed on message that will be signed
 
## Flow:

- [Rust](./musig/README.md)
- [JS](./musig_wasm/README.md)
