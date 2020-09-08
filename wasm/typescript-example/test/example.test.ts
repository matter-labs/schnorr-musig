import * as chai from "chai";
const expect = chai.expect;
import * as crypto from "crypto";

import { MusigBN256WasmSigner, MusigBN256WasmVerifier } from "musig-bindings";
import { privateKeyFromSeed, private_key_to_pubkey } from "zksync-crypto";

describe("Schnorr-MuSig", function () {
    this.timeout(10000);

    let privkeys = [];
    let pubkeys = [];
    let signers = [];

    let pre_commitments = [];
    let commitments = [];
    let aggregated_commitments = [];
    let signature_shares = [];
    let aggregated_signatures = [];

    let message = new Uint8Array(Buffer.from("my message"));

    let number_of_participants = 3;
    const NUM_BYTES = 32;

    function merge_array(elements: [][], isSig = false): Uint8Array {
        let buffer_size = isSig ? 2 * NUM_BYTES : NUM_BYTES;
        let buffer = new Uint8Array(number_of_participants * buffer_size);
        for (let i = 0; i < elements.length; i++) {
            buffer.set(elements[i], i * elements[i].length);
        }
        return buffer;
    }

    before(function () {
        for (let i = 0; i < number_of_participants; i++) {
            privkeys[i] = privateKeyFromSeed(new Uint8Array(Buffer.from(crypto.randomBytes(NUM_BYTES))));
            pubkeys[i] = private_key_to_pubkey(privkeys[i]);
        }

        let all_pubkeys = merge_array(pubkeys);

        for (let i = 0; i < number_of_participants; i++) {
            signers[i] = MusigBN256WasmSigner.new(all_pubkeys, i);
        }
    });

    it("should compute pre commitments", function () {
        for (let i = 0; i < number_of_participants; i++) {
            pre_commitments[i] = signers[i].compute_precommitment(privkeys[i], message);
        }
    });
    it("should receive pre-commitments and return commitments", function () {
        let all_pre_commitments = merge_array(pre_commitments);
        for (let i = 0; i < number_of_participants; i++) {
            commitments[i] = signers[i].receive_precommitments(all_pre_commitments, message);
        }
    });
    it("should receive commitments and return aggregated commitments", function () {
        let all_commitments = merge_array(commitments);
        for (let i = 0; i < number_of_participants; i++) {
            aggregated_commitments[i] = signers[i].receive_commitments(all_commitments);
        }
    });
    it("should compute signature share", function () {
        for (let i = 0; i < number_of_participants; i++) {
            signature_shares[i] = signers[i].sign(privkeys[i], message);
        }
    });

    it("should receive each signature shares", function () {
        let all_signature_shares = merge_array(signature_shares);
        for (let i = 0; i < number_of_participants; i++) {
            aggregated_signatures[i] = signers[i].receive_signature_shares(all_signature_shares);
        }
    });
    it("should verify each aggregated signatures", function () {
        let all_pubkeys = merge_array(pubkeys);
        for (let i = 0; i < number_of_participants; i++) {
            let is_valid = MusigBN256WasmVerifier.verify(message, all_pubkeys, aggregated_signatures[i], i);
            expect(is_valid).eq(true);
        }
    });
});
