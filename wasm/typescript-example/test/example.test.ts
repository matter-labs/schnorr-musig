import * as chai from "chai";
const expect = chai.expect;
import * as crypto from "crypto";

import { MusigBN256WasmSigner, MusigBN256WasmVerifier, MusigBN256WasmAggregatedPubkey } from "musig-bindings";
import { privateKeyFromSeed, private_key_to_pubkey } from "zksync-crypto";

describe("Schnorr-MuSig", function () {
    this.timeout(10000);

    let message = new Uint8Array(Buffer.from("my message"));

    let privkeys = [];
    let pubkeys = [];
    let signers = [];

    // we will use them during MPC
    let pre_commitments = [];
    let commitments = [];
    let aggregated_commitments = [];
    let signature_shares = [];
    let aggregated_signatures = [];

    let number_of_participants = 3;
    const NUM_BYTES = 32;

    // util function for merging array elements
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

    it("should compute aggregated pubkey from pubkey list", function(){
        let all_pubkeys = merge_array(pubkeys);

        let agg_pubkey = MusigBN256WasmAggregatedPubkey.compute(all_pubkeys);        
    })

    it("should compute pre commitments", function () {
        // each party should compute his own commitment and send hash of it to other parties
        for (let i = 0; i < number_of_participants; i++) {                 
            let seed = crypto.randomFillSync(new Uint32Array(4));
            pre_commitments[i] = signers[i].compute_precommitment(seed);
        }
    });
    it("should receive pre-commitments and return commitments", function () {
        // each party should send revealed commitment to other parties
        let all_pre_commitments = merge_array(pre_commitments);
        for (let i = 0; i < number_of_participants; i++) {
            commitments[i] = signers[i].receive_precommitments(all_pre_commitments);
        }
    });
    it("should receive commitments and return aggregated commitments", function () {
        // each party should receive and verify other parties' commitments
        // if any of them are invalid then protcol fails
        let all_commitments = merge_array(commitments);
        for (let i = 0; i < number_of_participants; i++) {
            aggregated_commitments[i] = signers[i].receive_commitments(all_commitments);
        }
        // we expect each signature should be same
    });
    it("should compute signature share", function () {
        // each party should produce his own signature share
        for (let i = 0; i < number_of_participants; i++) {
            signature_shares[i] = signers[i].sign(privkeys[i], message);
        }
    });
    it("should receive each signature shares", function () {
        // each party should receive and verify other partie's signature shares
        // if any of them are invalid then protocol fails.

        let all_signature_shares = merge_array(signature_shares);
        for (let i = 0; i < number_of_participants; i++) {
            aggregated_signatures[i] = signers[i].receive_signature_shares(all_signature_shares);
        }
        // we expect each signature should be same
    });
    it("should verify each aggregated signatures", function () {
        // since all signatures are same we do not need to verify each of them.
        // verification of one of them is enough.
        // loop is redundant
        let all_pubkeys = merge_array(pubkeys);
        for (let i = 0; i < number_of_participants; i++) {
            let is_valid = MusigBN256WasmVerifier.verify(message, all_pubkeys, aggregated_signatures[i]);
            expect(is_valid).eq(true);
        }
    });
});
