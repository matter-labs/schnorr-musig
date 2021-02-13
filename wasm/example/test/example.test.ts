import { expect } from "chai";
import * as crypto from "crypto";
import { utils } from "ethers";

import { MusigBN256WasmSigner, MusigBN256WasmVerifier, MusigBN256WasmAggregatedPubkey } from "musig-bindings";
import { privateKeyFromSeed, private_key_to_pubkey } from "zksync-crypto";

describe("Schnorr-MuSig", () => {
    const message = new Uint8Array(Buffer.from("my message"));

    const privkeys = [];
    const pubkeys = [];
    const signers = [];

    // we will use them during MPC
    const pre_commitments = [];
    const commitments = [];
    const aggregated_commitments = [];
    const signature_shares = [];
    const aggregated_signatures = [];

    const number_of_participants = 3;
    const num_bytes = 32;

    before(() => {
        for (let i = 0; i < number_of_participants; i++) {
            privkeys[i] = privateKeyFromSeed(new Uint8Array(Buffer.from(crypto.randomBytes(num_bytes))));
            pubkeys[i] = private_key_to_pubkey(privkeys[i]);
        }

        const all_pubkeys = utils.concat(pubkeys);

        for (let i = 0; i < number_of_participants; i++) {
            signers[i] = MusigBN256WasmSigner.new(all_pubkeys, i);
        }
    });

    it("should compute aggregated pubkey from pubkey list", () => {
        const all_pubkeys = utils.concat(pubkeys);
        const _agg_pubkey = MusigBN256WasmAggregatedPubkey.compute(all_pubkeys);
    });

    it("should compute pre commitments", () => {
        // each party should compute his own commitment and send hash of it to other parties
        for (let i = 0; i < number_of_participants; i++) {
            const seed = crypto.randomFillSync(new Uint32Array(4));
            pre_commitments[i] = signers[i].compute_precommitment(seed);
        }
    });
    it("should receive pre-commitments and return commitments", () => {
        // each party should send revealed commitment to other parties
        const all_pre_commitments = utils.concat(pre_commitments);
        for (let i = 0; i < number_of_participants; i++) {
            commitments[i] = signers[i].receive_precommitments(all_pre_commitments);
        }
    });
    it("should receive commitments and return aggregated commitments", () => {
        // each party should receive and verify other parties' commitments
        // if any of them are invalid then protcol fails
        const all_commitments = utils.concat(commitments);
        for (let i = 0; i < number_of_participants; i++) {
            aggregated_commitments[i] = signers[i].receive_commitments(all_commitments);
        }
        // we expect all commitments to be the same
        for (let i = 1; i < number_of_participants; i++) {
            expect(aggregated_commitments[i]).to.deep.eq(aggregated_commitments[0]);
        }
    });
    it("should compute signature share", () => {
        // each party should produce his own signature share
        for (let i = 0; i < number_of_participants; i++) {
            signature_shares[i] = signers[i].sign(privkeys[i], message);
        }
    });
    it("should receive each signature shares", () => {
        // each party should receive and verify other partie's signature shares
        // if any of them are invalid then protocol fails.
        const all_signature_shares = utils.concat(signature_shares);
        for (let i = 0; i < number_of_participants; i++) {
            aggregated_signatures[i] = signers[i].receive_signature_shares(all_signature_shares);
        }
        // we expect all signatures to be the same
        for (let i = 1; i < number_of_participants; i++) {
            expect(aggregated_signatures[i]).to.deep.eq(aggregated_signatures[0]);
        }
    });
    it("should verify each aggregated signatures", () => {
        // since all signatures are same we do not need to verify each of them.
        // verification of one of them is enough.
        // loop is redundant
        const all_pubkeys = utils.concat(pubkeys);
        for (let i = 0; i < number_of_participants; i++) {
            const is_valid = MusigBN256WasmVerifier.verify(message, all_pubkeys, aggregated_signatures[i]);
            expect(is_valid).eq(true);
        }
    });
});
