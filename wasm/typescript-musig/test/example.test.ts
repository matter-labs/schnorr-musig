import { expect } from "chai";
import * as crypto from "crypto";
import { utils } from "ethers";

import { MusigBN256WasmVerifier } from "musig-bindings";
import { MusigSigner } from "../src/signer";
import { privateKeyFromSeed, private_key_to_pubkey } from "zksync-crypto";

describe("Schnorr-MuSig", () => {
    const NUM_MESSAGES = 3;
    const NUM_BYTES = 32;
    const NUM_PARTICIPANTS = 3;
    const messages = [
        new Uint8Array(Buffer.from("first")),
        new Uint8Array(Buffer.from("second")),
        new Uint8Array(Buffer.from("third")),
    ];

    const privkeys = [];
    const pubkeys = [];
    const signers = [];

    // we will use them during MPC
    const precommitments = [];
    const commitments = [];
    const aggregatedCommitments = [];
    const challenges = [];
    const signatureShares = [];
    const aggregatedSignatures = [];

    before(() => {
        for (let i = 0; i < NUM_PARTICIPANTS; i++) {
            privkeys[i] = privateKeyFromSeed(new Uint8Array(Buffer.from(crypto.randomBytes(NUM_BYTES))));
            pubkeys[i] = private_key_to_pubkey(privkeys[i]);
        }

        for (let i = 0; i < NUM_PARTICIPANTS; i++) {
            signers[i] = new MusigSigner(i, pubkeys);
        }

        for (let i = 0; i < NUM_MESSAGES; i++) {
            signatureShares.push([]);
            aggregatedSignatures.push([]);
        }
    });

    it("should compute aggregated pubkey from pubkey list", () => {
        const aggregatedPubkey = signers[0].computePubkey(pubkeys);
    });

    it("should compute pre commitments", () => {
        // each party should compute his own commitment and send hash of it to other parties
        for (let i = 0; i < NUM_PARTICIPANTS; i++) {
            precommitments[i] = signers[i].computePrecommitment();
        }
    });
    it("should receive pre-commitments and return commitments", () => {
        // each party should send revealed commitment to other parties
        for (let i = 0; i < NUM_PARTICIPANTS; i++) {
            commitments[i] = signers[i].receivePrecommitments(precommitments);
        }
    });
    it("should receive commitments and return aggregated commitments", () => {
        // each party should receive and verify other parties' commitments
        // if any of them are invalid then protcol fails
        for (let i = 0; i < NUM_PARTICIPANTS; i++) {
            aggregatedCommitments[i] = signers[i].receiveCommitments(commitments);
        }
        // we expect all commitments to be the same
        for (let i = 1; i < NUM_PARTICIPANTS; i++) {
            expect(aggregatedCommitments[i]).to.deep.eq(aggregatedCommitments[0]);
        }
    });
    it("should compute signature share", () => {
        // each party should produce his own signature share
        for (let j = 0; j < NUM_MESSAGES; j++) {
            let result: any;
            for (let i = 0; i < NUM_PARTICIPANTS; i++) {
                result = signers[i].sign(privkeys[i], messages[j]);
                signatureShares[j][i] = result.signatureShare;
            }
            challenges[j] = result.challenge;
        }
    });
    it("should receive each signature shares", () => {
        // each party should receive and verify other partie's signature shares
        // if any of them are invalid then protocol fails.
        for (let j = 0; j < NUM_MESSAGES; j++) {
            for (let i = 0; i < NUM_PARTICIPANTS; i++) {
                aggregatedSignatures[j][i] = signers[i].receiveSignatureShares(signatureShares[j], challenges[j]);
            }
        }
        // we expect all signature shares to be the same
        for (let j = 0; j < NUM_MESSAGES; j++) {
            for (let i = 1; i < NUM_PARTICIPANTS; i++) {
                expect(aggregatedSignatures[j][i]).to.deep.eq(aggregatedSignatures[j][0]);
            }
        }
    });
    it("should verify each aggregated signatures", () => {
        // since all signatures are same we do not need to verify each of them.
        // verification of one of them is enough.
        // loop is redundant
        const allPubkeys = utils.concat(pubkeys);
        for (let j = 0; j < NUM_MESSAGES; j++) {
            for (let i = 0; i < NUM_PARTICIPANTS; i++) {
                const valid = MusigBN256WasmVerifier.verify(messages[j], allPubkeys, aggregatedSignatures[j][i]);
                expect(valid).to.be.true;
            }
        }
    });
});
