import { MusigBN256WasmSigner, MusigBN256WasmAggregatedPubkey } from "musig-bindings";
import { utils, BytesLike } from "ethers";
import * as crypto from "crypto";

const LENGTH_IN_BYTES = 32;

export class MusigSigner {
    private signer: MusigBN256WasmSigner;

    constructor(position: number, private pubkeys: BytesLike[]) {
        this.signer = MusigBN256WasmSigner.new(utils.concat(pubkeys), position);
    }

    computePubkey(): Uint8Array {
        return MusigBN256WasmAggregatedPubkey.compute(utils.concat(this.pubkeys));
    }

    computePrecommitment(seed?: Uint32Array): Uint8Array {
        const seed_ = seed || crypto.randomFillSync(new Uint32Array(4));
        return this.signer.compute_precommitment(seed_);
    }

    receivePrecommitments(precommitments: BytesLike[]): Uint8Array {
        return this.signer.receive_precommitments(utils.concat(precommitments));
    }

    receiveCommitments(commitments: BytesLike[]): Uint8Array {
        return this.signer.receive_commitments(utils.concat(commitments));
    }

    sign(privkey: BytesLike, message: BytesLike) {
        const result = this.signer.sign(utils.arrayify(privkey), utils.arrayify(message));
        const signatureShare = result.slice(0, LENGTH_IN_BYTES);
        const challenge = result.slice(LENGTH_IN_BYTES);
        return { signatureShare, challenge };
    }

    receiveSignatureShares(signature_shares: BytesLike[], challenge: BytesLike): Uint8Array {
        return this.signer.receive_signature_shares(utils.concat(signature_shares), utils.arrayify(challenge));
    }
}
