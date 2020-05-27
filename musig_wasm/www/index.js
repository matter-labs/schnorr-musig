import * as wasm from "musig_wasm";
import {MusigWasmVerifier, MusigWasm, MusigWasmBuilder} from "musig_wasm";

console.log("Start");

wasm.init();

console.log("Init");

const n = 5;

let privateKeys = [];
let publicKeys = [];

for (let i = 0; i < n; i++) {
    let array = new Uint32Array(8);
    window.crypto.getRandomValues(array);
    let privateKey = wasm.MusigWasmUtils.generatePrivateKey(array);
    let publicKey = wasm.MusigWasmUtils.extractPublicKey(privateKey);

    privateKeys.push(privateKey);
    publicKeys.push(publicKey);
}

console.log("Generated keys");

let sessions = new Array(MusigWasm.prototype); // Lol, what?
sessions.pop();

let msg = new Uint8Array(128);
window.crypto.getRandomValues(msg);

for (let i = 0; i < n; i++) {
    let builder = new MusigWasmBuilder();
    for (let j = 0; j < n; j++) {
        builder.addParticipant(publicKeys[j], i === j);
    }

    builder.deriveSeed(privateKeys[i], msg);

    sessions.push(builder.build());
}

console.log("Generated sessions");

let aggregatedPublicKey = sessions[0].getAggregatedPublicKey();

for (let i = 0; i < n; i++) {
    let session = sessions[i];

    for (let j = 0; j < n; j++) {
        if (i === j) {
            continue;
        }

        sessions[j].setT(session.getT(), i);
    }
}

console.log("Set commitments");

for (let i = 0; i < n; i++) {
    let session = sessions[i];

    for (let j = 0; j < n; j++) {
        if (i === j) {
            continue;
        }

        sessions[j].setRPub(session.getRPub(), i);
    }
}

console.log("Set r_pub");

let signatures = [];

for (let i = 0; i < n; i++) {
    signatures.push(sessions[i].sign(privateKeys[i], msg));
}

let aggregator = sessions[0].buildSignatureAggregator();

for (let i = 0; i < n; i++) {
    aggregator.addSignature(signatures[i]);
}

let signature = aggregator.getSignature();

console.log("Aggregated signature");

let verifier = new MusigWasmVerifier();

let verified = verifier.verify(msg, aggregatedPublicKey, signature);

console.log(verified);