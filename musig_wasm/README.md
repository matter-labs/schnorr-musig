## Flow:

1. Each signer (i) creates MusigSession instance
    ```javascript
    import * as wasm from "musig_wasm";
    import {MusigWasmVerifier, MusigWasm, MusigWasmBuilder, MusigHashAlg} from "musig_wasm";
    
    let builder_i = new MusigWasmBuilder();
    for (let j = 0; j < n; j++) {
        builder_i.addParticipant(publicKey_i, i === j);
    }
   
    builder_i.deriveSeed(signerPrivateKey_i, message);
   
    let session_i = builder_i.build();
    ```

1. Get aggregated public key which will be used for verification
    ```javascript
    let aggregatedPublicKey = sessions_i.getAggregatedPublicKey();
    ```
   
   Each signer will get same value from this function

1. Each signer (i) should upload its commitment (t) to the server
    ```javascript
    let t_i = session_i.getT();
    // Send t to the server 
    ```
   
1. Each signer (i) should get commitments (t) from all of other signers
    ```javascript
    for (let j = 0; j < n; j++) {
        if (j === i) {
            continue;
        }
        session_i.setT(t_j, j); 
    }
    ```
   
1. Each signer (i) reveals his R (sends it to the server)
    ```javascript
    let r_pub_i = session_i.getRPub();
    // Send r_pub_i to the server
    ``` 

1. Each signer (i) should get R from all of other signers
    ```javascript
    for (let j = 0; j < n; j++) {
        if (j === i) {
            continue;
        }
        session_i.setRPub(r_pub_j, j); 
    }
    ```
   
1. Each signer (i) produces his part of the signature (s) and pushes it to the server
    ```javascript
    let s_i = session_i.sign(signerPrivateKey_i, message);
    // Send s_i to the server
    ```
   
1. Any (or all) of the signers can now aggregate parts into final signature
    ```javascript
    let aggregator = sessions_i.buildSignatureAggregator();
    for (let i = 0; i < n; i++) {
        aggregator.addSignature(s_i);
    }
    
    let signature = aggregator.getSignature();
    ```
   
1. Signature can now be verified
    ```javascript
    let verifier = new MusigWasmVerifier(MusigHashAlg.SHA256);
    
    let verified = verifier.verify(message, aggregatedPublicKey, signature);
    ```
