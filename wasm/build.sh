# generate bindings
which wasm-pack || cargo install wasm-pack
wasm-pack build --release --target=nodejs --out-name=musig-bindings --out-dir=musig-bindings
