# generate bindings

set -e

which wasm-pack || cargo install wasm-pack

# pack for bundler
wasm-pack build --release --target=bundler --out-name=schnorr-musig-bundler --out-dir=dist

# pack for browser
wasm-pack build --release --target=web --out-name=schnorr-musig-web --out-dir=dist

# pack for node.js
wasm-pack build --release --target=nodejs --out-name=schnorr-musig-node --out-dir=dist

rm dist/package.json
