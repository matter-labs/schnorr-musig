use wasm_bindgen::prelude::*;
#[wasm_bindgen]
pub struct MusigUtils;


#[wasm_bindgen]
impl MusigUtils{
    #[wasm_bindgen]
    pub fn generate_keypair(seed: &[u8]){
        println!("seed: {:?}", seed);
    }
}