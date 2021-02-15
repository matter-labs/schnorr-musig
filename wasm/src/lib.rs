pub mod aggregated_pubkey;
mod decoder;
mod errors;
pub mod signer;
#[cfg(test)]
mod tests;
pub mod verifier;

pub use musig::errors::MusigError;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
