#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

mod keystore;
mod protocol;
mod crypto;
mod storage;
mod utils;

pub use libsignal_protocol;

pub use {
    keystore::KeyStore,
    protocol::Protocol,
    storage::PreKeyBundleSerde,
    crypto::*
};

