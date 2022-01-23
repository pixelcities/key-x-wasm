extern crate console_error_panic_hook;

use wasm_bindgen::prelude::*;

use libsignal_protocol::*;
use rand::rngs::OsRng;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub fn gen_public_key() -> String {
    let mut csprng = OsRng;

    let signed_pre_key_pair = KeyPair::generate(&mut csprng);
    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();

    let pkey = format!("{:X?}", signed_pre_key_public);

    pkey
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_public_key() {
        let _pkey = gen_public_key();

        assert!(true);
    }
}

