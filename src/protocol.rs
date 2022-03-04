extern crate console_error_panic_hook;

use wasm_bindgen::prelude::*;

use std::sync::Arc;
use std::cell::RefCell;

use libsignal_protocol::*;
use rand::rngs::OsRng;

use crate::crypto::*;

pub struct ProtocolInner {
    secret_key: String,
    store: RefCell<Option<InMemSignalProtocolStore>>
}

#[wasm_bindgen]
pub struct Protocol {
    inner: Arc<ProtocolInner>
}

#[wasm_bindgen]
impl Protocol {
    #[wasm_bindgen(constructor)]
    pub fn new(secret_key: String) -> Protocol {
        console_error_panic_hook::set_once();

        Protocol {
            inner: Arc::new(ProtocolInner {
                secret_key: secret_key,
                store: RefCell::new(None)
            })
        }
    }

    // TODO: init function with secret_key

    pub fn register(&self, user_id: String) -> () {
        let mut csprng = OsRng;

        let identity_key = IdentityKeyPair::generate(&mut csprng);

        let store = InMemSignalProtocolStore::new(identity_key, 1).unwrap();

        self.inner.store.replace(Some(store));
        let address = ProtocolAddress::new(user_id.to_owned(), 1);
        println!("{:?}", address);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol() {
        let protocol = Protocol::new();
        protocol.register("e3e82154-1a7b-427f-a537-954770fd7cc6");

        assert!(true);
    }
}

