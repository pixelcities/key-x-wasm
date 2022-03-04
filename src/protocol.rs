extern crate console_error_panic_hook;

use wasm_bindgen::prelude::*;

use std::sync::Arc;
use std::cell::RefCell;

use libsignal_protocol::*;

// use crate::crypto::*;
use crate::storage::SyncableStore;

pub struct ProtocolInner {
    secret_key: RefCell<Option<String>>,
    store: RefCell<Option<SyncableStore>>
}

#[wasm_bindgen]
pub struct Protocol {
    inner: Arc<ProtocolInner>
}

#[wasm_bindgen]
impl Protocol {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Protocol {
        console_error_panic_hook::set_once();

        Protocol {
            inner: Arc::new(ProtocolInner {
                secret_key: RefCell::new(None),
                store: RefCell::new(None)
            })
        }
    }

    pub fn init(&self, secret_key: String) -> () {
        let store = SyncableStore::new(&secret_key);

        self.inner.secret_key.replace(Some(secret_key));
        self.inner.store.replace(Some(store));
    }

    pub fn register(&self, user_id: String) -> () {
        let store = SyncableStore::register();

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
        protocol.register("e3e82154-1a7b-427f-a537-954770fd7cc6".to_string());

        assert!(true);
    }
}

