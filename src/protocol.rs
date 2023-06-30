extern crate base64;
extern crate console_error_panic_hook;

use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use js_sys::{Promise, Date, Error};
use web_sys::console;

use std::sync::Arc;
use std::cell::RefCell;
use std::convert::TryFrom;

use rand::rngs::OsRng;
use libsignal_protocol::*;
use libsignal_protocol::{PreKeyBundle, PreKeySignalMessage, Fingerprint};
use crate::storage::{SyncableStore, PreKeyBundleSerde};

use crate::utils::*;

pub struct ProtocolInner {
    storage: RefCell<Option<SyncableStore>>,
    timeout: RefCell<Option<i32>>,
    message_ids: RefCell<Vec<String>>
}

#[wasm_bindgen]
pub struct Protocol {
    inner: Arc<ProtocolInner>
}

async fn gen_pre_key_bundles(storage: &mut SyncableStore) -> () {
    let mut csprng = OsRng;

    let response = request("GET".to_string(), format!("{}/protocol/bundles", storage.api_basepath), None).await;
    let bundle_id = match response.as_f64() {
        Some(i) => (i as u32) + 1,
        None => 1
    };

    let signed_pre_key_id = 1;
    let signed_pre_key_record = match storage.store.get_signed_pre_key(signed_pre_key_id, None).await {
        Ok(record) => record,
        Err(_) => {
            let signed_pre_key_pair = KeyPair::generate(&mut csprng);

            let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
            let signed_pre_key_signature = storage.store
                .get_identity_key_pair(None).await.unwrap()
                .private_key()
                .calculate_signature(&signed_pre_key_public, &mut csprng).unwrap();

            storage.store.save_signed_pre_key(
                signed_pre_key_id,
                &SignedPreKeyRecord::new(
                    signed_pre_key_id,
                    Date::now() as u64,
                    &signed_pre_key_pair,
                    &signed_pre_key_signature,
                ),
                None
            ).await.unwrap();

            storage.store.get_signed_pre_key(signed_pre_key_id, None).await.unwrap()
        }
    };

    let identity_key = *storage.store.get_identity_key_pair(None).await.unwrap().identity_key();

    for i in bundle_id..bundle_id+5 {
        let pre_key_id = i;
        let pre_key_pair = KeyPair::generate(&mut csprng);

        storage.store.save_pre_key(pre_key_id, &PreKeyRecord::new(pre_key_id, &pre_key_pair), None).await.unwrap();

        let pre_key_bundle: PreKeyBundleSerde = PreKeyBundle::new(
            storage.store.get_local_registration_id(None).await.unwrap(),
            1,
            Some((pre_key_id, pre_key_pair.public_key)),
            signed_pre_key_id,
            signed_pre_key_record.public_key().unwrap(),
            signed_pre_key_record.signature().unwrap(),
            identity_key,
        ).unwrap().into();
        let bundle = base64::encode(pre_key_bundle.serialize());
        let payload = format!("{{\"bundle_id\": {}, \"bundle\": \"{}\" }}", pre_key_id, bundle);

        request("POST".to_string(), format!("{}/protocol/bundles", storage.api_basepath), Some(payload)).await;
    };
}

#[wasm_bindgen]
impl Protocol {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Protocol {
        console_error_panic_hook::set_once();

        Protocol {
            inner: Arc::new(ProtocolInner {
                storage: RefCell::new(None),
                timeout: RefCell::new(None),
                message_ids: RefCell::new(Vec::new())
            })
        }
    }

    pub fn init(&self, secret_key: String, api_basepath: JsValue) -> Promise {
        let _self = self.inner.clone();

        let basepath = if !api_basepath.is_undefined() && api_basepath.is_string() {
            api_basepath.as_string().unwrap()
        } else {
            option_env!("API_BASEPATH").unwrap_or("http://localhost:5000").to_string()
        };

        let done = async move {
            let storage = SyncableStore::new(secret_key, basepath).await;

            _self.storage.replace(Some(storage));

            Ok(JsValue::undefined())
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn register(&self, secret_key: String, api_basepath: JsValue) -> Promise {
        let _self = self.inner.clone();

        let basepath = if !api_basepath.is_undefined() && api_basepath.is_string() {
            api_basepath.as_string().unwrap()
        } else {
            option_env!("API_BASEPATH").unwrap_or("http://localhost:5000").to_string()
        };

        let done = async move {
            let mut storage = SyncableStore::register(secret_key, basepath);

            // Generate and publish some bundles
            gen_pre_key_bundles(&mut storage).await;

            // Share our identity public key
            let identity_key = base64::encode(storage.store.identity_store.get_identity_key_pair(None).await.unwrap().public_key().serialize());

            // Save state
            storage.sync(None).await;

            _self.storage.replace(Some(storage));

            Ok(JsValue::from_str(&identity_key))
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn add_pre_key_bundles(&self) -> Promise {
        let _self = self.inner.clone();

        wasm_bindgen_futures::future_to_promise(async move {
            match _self.storage.try_borrow_mut().map(|mut s| s.take().unwrap()) {
                Ok(mut storage) => {
                    gen_pre_key_bundles(&mut storage).await;
                    storage.sync(None).await;

                    _self.storage.replace(Some(storage));

                    Ok(JsValue::undefined())
                },
                Err(_) => Err(Error::new("Cannot add pre key bundles: storage is already borrowed").into())
            }
        })
    }

    pub fn get_fingerprint(&self, our_id: String, their_id: String) -> Promise {
        let maybe_store = self.inner.storage.try_borrow().map(|s| s.clone()).unwrap_or(None);
        let address = ProtocolAddress::new(their_id.clone(), 1);

        wasm_bindgen_futures::future_to_promise(async move {
            match maybe_store {
                Some(storage) => {
                    let our_identity_key = storage.store.identity_store.get_identity_key_pair(None).await.unwrap().identity_key().clone();

                    match storage.store.identity_store.get_identity(&address, None).await.unwrap() {
                        Some(their_identity_key) => {
                            let fprint = Fingerprint::new(2, 5200, our_id.as_bytes(), &our_identity_key, their_id.as_bytes(), &their_identity_key).unwrap().display;

                            Ok(JsValue::from_str(&fprint.to_string()))
                        },
                        None => Ok(JsValue::undefined())
                    }
                },
                None => Err(Error::new("Cannot get fingerprint: storage is mutably borrowed").into())
            }
        })
    }

    pub fn encrypt(&self, user_id: String, message: String) -> Promise {
        let mut csprng = OsRng;
        let address = ProtocolAddress::new(user_id.clone(), 1);

        let _self = self.inner.clone();
        let done = async move {
            match _self.storage.try_borrow_mut().map(|mut s| s.take().unwrap()) {
                Ok(mut storage) => {
                    // No existing session means we need to fetch a pre_key_bundle
                    if storage.store.session_store.load_session(&address, None).await.unwrap().is_none() {
                        let response = request("GET".to_string(), format!("{}/protocol/bundles/{}", storage.api_basepath, &user_id), None).await; // assume it has a bundle
                        let bundle_id = response.as_f64().unwrap() as u32;

                        let bundle = request("DELETE".to_string(), format!("{}/protocol/bundles/{}/{}", storage.api_basepath, &user_id, &bundle_id), None).await.as_string().unwrap();
                        let pre_key_bundle: PreKeyBundle = PreKeyBundleSerde::deserialize(&base64::decode(&bundle).unwrap()[..]).into();

                        // Create the session
                        process_prekey_bundle(
                            &address,
                            &mut storage.store.session_store,
                            &mut storage.store.identity_store,
                            &pre_key_bundle,
                            &mut csprng,
                            None,
                        ).await.unwrap();
                    }

                    let encrypted = message_encrypt(message.as_bytes(), &address, &mut storage.store.session_store, &mut storage.store.identity_store, None).await.unwrap();

                    _self.storage.replace(Some(storage));

                    Ok(JsValue::from_str(&base64::encode(&encrypted.serialize())))
                },
                Err(_) => Err(Error::new("Cannot encrypt message: storage is already borrowed").into())
            }
        };

        self.schedule_sync();

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn decrypt(&self, user_id: String, message_id: String, message: String) -> Promise {
        let mut csprng = OsRng;
        let address = ProtocolAddress::new(user_id.clone(), 1);

        let _self = self.inner.clone();
        let done = async move {
            let maybe_message_ids = _self.message_ids.try_borrow_mut();
            if maybe_message_ids.is_ok() && !message_id.is_empty() {
                maybe_message_ids.unwrap().push(message_id);
            }

            match _self.storage.try_borrow_mut().map(|mut s| s.take().unwrap()) {
                Ok(mut storage) => {
                    let session_exists = storage.store.session_store.load_session(&address, None).await.unwrap();

                    let bytes = base64::decode(&message).unwrap();
                    let ctext = match session_exists {
                        Some(_) => {
                            // Prekey messages may be queued up, maybe fallback to prekey type
                            match SignalMessage::try_from(&bytes[..]) {
                                Ok(message) => CiphertextMessage::SignalMessage(message),
                                Err(_) => CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(&bytes[..]).unwrap())
                            }
                        },
                        None => CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::try_from(&bytes[..]).unwrap()),
                    };

                    let maybe_decrypted = message_decrypt(
                        &ctext,
                        &address,
                        &mut storage.store.session_store,
                        &mut storage.store.identity_store,
                        &mut storage.store.pre_key_store,
                        &mut storage.store.signed_pre_key_store,
                        &mut csprng,
                        None,
                    ).await;

                    _self.storage.replace(Some(storage));

                    match maybe_decrypted {
                        Ok(decrypted) => {
                            Ok(JsValue::from_str(&String::from_utf8(decrypted).unwrap()))
                        },
                        Err(SignalProtocolError::DuplicatedMessage(_, _)) => {
                            Err(JsValue::from_str(&"DuplicatedMessageError".to_owned()))
                        },
                        Err(e) => {
                            console::log_2(&"Error when decrypting message: ".into(), &e.to_string().into());
                            Err(JsValue::from_str(&"MessageDecryptError".to_owned()))
                        }
                    }
                },
                Err(_) => Err(Error::new("Cannot decrypt message: storage is already borrowed").into())
            }
        };

        self.schedule_sync();

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn sign(&self, message: String) -> Promise {
        let mut csprng = OsRng;
        let maybe_store = self.inner.storage.try_borrow().map(|s| s.clone()).unwrap_or(None);

        wasm_bindgen_futures::future_to_promise(async move {
            match maybe_store {
                Some(storage) => {
                    let priv_key = storage.store.identity_store.get_identity_key_pair(None).await.unwrap().private_key().clone();
                    let signature = priv_key.calculate_signature(message.as_bytes(), &mut csprng).unwrap();

                    Ok(hex::encode(signature).into())
                },
                None => Err(Error::new("Cannot calculate signature: storage is mutably borrowed").into())
            }
        })
    }

    pub fn verify(&self, message: String, signature: String, user_id: JsValue) -> Promise {
        let maybe_store = self.inner.storage.try_borrow().map(|s| s.clone()).unwrap_or(None);

        // Optionally give the user id to verify against. When verifiying our own signature,
        // this should be left empty.
        let address = if !user_id.is_undefined() && user_id.is_string() {
            Some(ProtocolAddress::new(user_id.as_string().unwrap(), 1))
        } else {
            None
        };

        wasm_bindgen_futures::future_to_promise(async move {
            match maybe_store {
                Some(storage) => {
                    let maybe_pub_key = match address {
                        Some(their_address) => {
                            storage.store.identity_store.get_identity(&their_address, None).await.unwrap().map(|x| x.public_key().clone())
                        },
                        None => Some(storage.store.identity_store.get_identity_key_pair(None).await.unwrap().public_key().clone())
                    };

                    match maybe_pub_key {
                        Some(pub_key) => {
                            match hex::decode(signature) {
                                Ok(sig_bytes) => {
                                    match pub_key.verify_signature(message.as_bytes(), &sig_bytes) {
                                        Ok(true) => Ok(true.into()),
                                        _ => Ok(false.into())
                                    }
                                },
                                Err(_) => Err(Error::new("Signature is not in hex").into())
                            }
                        },
                        None => Err(Error::new("Cannot find public key for this user").into())
                    }
                },
                None => Err(Error::new("Cannot verify signature: storage is mutably borrowed").into())
            }
        })
    }

    pub fn sync(&self) -> Promise {
        let maybe_store = self.inner.storage.try_borrow().map(|s| s.clone()).unwrap_or(None);

        let maybe_message_ids = self.inner.message_ids.try_borrow_mut();
        let message_ids = if maybe_message_ids.is_ok() {
            let mut message_ids = maybe_message_ids.unwrap();
            let res = message_ids.clone();
            message_ids.clear();
            res
        } else {
            vec![]
        };

        wasm_bindgen_futures::future_to_promise(async move {
            match maybe_store {
                Some(store) => {
                    store.sync(Some(message_ids)).await;

                    Ok(JsValue::undefined())
                },
                None => Err(Error::new("Cannot sync store: storage is mutably borrowed").into())
            }
        })
    }

    pub fn schedule_sync(&self) -> () {
        let window = web_sys::window().unwrap();

        // Only create a timeout callback when there is no handle to an existing one
        if self.inner.timeout.try_borrow().map(|t| t.is_none()).unwrap_or(false) {
            let _self = self.inner.clone();
            let f = Closure::wrap(Box::new(move || {
                let maybe_message_ids = _self.message_ids.try_borrow_mut();
                let message_ids = if maybe_message_ids.is_ok() {
                    let mut message_ids = maybe_message_ids.unwrap();
                    let res = message_ids.clone();
                    message_ids.clear();
                    res
                } else {
                    vec![]
                };

                match _self.storage.try_borrow().map(|s| s.clone().unwrap()) {
                    Ok(storage) => {
                        // Unset timeout "lock"
                        _self.timeout.try_borrow_mut().map(|mut t| t.take()).ok();

                        let _obj: &js_sys::Object = wasm_bindgen_futures::future_to_promise(async move {
                            storage.sync(Some(message_ids)).await;

                            Ok(JsValue::undefined())
                        }).as_ref();
                    },
                    Err(_) => {}
                };
            }) as Box<dyn FnMut()>);
            let handle = window.set_timeout_with_callback_and_timeout_and_arguments_0(&f.as_ref().unchecked_ref(), 3_000).unwrap();
            self.inner.timeout.try_borrow_mut().map(|mut t| t.replace(handle)).ok();

            // TODO: this leaks memory
            f.forget();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol() {
        let protocol = Protocol::new();

        assert!(true);
    }
}

