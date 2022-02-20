extern crate base64;
extern crate hex;
extern crate console_error_panic_hook;

use wasm_bindgen::prelude::*;

use std::str;
use std::sync::Arc;
use std::cell::RefCell;
use std::collections::hash_map::HashMap;

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::*;
use web_sys::{console, Request, RequestInit, RequestCredentials, RequestMode, Response};
use futures_channel::oneshot;
use js_sys::{Promise};

use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use argon2::{password_hash::{PasswordHasher, SaltString, Output}, Argon2, Params, Algorithm, Version};
use aes_gcm_siv::{Aes256GcmSiv, Key as AesKey, Nonce};
use aes_gcm_siv::aead::{Aead, NewAead};

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

pub struct KeyXInner {
    root_key: RefCell<Option<Output>>,
    keys: RefCell<HashMap<String, String>>
}

#[wasm_bindgen]
pub struct KeyX {
    inner: Arc<KeyXInner>
}

fn gen_nonce<T>(csprng: &mut T) -> [u8; 12] where T: CryptoRng + Rng, {
    let mut nonce = [0u8; 12];
    csprng.fill_bytes(&mut nonce);
    nonce
}

fn gen_key<T>(csprng: &mut T) -> [u8; 32] where T: CryptoRng + Rng, {
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);
    key
}

#[wasm_bindgen]
impl KeyX {
    #[wasm_bindgen(constructor)]
    pub fn new() -> KeyX {
        console_error_panic_hook::set_once();

        KeyX { inner: Arc::new(KeyXInner {
            root_key: RefCell::new(None),
            keys: RefCell::new(HashMap::new())
        })}
    }

    pub fn open_sesame(&self, email: String, passphrase: String) -> String {
        let (root_key, hashed_passphrase) = self.derive_keys(email, passphrase);

        self.inner.root_key.replace(root_key);
        hashed_passphrase
    }

    pub fn get_hashed_passphrase(&self, email: String, passphrase: String) -> String {
        let (_, hashed_passphrase) = self.derive_keys(email, passphrase);

        hashed_passphrase
    }

    pub fn is_locked(&self) -> bool {
        let root_key = self.inner.root_key.borrow();
        root_key.is_none()
    }

    pub fn load_keys(&self) -> () {
        let _self = self.inner.clone();

        spawn_local(async move {
            let mut opts = RequestInit::new();
            opts.method("GET");
            opts.mode(RequestMode::Cors);
            opts.credentials(RequestCredentials::Include);

            let request = Request::new_with_str_and_init("http://localhost:5000/keys", &opts).unwrap();

            request
                .headers()
                .set("Accept", "application/json").unwrap();

            let window = web_sys::window().unwrap();
            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.unwrap();

            let resp: Response = resp_value.dyn_into().unwrap();
            let json = JsFuture::from(resp.json().unwrap()).await.unwrap();

            for key in js_sys::try_iter(&json).unwrap().unwrap() {
                let obj = key.unwrap();
                let key_id: String = js_sys::Reflect::get(&obj, &"key_id".into()).unwrap().as_string().unwrap();
                let ciphertext: String = js_sys::Reflect::get(&obj, &"ciphertext".into()).unwrap().as_string().unwrap();

                _self.keys.borrow_mut().insert(key_id, ciphertext);
            }
        });
    }

    pub fn get_key(&self, id: String) -> String {
        match self.inner.keys.borrow().get(&id) {
            Some(key) => {
                self.decrypt_key(key)
            },
            None => panic!("Invalid key id")
        }
    }

    pub fn generate_key(&self) -> Promise {
        let mut csprng = OsRng;

        let _self = self.inner.clone();
        let key = hex::encode(gen_key(&mut csprng));
        let ciphertext = self.encrypt_key(&key);

        let (tx, rx) = oneshot::channel();

        spawn_local(async move {
            let body = format!("{{\"ciphertext\": \"{}\"}}", ciphertext);

            let mut opts = RequestInit::new();
            opts.method("POST");
            opts.mode(RequestMode::Cors);
            opts.credentials(RequestCredentials::Include);
            opts.body(Some(&body.into()));

            let request = Request::new_with_str_and_init("http://localhost:5000/keys", &opts).unwrap();

            request
                .headers()
                .set("Content-Type", "application/json").unwrap();

            let window = web_sys::window().unwrap();
            let resp_value = JsFuture::from(window.fetch_with_request(&request)).await.unwrap();

            let resp: Response = resp_value.dyn_into().unwrap();
            let json = JsFuture::from(resp.json().unwrap()).await.unwrap();

            let key_id: String = js_sys::Reflect::get(&json, &"key_id".into()).unwrap().as_string().unwrap();
            let ciphertext: String = js_sys::Reflect::get(&json, &"ciphertext".into()).unwrap().as_string().unwrap();

            _self.keys.borrow_mut().insert(key_id.clone(), ciphertext);

            drop(tx.send(key_id));
        });

        let done = async move {
            match rx.await {
                Ok(key_id) => Ok(key_id.into()),
                Err(_) => Err(JsValue::undefined()),
            }
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    pub fn rotate_keys(&self, email: String, passphrase: String) -> Promise {
        let mut csprng = OsRng;

        console::log_1(&"Rotating keystore".into());

        let (new_root_key, new_hashed_passphrase) = self.derive_keys(email, passphrase);
        let old_keys = self.inner.keys.borrow().clone();
        let token = base64::encode(gen_nonce(&mut csprng));

        let mut batch = vec![];

        for (key_id, ciphertext) in &old_keys {
            let plaintext = self.decrypt_key(ciphertext);
            let new_ciphertext = self.encrypt_key_custom(&plaintext, new_root_key.unwrap());

            batch.push(format!("{{\"key_id\": \"{}\", \"ciphertext\": \"{}\"}}", key_id, new_ciphertext));
        }

        let payload = format!("{{\"token\": \"{}\", \"keys\": [{}]}}", token, batch.join(","));

        let (tx, rx) = oneshot::channel();

        spawn_local(async move {
            let mut opts = RequestInit::new();
            opts.method("POST");
            opts.mode(RequestMode::Cors);
            opts.credentials(RequestCredentials::Include);
            opts.body(Some(&payload.into()));

            let request = Request::new_with_str_and_init("http://localhost:5000/keys/rotate", &opts).unwrap();

            request
                .headers()
                .set("Content-Type", "application/json").unwrap();

            let window = web_sys::window().unwrap();
            JsFuture::from(window.fetch_with_request(&request)).await.unwrap();

            drop(tx.send((token, new_hashed_passphrase)));
        });

        let done = async move {
            match rx.await {
                Ok((token, new_hashed_passphrase)) => {
                    let obj = js_sys::Object::new();
                    js_sys::Reflect::set(&obj, &"token".into(), &token.into()).unwrap();
                    js_sys::Reflect::set(&obj, &"hashed_passphrase".into(), &new_hashed_passphrase.into()).unwrap();

                    Ok(obj.into())
                },
                Err(_) => Err(JsValue::undefined()),
            }
        };

        wasm_bindgen_futures::future_to_promise(done)
    }

    fn derive_keys(&self, email: String, passphrase: String) -> (Option<Output>, String) {
        // Derive root key
        let root_key = {
            let params = Params::new(4096, 4, 1, Some(32)).unwrap(); // ~ 1250ms
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let salt = SaltString::b64_encode(&email.as_bytes()).unwrap();
            Some(argon2.hash_password(passphrase.as_bytes(), &salt).unwrap().hash.unwrap())
        };

        // Because the root key is based on both the email and passphrase the
        // hash will change when either of the two is mutated. Take care.
        let hashed_passphrase = {
            let params = Params::new(512, 1, 1, Some(32)).unwrap(); // ~ <100ms
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let salt =  SaltString::b64_encode(&passphrase.as_bytes()).unwrap();
            argon2.hash_password(root_key.unwrap().as_bytes(), &salt).unwrap().hash.unwrap()
        };

        (root_key, base64::encode(hashed_passphrase.as_bytes()))
    }

    fn encrypt_key(&self, plaintext: &String) -> String {
        let root_key = self.inner.root_key.borrow().unwrap();
        self.encrypt_key_custom(plaintext, root_key)
    }

    fn encrypt_key_custom(&self, plaintext: &String, root_key: Output) -> String {
        let mut csprng = OsRng;

        let key = AesKey::from_slice(root_key.as_bytes());
        let cipher = Aes256GcmSiv::new(key);
        let nonce = gen_nonce(&mut csprng);

        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes()).expect("encryption failure!");

        format!("{}:{}", base64::encode(nonce), base64::encode(ciphertext))
    }

    fn decrypt_key(&self, ciphertext: &String) -> String {
        let root_key = self.inner.root_key.borrow().unwrap();
        self.decrypt_key_custom(ciphertext, root_key)
    }

    fn decrypt_key_custom(&self, ciphertext: &String, root_key: Output) -> String {
        let split: Vec<&str> = ciphertext.split(':').collect();
        let nonce: Vec<u8> = base64::decode(split[0]).unwrap();
        let bytes = base64::decode(split[1]).unwrap();

        let key = AesKey::from_slice(root_key.as_bytes());
        let cipher = Aes256GcmSiv::new(key);

        let plaintext = cipher.decrypt(Nonce::from_slice(&nonce), bytes.as_ref()).expect("decryption failure!");

        str::from_utf8(&plaintext).unwrap().to_string()
    }
}



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

    #[test]
    fn test_key_x() {
        let key_x = KeyX::new();
        key_x.open_sesame("hello@pixelcities.io".to_string(), "passphrase".to_string());

        let key = key_x.encrypt_key(&"secret".to_string());
        let output = "Bas52beOECLMh+sr:ER+eJfhHdtE6qkUhrDlVfeiOqkoevw==".to_string();
        let decrypted = key_x.decrypt_key(&output);

        assert_eq!("secret", decrypted);
    }
}

