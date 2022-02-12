extern crate base64;
extern crate console_error_panic_hook;

use wasm_bindgen::prelude::*;

use std::str;
use std::sync::Arc;
use std::cell::RefCell;
use std::collections::hash_map::HashMap;

use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};

use argon2::{password_hash::{PasswordHasher, SaltString, Output}, Argon2, Params, Algorithm, Version};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
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
        // Derive root key
        let root_key = {
            let params = Params::new(4096, 4, 1, Some(32)).unwrap(); // ~ 1250ms
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let salt = SaltString::b64_encode(&email.as_bytes()).unwrap();
            Some(argon2.hash_password(passphrase.as_bytes(), &salt).unwrap().hash.unwrap())
        };

        self.inner.root_key.replace(root_key);

        // Because the root key is based on both the email and passphrase the
        // hash will change when either of the two is mutated. Take care.
        let hashed_passphrase = {
            let params = Params::new(512, 1, 1, Some(32)).unwrap(); // ~ <100ms
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

            let salt =  SaltString::b64_encode(&passphrase.as_bytes()).unwrap();
            argon2.hash_password(self.inner.root_key.borrow().unwrap().as_bytes(), &salt).unwrap().hash.unwrap()
        };

        base64::encode(hashed_passphrase.as_bytes())
    }

    pub fn is_locked(&self) -> bool {
        let root_key = self.inner.root_key.borrow();
        root_key.is_none()
    }

    pub fn get_key(&self, id: String) -> String {
        match self.inner.keys.borrow().get(&id) {
            Some(key) => {
                self.decrypt_key(key.clone())
            },
            None => panic!("Invalid key id")
        }
    }

    pub fn encrypt_key(&self, plaintext: String) -> String {
        let mut csprng = OsRng;

        let root_key = self.inner.root_key.borrow().unwrap();
        let key = Key::from_slice(root_key.as_bytes());
        let cipher = Aes256GcmSiv::new(key);
        let nonce = gen_nonce(&mut csprng);

        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes()).expect("encryption failure!");

        format!("{}:{}", base64::encode(nonce), base64::encode(ciphertext))
    }

    pub fn decrypt_key(&self, ciphertext: String) -> String {
        let split: Vec<&str> = ciphertext.split(':').collect();
        let nonce: Vec<u8> = base64::decode(split[0]).unwrap();
        let bytes = base64::decode(split[1]).unwrap();

        let root_key = self.inner.root_key.borrow().unwrap();
        let key = Key::from_slice(root_key.as_bytes());
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

        let key = key_x.encrypt_key("secret".to_string());
        let output = "Bas52beOECLMh+sr:ER+eJfhHdtE6qkUhrDlVfeiOqkoevw==".to_string();
        let decrypted = key_x.decrypt_key(output);

        assert_eq!("secret", decrypted);
    }
}

