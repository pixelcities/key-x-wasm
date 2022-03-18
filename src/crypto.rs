use std::str;

use rand::rngs::OsRng;
use rand::{CryptoRng, Rng};
use aes_gcm_siv::{Aes256GcmSiv, Key as AesKey, Nonce};
use aes_gcm_siv::aead::{Aead, NewAead};

pub fn gen_nonce<T>(csprng: &mut T) -> [u8; 12] where T: CryptoRng + Rng, {
    let mut nonce = [0u8; 12];
    csprng.fill_bytes(&mut nonce);
    nonce
}

pub fn gen_key_16<T>(csprng: &mut T) -> [u8; 16] where T: CryptoRng + Rng, {
    let mut key = [0u8; 16];
    csprng.fill_bytes(&mut key);
    key
}

pub fn gen_key_32<T>(csprng: &mut T) -> [u8; 32] where T: CryptoRng + Rng, {
    let mut key = [0u8; 32];
    csprng.fill_bytes(&mut key);
    key
}

pub fn encrypt_custom(plaintext: &String, secret_key: &[u8]) -> String {
    let mut csprng = OsRng;

    let key = AesKey::from_slice(secret_key);
    let cipher = Aes256GcmSiv::new(key);
    let nonce = gen_nonce(&mut csprng);

    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes()).expect("encryption failure!");

    format!("{}:{}", base64::encode(nonce), base64::encode(ciphertext))
}

pub fn decrypt_custom(ciphertext: &String, secret_key: &[u8]) -> String {
    let split: Vec<&str> = ciphertext.split(':').collect();
    let nonce: Vec<u8> = base64::decode(split[0]).unwrap();
    let bytes = base64::decode(split[1]).unwrap();

    let key = AesKey::from_slice(secret_key);
    let cipher = Aes256GcmSiv::new(key);

    let plaintext = cipher.decrypt(Nonce::from_slice(&nonce), bytes.as_ref()).expect("decryption failure!");

    str::from_utf8(&plaintext).unwrap().to_string()
}

