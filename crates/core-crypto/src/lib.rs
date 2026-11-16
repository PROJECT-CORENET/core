//! Криптографические примитивы CORE (АРХИТЕКТУРА.md §9.4).
//!
//! Только обёртки над проверенными библиотеками — никакой самописной криптографии.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

/// Ed25519-ключ: подписи команд (ключи очередей/журналов), идентичность ноды.
#[derive(Clone)]
pub struct Ed25519Key(SigningKey);

impl Ed25519Key {
    pub fn generate() -> Self {
        Self(SigningKey::generate(&mut OsRng))
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(secret))
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.0.sign(msg).to_bytes()
    }
}

impl std::fmt::Debug for Ed25519Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Ed25519Key(pk={})", hex_prefix(&self.public_key()))
    }
}

/// Строгая проверка Ed25519-подписи. Любой мусор на входе → `false`.
pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(pk) = <[u8; 32]>::try_from(public_key) else { return false };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else { return false };
    let Ok(sig) = Signature::from_slice(sig) else { return false };
    vk.verify_strict(msg, &sig).is_ok()
}

/// Статический X25519-ключ для Noise.
#[derive(Clone)]
pub struct NoiseKeypair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl NoiseKeypair {
    pub fn generate() -> Self {
        Self::from_private(random_bytes())
    }

    pub fn from_private(private: [u8; 32]) -> Self {
        let secret = x25519_dalek::StaticSecret::from(private);
        let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
        Self { private, public }
    }
}

impl std::fmt::Debug for NoiseKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoiseKeypair(pk={})", hex_prefix(&self.public))
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().take(4).map(|b| format!("{b:02x}")).collect::<String>() + "…"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let key = Ed25519Key::generate();
        let sig = key.sign(b"msg");
        assert!(verify(&key.public_key(), b"msg", &sig));
        assert!(!verify(&key.public_key(), b"other", &sig));
        assert!(!verify(&Ed25519Key::generate().public_key(), b"msg", &sig));
        assert!(!verify(&[0u8; 5], b"msg", &sig));
        assert!(!verify(&key.public_key(), b"msg", &sig[..10]));
    }

    #[test]
    fn key_roundtrip() {
        let key = Ed25519Key::generate();
        assert_eq!(Ed25519Key::from_bytes(&key.to_bytes()).public_key(), key.public_key());
        let kp = NoiseKeypair::generate();
        assert_eq!(NoiseKeypair::from_private(kp.private).public, kp.public);
    }
}
