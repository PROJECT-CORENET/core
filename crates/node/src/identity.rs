//! Идентичность ноды (АРХИТЕКТУРА.md §6.1):
//! Ed25519 (подписи, `node_id = SHA-256(pk)`) + X25519 (статический Noise-ключ).

use std::io::Write;
use std::path::Path;

use anyhow::Context;
use core_crypto::{sha256, Ed25519Key, NoiseKeypair};
use core_net::NodeAddr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct NodeIdentity {
    pub signing: Ed25519Key,
    pub noise: NoiseKeypair,
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    ed25519_secret: String,
    x25519_secret: String,
}

impl NodeIdentity {
    pub fn generate() -> Self {
        Self { signing: Ed25519Key::generate(), noise: NoiseKeypair::generate() }
    }

    /// Детерминированные ключи из строки-зерна. **Только для тестовых сетей**: кто знает
    /// зерно, тот владеет нодой. Нужно, чтобы адреса testnet-нод были известны заранее.
    pub fn from_seed(seed: &str) -> Self {
        let derive = |label: &str| core_crypto::sha256(format!("CORE/testnet/{label}/{seed}").as_bytes());
        Self {
            signing: Ed25519Key::from_bytes(&derive("ed25519")),
            noise: NoiseKeypair::from_private(derive("x25519")),
        }
    }

    pub fn node_id(&self) -> [u8; 32] {
        sha256(&self.signing.public_key())
    }

    pub fn address(&self, host: &str) -> NodeAddr {
        NodeAddr { public_key: self.noise.public, host: host.to_string() }
    }

    /// Загрузить ключи из файла или создать новые. Возвращает `true`, если ключи созданы.
    pub fn load_or_create(path: &Path) -> anyhow::Result<(Self, bool)> {
        if path.exists() {
            return Ok((Self::load(path)?, false));
        }
        let identity = Self::generate();
        identity.save(path)?;
        Ok((identity, true))
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let stored: StoredIdentity = toml::from_str(&text)?;
        Ok(Self {
            signing: Ed25519Key::from_bytes(&decode_key(&stored.ed25519_secret)?),
            noise: NoiseKeypair::from_private(decode_key(&stored.x25519_secret)?),
        })
    }

    /// Файл с секретами создаётся с правами 0600.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let stored = StoredIdentity {
            ed25519_secret: hex::encode(self.signing.to_bytes()),
            x25519_secret: hex::encode(self.noise.private),
        };
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(path).with_context(|| format!("creating {}", path.display()))?;
        file.write_all(toml::to_string(&stored)?.as_bytes())?;
        Ok(())
    }
}

fn decode_key(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    hex::decode(hex_str)?.try_into().map_err(|_| anyhow::anyhow!("key must be 32 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.toml");
        let (created, fresh) = NodeIdentity::load_or_create(&path).unwrap();
        assert!(fresh);
        let (loaded, fresh) = NodeIdentity::load_or_create(&path).unwrap();
        assert!(!fresh);
        assert_eq!(created.node_id(), loaded.node_id());
        assert_eq!(created.noise.public, loaded.noise.public);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
