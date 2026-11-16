use std::fmt;
use std::str::FromStr;

use crate::NetError;

const SCHEME: &str = "core://";

/// Адрес ноды: статический Noise-ключ + `host:port`.
///
/// Ключ в адресе — то, что делает подключение аутентифицированным:
/// без него нельзя отличить настоящую ноду от MITM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeAddr {
    pub public_key: [u8; 32],
    pub host: String,
}

impl fmt::Display for NodeAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{SCHEME}{}@{}", hex::encode(self.public_key), self.host)
    }
}

impl FromStr for NodeAddr {
    type Err = NetError;

    fn from_str(s: &str) -> Result<Self, NetError> {
        let bad = || NetError::BadAddress(s.to_string());
        let rest = s.strip_prefix(SCHEME).ok_or_else(bad)?;
        let (key, host) = rest.split_once('@').ok_or_else(bad)?;
        let public_key: [u8; 32] = hex::decode(key).ok().and_then(|k| k.try_into().ok()).ok_or_else(bad)?;
        if host.is_empty() || !host.contains(':') {
            return Err(bad());
        }
        Ok(Self { public_key, host: host.to_string() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let addr = NodeAddr { public_key: [0xab; 32], host: "127.0.0.1:7443".into() };
        let s = addr.to_string();
        assert!(s.starts_with("core://abab"));
        assert_eq!(s.parse::<NodeAddr>().unwrap(), addr);
    }

    #[test]
    fn rejects_garbage() {
        for s in [
            "",
            "core://",
            "http://aa@h:1",
            "core://zz@h:1",
            "core://abab@h:1",
            &format!("core://{}@", "ab".repeat(32)),
            &format!("core://{}@host", "ab".repeat(32)),
        ] {
            assert!(s.parse::<NodeAddr>().is_err(), "{s}");
        }
    }
}
