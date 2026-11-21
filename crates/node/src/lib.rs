//! Нода сети CORE (АРХИТЕКТУРА.md §6, §7).
//!
//! Реализовано:
//! - **mailbox** — очереди (§7.1) и журналы (§7.2) с подписями, подписками и TTL;
//! - **сеть нод** — соседи, gossip подписанных дескрипторов и статистики, снимок сети (§6, §16);
//! - **presence** — статус «в сети» с heartbeat и TTL (§15).

pub mod config;
pub mod discovery;
pub mod identity;
pub mod server;
pub mod store;

mod hub;
mod peers;
mod presence;
mod push;

pub use config::Config;
pub use identity::NodeIdentity;
pub use server::Node;
pub use store::Store;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Короткий префикс идентификатора для логов.
pub fn short_id(id: &[u8]) -> String {
    hex::encode(&id[..id.len().min(4)])
}
