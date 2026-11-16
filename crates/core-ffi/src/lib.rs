//! Мост Rust → Swift (UniFFI) для приложений CORE.
//!
//! Вся сеть, криптография и проверка подписей — здесь, в Rust. Swift получает уже
//! проверенные данные в виде простых структур (§21.2).

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use core_directory::{mutual_links, verify_snapshot};
use core_net::{Client, NetError, NodeAddr};
use core_proto::msg::{request, response, NetSnapshot, Ping};

mod client;

uniffi::setup_scaffolding!();

const SNAPSHOT_MAX_PAGES: usize = 64;
const CALL_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CoreError {
    #[error("Неверный адрес ноды: {message}")]
    InvalidAddress { message: String },
    #[error("Нет связи с нодой: {message}")]
    Network { message: String },
    #[error("Нода вернула ошибку: {message}")]
    Node { message: String },
    #[error("{message}")]
    Client { message: String },
}

impl From<NetError> for CoreError {
    fn from(e: NetError) -> Self {
        match e {
            NetError::BadAddress(_) => CoreError::InvalidAddress { message: e.to_string() },
            NetError::Node { .. } => CoreError::Node { message: e.to_string() },
            other => CoreError::Network { message: other.to_string() },
        }
    }
}

/// Нода на карте сети.
#[derive(Debug, Clone, uniffi::Record)]
pub struct NetworkNode {
    /// node_id, hex.
    pub id: String,
    /// Первые 8 символов id — для подписей.
    pub short_id: String,
    pub name: String,
    pub region: String,
    pub addresses: Vec<String>,
    pub version: String,
    /// Свежая статистика есть (последние 3 минуты).
    pub online: bool,
    /// Клиентов онлайн (округлено вниз до 5).
    pub clients: u32,
    /// Нагрузка 0…10.
    pub load: u32,
    pub uptime_secs: u64,
    /// Это нода, через которую подключено приложение.
    pub is_entry: bool,
    /// Полный адрес `core://…` (первый адрес дескриптора).
    pub address: String,
}

/// Связь, подтверждённая обеими нодами.
#[derive(Debug, Clone, uniffi::Record)]
pub struct NetworkLink {
    pub a: String,
    pub b: String,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct NetworkSnapshot {
    pub nodes: Vec<NetworkNode>,
    pub links: Vec<NetworkLink>,
    /// id ноды подключения.
    pub entry_id: String,
    /// Сколько записей пришло и сколько прошло проверку подписей.
    pub received: u32,
    pub verified: u32,
    pub latency_ms: u64,
    pub fetched_at_ms: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct NodeAddressInfo {
    pub host: String,
    pub public_key: String,
    pub normalized: String,
}

/// Версия ядра.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Разобрать и проверить адрес `core://<ключ>@host:port`.
#[uniffi::export]
pub fn parse_node_address(address: String) -> Result<NodeAddressInfo, CoreError> {
    let addr: NodeAddr = address.trim().parse()?;
    Ok(NodeAddressInfo {
        host: addr.host.clone(),
        public_key: hex::encode(addr.public_key),
        normalized: addr.to_string(),
    })
}

/// Задержка до ноды (Noise-рукопожатие + Ping), мс.
#[uniffi::export(async_runtime = "tokio")]
pub async fn ping_node(address: String) -> Result<u64, CoreError> {
    let addr: NodeAddr = address.trim().parse()?;
    with_timeout(async {
        let (client, _events) = Client::connect(&addr).await?;
        let started = Instant::now();
        client.request(request::Body::Ping(Ping {}), None).await?;
        Ok(started.elapsed().as_millis() as u64)
    })
    .await
}

/// Снимок сети глазами ноды. Подписи всех записей проверяются здесь, на устройстве.
#[uniffi::export(async_runtime = "tokio")]
pub async fn fetch_network(address: String) -> Result<NetworkSnapshot, CoreError> {
    let addr: NodeAddr = address.trim().parse()?;
    with_timeout(async {
        let started = Instant::now();
        let (client, _events) = Client::connect(&addr).await?;
        let mut nodes = vec![];
        let mut cursor = vec![];
        let mut self_id = vec![];
        for _ in 0..SNAPSHOT_MAX_PAGES {
            let response::Body::NetSnapshotReply(r) =
                client.request(request::Body::NetSnapshot(NetSnapshot { cursor }), None).await?
            else {
                return Err(CoreError::Node { message: "unexpected response".into() });
            };
            let empty = r.nodes.is_empty();
            nodes.extend(r.nodes);
            self_id = r.self_id;
            if r.next_cursor.is_empty() || empty {
                break;
            }
            cursor = r.next_cursor;
        }
        let latency_ms = started.elapsed().as_millis() as u64;
        Ok(build_snapshot(nodes, &self_id, latency_ms, now_ms()))
    })
    .await
}

fn build_snapshot(raw: Vec<core_proto::msg::NetNode>, self_id: &[u8], latency_ms: u64, now: u64) -> NetworkSnapshot {
    let received = raw.len() as u32;
    let dir = verify_snapshot(raw, now);
    let entry_id = hex::encode(self_id);
    let nodes: Vec<NetworkNode> = dir
        .iter()
        .map(|(id, e)| {
            let d = &e.descriptor;
            let id_hex = hex::encode(id);
            let stats = e.stats.as_ref();
            let address = d
                .addresses
                .first()
                .map(|h| NodeAddr { public_key: d.x25519_pk.as_slice().try_into().unwrap_or([0; 32]), host: h.clone() })
                .map(|a| a.to_string())
                .unwrap_or_default();
            NetworkNode {
                short_id: id_hex[..8].to_string(),
                is_entry: id_hex == entry_id,
                id: id_hex,
                name: d.name.clone(),
                region: d.region.clone(),
                addresses: d.addresses.clone(),
                version: d.version.clone(),
                online: e.is_online(now),
                clients: stats.map_or(0, |s| s.clients_online),
                load: stats.map_or(0, |s| s.load),
                uptime_secs: stats.map_or(0, |s| s.uptime_secs),
                address,
            }
        })
        .collect();
    let links =
        mutual_links(&dir).into_iter().map(|(a, b)| NetworkLink { a: hex::encode(a), b: hex::encode(b) }).collect();
    NetworkSnapshot { verified: nodes.len() as u32, nodes, links, entry_id, received, latency_ms, fetched_at_ms: now }
}

async fn with_timeout<T>(fut: impl std::future::Future<Output = Result<T, CoreError>>) -> Result<T, CoreError> {
    tokio::time::timeout(CALL_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| Err(CoreError::Network { message: "timeout".into() }))
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_parsing() {
        let ok = format!("  core://{}@127.0.0.1:17441 ", "ab".repeat(32));
        let info = parse_node_address(ok).unwrap();
        assert_eq!(info.host, "127.0.0.1:17441");
        assert!(matches!(parse_node_address("nope".into()), Err(CoreError::InvalidAddress { .. })));
    }

    #[tokio::test]
    async fn unreachable_node_is_network_error() {
        let addr = format!("core://{}@127.0.0.1:1", "ab".repeat(32));
        assert!(matches!(fetch_network(addr).await, Err(CoreError::Network { .. })));
    }
}
