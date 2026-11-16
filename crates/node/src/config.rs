use std::path::Path;

use serde::{Deserialize, Serialize};

const DAY_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Адрес, на котором нода слушает соединения.
    pub listen: String,
    /// Публичный `host:port` для адреса ноды (если `listen` = 0.0.0.0 или нода за NAT).
    pub public_host: Option<String>,
    /// Дополнительные `host:port` в дескрипторе (например, адрес внутри docker-сети).
    pub extra_addresses: Vec<String>,
    /// Человекочитаемое имя ноды для карты сети.
    pub name: String,
    /// Код страны для карты сети, например "NL".
    pub region: String,

    /// Адреса `core://…` нод, с которых начинается знакомство с сетью (§20.2).
    pub bootstrap: Vec<String>,
    /// Желаемое число соседей; исходящих соединений — половина.
    pub max_peers: usize,
    /// Как часто публиковать свой дескриптор и статистику (§16.2: 60 с).
    pub gossip_interval_secs: u64,
    /// Как часто проверять, хватает ли соседей.
    pub peer_check_interval_secs: u64,

    /// Сколько хранить недоставленные сообщения очередей (§7.1: 21 день).
    pub queue_ttl_secs: u64,
    /// Сколько хранить записи журналов (§7.2: 30 дней).
    pub log_ttl_secs: u64,
    /// Максимум недоставленных сообщений в одной очереди.
    pub max_queue_messages: u32,
    /// Максимум одновременных соединений.
    pub max_connections: usize,
    /// Закрывать соединение без активности (клиенты шлют Ping).
    pub idle_timeout_secs: u64,
    pub cleanup_interval_secs: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:7443".into(),
            public_host: None,
            extra_addresses: vec![],
            name: String::new(),
            region: String::new(),
            bootstrap: vec![],
            max_peers: 8,
            gossip_interval_secs: 60,
            peer_check_interval_secs: 10,
            queue_ttl_secs: 21 * DAY_SECS,
            log_ttl_secs: 30 * DAY_SECS,
            max_queue_messages: 1000,
            max_connections: 10_000,
            idle_timeout_secs: 300,
            cleanup_interval_secs: 3600,
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        Ok(toml::from_str(&std::fs::read_to_string(path)?)?)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        std::fs::write(path, toml::to_string_pretty(self)?)?;
        Ok(())
    }

    /// `host:port`, который попадает в адрес ноды.
    pub fn advertised_host(&self) -> &str {
        self.public_host.as_deref().unwrap_or(&self.listen)
    }
}
