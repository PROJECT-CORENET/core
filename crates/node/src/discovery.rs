//! Соседи из общего списка нод (`GIT_NODES`): быстрое развёртывание без ручного bootstrap.
//!
//! Нода скачивает список (JSON, который публикует workflow `deploy` на GitHub Pages), меряет
//! задержку до каждой ноды из списка и из каталога сети (TCP + рукопожатие Noise) и держит рейтинг.
//! Дозвон идёт сначала к ближайшим, а если среди соседей есть заметно более медленный, чем
//! свободная ближняя нода, — медленный отпускается, и его место занимает ближняя.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use core_net::{Client, NodeAddr};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::server::State;
use crate::short_id;

/// Список сети CORE по умолчанию (`GIT_NODES=1`).
pub const DEFAULT_LIST: &str = "https://project-corenet.github.io/core/nodes.json";
/// Как часто перечитывать список и перемерять задержки.
const REFRESH: Duration = Duration::from_secs(15 * 60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
const PROBE_TIMEOUT: Duration = Duration::from_secs(4);
const PROBE_PARALLEL: usize = 16;
/// Больше нод не меряем за раз — в большой сети хватит выборки.
const MAX_PROBED: usize = 64;
/// Сосед заменяется, если свободная нода быстрее него хотя бы вдвое и на 20 мс.
const SWAP_RATIO: u32 = 2;
const SWAP_MIN_GAIN: Duration = Duration::from_millis(20);

/// Нода с измеренной задержкой.
#[derive(Debug, Clone)]
pub(crate) struct Ranked {
    pub key: [u8; 32],
    pub hosts: Vec<String>,
    pub rtt: Duration,
}

/// Значение `GIT_NODES` → URL списка. `1` / `true` / `yes` / `default` — список по умолчанию,
/// пусто / `0` / `false` — выключено.
pub fn list_url(value: &str) -> Option<String> {
    let v = value.trim();
    match v.to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => None,
        "1" | "true" | "yes" | "on" | "default" => Some(DEFAULT_LIST.to_string()),
        _ if v.starts_with("https://") || v.starts_with("http://") => Some(v.to_string()),
        _ => {
            warn!("⚠️ GIT_NODES must be a URL or 1/true, got {v:?} — ignored");
            None
        }
    }
}

/// JSON-массив: строки `"core://…"` или объекты `{"address": "core://…", …}` (как читает приложение).
pub fn parse_list(json: &str) -> Vec<NodeAddr> {
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(json) else {
        return vec![];
    };
    let mut seen = HashSet::new();
    items
        .iter()
        .filter_map(|item| match item {
            serde_json::Value::String(s) => Some(s.as_str()),
            serde_json::Value::Object(o) => ["address", "addr", "url"].iter().find_map(|k| o.get(*k)?.as_str()),
            _ => None,
        })
        .filter_map(|s| s.trim().parse::<NodeAddr>().ok())
        .filter(|a| seen.insert(a.public_key))
        .collect()
}

async fn fetch(url: &str) -> anyhow::Result<Vec<NodeAddr>> {
    let url = url.to_string();
    let body = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(FETCH_TIMEOUT)).build().into();
        let mut response = agent.get(&url).header("Accept", "application/json").call()?;
        Ok(response.body_mut().with_config().limit(1024 * 1024).read_to_string()?)
    })
    .await??;
    Ok(parse_list(&body))
}

/// Задержка до ноды: соединение и рукопожатие по первому ответившему адресу.
async fn probe(key: [u8; 32], hosts: Vec<String>) -> Option<Duration> {
    for host in hosts {
        let addr = NodeAddr { public_key: key, host };
        let started = Instant::now();
        if let Ok(Ok(_conn)) = tokio::time::timeout(PROBE_TIMEOUT, Client::connect(&addr)).await {
            return Some(started.elapsed());
        }
    }
    None
}

/// Кандидаты: ноды из списка + известные по каталогу сети, без себя.
fn candidates(state: &State, list: &[NodeAddr]) -> Vec<([u8; 32], Vec<String>)> {
    let own = state.identity.noise.public;
    let mut seen = HashSet::from([own]);
    let mut out = vec![];
    for a in list {
        if seen.insert(a.public_key) {
            out.push((a.public_key, vec![a.host.clone()]));
        }
    }
    for (_, e) in state.directory.lock().unwrap().iter() {
        let Ok(key) = <[u8; 32]>::try_from(e.descriptor.x25519_pk.as_slice()) else { continue };
        if seen.insert(key) {
            out.push((key, e.descriptor.addresses.clone()));
        }
    }
    out.truncate(MAX_PROBED);
    out
}

async fn rank(targets: Vec<([u8; 32], Vec<String>)>) -> Vec<Ranked> {
    let limit = Arc::new(Semaphore::new(PROBE_PARALLEL));
    let mut set = JoinSet::new();
    for (key, hosts) in targets {
        let limit = limit.clone();
        set.spawn(async move {
            let _permit = limit.acquire_owned().await.ok()?;
            let rtt = probe(key, hosts.clone()).await?;
            Some(Ranked { key, hosts, rtt })
        });
    }
    let mut ranked = vec![];
    while let Some(r) = set.join_next().await {
        if let Ok(Some(r)) = r {
            ranked.push(r);
        }
    }
    ranked.sort_by_key(|r| r.rtt);
    ranked
}

/// Отпустить самого медленного соседа, если есть свободная нода намного ближе.
fn rebalance(state: &State, ranked: &[Ranked]) {
    let target = state.config.max_peers.div_ceil(2).max(1);
    let outbound = state.peers.outbound_keys();
    if outbound.len() < target {
        return; // место есть — ближайших и так наберёт дозвон
    }
    let worst = ranked.iter().filter(|r| outbound.contains(&r.key)).max_by_key(|r| r.rtt);
    let best = ranked.iter().find(|r| !outbound.contains(&r.key));
    let (Some(worst), Some(best)) = (worst, best) else { return };
    if best.rtt * SWAP_RATIO < worst.rtt && worst.rtt - best.rtt >= SWAP_MIN_GAIN {
        info!(
            "🔀 better neighbour {} ({} ms) — releasing {} ({} ms)",
            short_id(&best.key),
            best.rtt.as_millis(),
            short_id(&worst.key),
            worst.rtt.as_millis()
        );
        state.peers.kick(worst.key);
    }
}

/// Перечитывать список, перемерять задержки и подбирать соседей. Работает, только если задан `git_nodes`.
pub(crate) async fn discovery_loop(state: Arc<State>) {
    let Some(url) = state.config.git_nodes.clone() else { return };
    let mut list: Vec<NodeAddr> = vec![];
    loop {
        match fetch(&url).await {
            Ok(fresh) if !fresh.is_empty() => {
                info!("📥 node list {url}: {} nodes", fresh.len());
                list = fresh;
            }
            Ok(_) => warn!("⚠️ node list {url} is empty — keeping {} known", list.len()),
            Err(e) => warn!("⚠️ node list {url} unavailable: {e} — keeping {} known", list.len()),
        }
        let ranked = rank(candidates(&state, &list)).await;
        if ranked.is_empty() {
            warn!("⚠️ no node from the list answered");
        } else {
            let top: Vec<String> =
                ranked.iter().take(5).map(|r| format!("{}={}ms", short_id(&r.key), r.rtt.as_millis())).collect();
            info!("📶 nearest nodes: {}", top.join(" "));
        }
        debug!("📶 ranked {} nodes", ranked.len());
        rebalance(&state, &ranked);
        *state.ranked.lock().unwrap() = ranked;
        tokio::time::sleep(REFRESH).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "core://5409094ab65eab5f5730f0006f402350888c96ecbad0cf6bed76d78c16fc400f@188.225.72.79:7445";
    const B: &str = "core://c5e78ee557de779b318b91cc73f980477eb1024c1b17ef6c53005d82f88a2771@141.98.235.172:7445";

    #[test]
    fn parses_strings_objects_and_dedups() {
        let json = format!(r#"["{A}", {{"name": "N2", "address": "{B}"}}, {{"address": "{A}"}}, 5, "junk"]"#);
        let list = parse_list(&json);
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].host, "141.98.235.172:7445");
        assert!(parse_list("{}").is_empty());
    }

    #[test]
    fn list_url_values() {
        assert_eq!(list_url("1").as_deref(), Some(DEFAULT_LIST));
        assert_eq!(list_url(" true ").as_deref(), Some(DEFAULT_LIST));
        assert_eq!(list_url("https://x.y/n.json").as_deref(), Some("https://x.y/n.json"));
        assert_eq!(list_url("0"), None);
        assert_eq!(list_url(""), None);
        assert_eq!(list_url("nonsense"), None);
    }
}
