//! Соседи по сети нод (§6.2, §6.4): исходящие соединения, gossip, публикация своего
//! дескриптора и статистики.
//!
//! Нода ↔ нода используют тот же Noise_NK, что и клиенты; после рукопожатия
//! инициатор представляется `PeerHello` — дескриптор + подпись хеша сессии ключом
//! идентичности. Инициатор шлёт gossip запросами, принимающая сторона — событиями.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use core_crypto::random_bytes;
use core_directory::{
    sign_descriptor, sign_session, sign_stats, verify_descriptor, NodeId, DESCRIPTOR_TTL_MS, MAX_PEERS_IN_STATS,
};
use core_net::{Client, NetError, NodeAddr};
use core_proto::msg::{event, gossip, request, response, Gossip, NodeDescriptor, NodeStats, PeerHello, Ping};
use rand::seq::SliceRandom;
use tokio::sync::{mpsc, Notify};
use tracing::{debug, info, warn};

use crate::server::State;
use crate::{now_ms, short_id, Config, NodeIdentity};

pub const LINK_QUEUE: usize = 1024;
/// Сколько хопов проходит gossip-сообщение.
pub const GOSSIP_TTL: u32 = 8;
const SEEN_CAPACITY: usize = 100_000;
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BACKOFF_SECS: u64 = 600;
const MAX_TEXT_BYTES: usize = 64;
/// Склеиваем подряд идущие изменения соседей в одну публикацию.
const CHANGE_DEBOUNCE: Duration = Duration::from_millis(500);

struct Link {
    node_id: NodeId,
    tx: mpsc::Sender<Gossip>,
}

#[derive(Default)]
pub struct Peers {
    links: Mutex<HashMap<u64, Link>>,
    next_link: AtomicU64,
    /// X25519-ключи нод, к которым мы сейчас подключаемся или подключены (исходящие).
    dialing: Mutex<HashSet<[u8; 32]>>,
    /// Неудачные попытки: ключ → (число неудач подряд, когда можно снова).
    backoff: Mutex<HashMap<[u8; 32], (u32, Instant)>>,
    /// Набор соседей изменился — пора опубликовать свежую статистику.
    changed: Notify,
    /// Исходящие соединения, которые можно закрыть по просьбе подбора соседей (нашлась нода ближе).
    kicks: Mutex<HashMap<[u8; 32], Arc<Notify>>>,
}

impl Peers {
    pub fn register(&self, node_id: NodeId, tx: mpsc::Sender<Gossip>) -> u64 {
        let id = self.next_link.fetch_add(1, Ordering::Relaxed);
        self.links.lock().unwrap().insert(id, Link { node_id, tx });
        self.changed.notify_one();
        id
    }

    pub fn unregister(&self, link: u64) {
        self.links.lock().unwrap().remove(&link);
        self.changed.notify_one();
    }

    /// Уникальные node_id всех соседей (в обе стороны).
    pub fn node_ids(&self) -> Vec<NodeId> {
        let mut ids: Vec<_> = self.links.lock().unwrap().values().map(|l| l.node_id).collect();
        ids.sort();
        ids.dedup();
        ids
    }

    pub fn len(&self) -> usize {
        self.links.lock().unwrap().len()
    }

    pub fn broadcast(&self, g: &Gossip, except: Option<NodeId>) {
        for link in self.links.lock().unwrap().values() {
            if Some(link.node_id) != except {
                // Медленный сосед не тормозит остальных: при переполнении сообщение теряется,
                // следующая публикация придёт через gossip_interval.
                let _ = link.tx.try_send(g.clone());
            }
        }
    }

    fn try_start_dial(&self, key: [u8; 32]) -> bool {
        if let Some((_, until)) = self.backoff.lock().unwrap().get(&key) {
            if Instant::now() < *until {
                return false;
            }
        }
        self.dialing.lock().unwrap().insert(key)
    }

    fn finish_dial(&self, key: [u8; 32], connected: bool) {
        self.dialing.lock().unwrap().remove(&key);
        let mut backoff = self.backoff.lock().unwrap();
        if connected {
            backoff.remove(&key);
        } else {
            let fails = backoff.get(&key).map_or(1, |(n, _)| n + 1);
            let delay = (1u64 << fails.min(10)).min(MAX_BACKOFF_SECS);
            backoff.insert(key, (fails, Instant::now() + Duration::from_secs(delay)));
        }
    }

    fn dialing_count(&self) -> usize {
        self.dialing.lock().unwrap().len()
    }

    /// Ключи исходящих соседей (подключённых или подключающихся).
    pub(crate) fn outbound_keys(&self) -> HashSet<[u8; 32]> {
        self.dialing.lock().unwrap().clone()
    }

    /// Закрыть исходящее соединение с нодой (его место займёт более близкая).
    pub(crate) fn kick(&self, key: [u8; 32]) {
        if let Some(n) = self.kicks.lock().unwrap().get(&key) {
            n.notify_one();
        }
    }
}

/// Последние увиденные `msg_id` — чтобы gossip не ходил по кругу (из `идеи.md`, п.5).
#[derive(Default)]
pub struct SeenCache {
    set: HashSet<Vec<u8>>,
    order: VecDeque<Vec<u8>>,
}

impl SeenCache {
    /// `true`, если `msg_id` встречен впервые.
    pub fn insert(&mut self, msg_id: &[u8]) -> bool {
        if !self.set.insert(msg_id.to_vec()) {
            return false;
        }
        self.order.push_back(msg_id.to_vec());
        if self.order.len() > SEEN_CAPACITY {
            if let Some(old) = self.order.pop_front() {
                self.set.remove(&old);
            }
        }
        true
    }
}

pub fn new_gossip(payload: gossip::Payload, ttl: u32) -> Gossip {
    Gossip { msg_id: random_bytes::<16>().to_vec(), ttl, payload: Some(payload) }
}

/// Принять gossip: проверить, применить к каталогу и, если это новость, переслать дальше.
pub(crate) fn handle_gossip(state: &State, g: Gossip, from: Option<NodeId>) {
    if g.msg_id.len() != 16 || !state.seen.lock().unwrap().insert(&g.msg_id) {
        return;
    }
    let Some(payload) = g.payload.clone() else { return };
    let now = now_ms();
    let result = {
        let mut dir = state.directory.lock().unwrap();
        match payload {
            gossip::Payload::Descriptor(d) => dir.apply_descriptor(d, now),
            gossip::Payload::Stats(s) => dir.apply_stats(s, now),
        }
    };
    match result {
        Ok(true) if g.ttl > 1 => state.peers.broadcast(&Gossip { ttl: g.ttl - 1, ..g }, from),
        Ok(_) => {}
        Err(e) => debug!("🚫 rejected gossip from {}: {e}", from.map(|f| short_id(&f)).unwrap_or_default()),
    }
}

/// Новому соседу — всё, что мы знаем (TTL 1: он применит, но не будет пересылать).
pub(crate) fn initial_sync(state: &State, tx: &mpsc::Sender<Gossip>) {
    let dir = state.directory.lock().unwrap();
    for (_, e) in dir.iter() {
        let _ = tx.try_send(new_gossip(gossip::Payload::Descriptor(e.descriptor.clone()), 1));
        if let Some(s) = &e.stats {
            let _ = tx.try_send(new_gossip(gossip::Payload::Stats(s.clone()), 1));
        }
    }
}

pub fn make_descriptor(identity: &NodeIdentity, addresses: Vec<String>, config: &Config, now: u64) -> NodeDescriptor {
    let mut d = NodeDescriptor {
        x25519_pk: identity.noise.public.to_vec(),
        addresses,
        roles: vec!["entry".into(), "mailbox".into(), "presence".into()],
        version: env!("CARGO_PKG_VERSION").into(),
        region: truncate_bytes(&config.region, MAX_TEXT_BYTES),
        name: truncate_bytes(&config.name, MAX_TEXT_BYTES),
        published_at_ms: now,
        expires_at_ms: now + DESCRIPTOR_TTL_MS,
        ..Default::default()
    };
    sign_descriptor(&mut d, &identity.signing);
    d
}

fn truncate_bytes(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn make_stats(state: &State, now: u64) -> NodeStats {
    let clients = state.clients.load(Ordering::Relaxed) as u32;
    let connections = state.connections.load(Ordering::Relaxed);
    let mut s = NodeStats {
        peers: state.peers.node_ids().into_iter().take(MAX_PEERS_IN_STATS).map(|p| p.to_vec()).collect(),
        // Округление вниз до 5: по скачку счётчика нельзя понять, что подключился конкретный человек.
        clients_online: clients / 5 * 5,
        load: (connections * 10 / state.config.max_connections.max(1)).min(10) as u32,
        uptime_secs: state.started.elapsed().as_secs(),
        published_at_ms: now,
        ..Default::default()
    };
    sign_stats(&mut s, &state.identity.signing);
    s
}

/// Раз в `gossip_interval` и при изменении соседей: переподписать дескриптор при
/// необходимости, опубликовать статистику — карта сети обновляется почти сразу.
pub(crate) async fn publisher_loop(state: Arc<State>) {
    let mut tick = tokio::time::interval(Duration::from_secs(state.config.gossip_interval_secs.max(1)));
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = state.peers.changed.notified() => tokio::time::sleep(CHANGE_DEBOUNCE).await,
        }
        let now = now_ms();
        let descriptor = {
            let mut own = state.own_descriptor.lock().unwrap();
            if own.expires_at_ms < now + DESCRIPTOR_TTL_MS / 2 {
                *own = make_descriptor(&state.identity, own.addresses.clone(), &state.config, now);
            }
            own.clone()
        };
        let stats = make_stats(&state, now);
        let (known, online) = {
            let mut dir = state.directory.lock().unwrap();
            let _ = dir.apply_descriptor(descriptor.clone(), now);
            let _ = dir.apply_stats(stats.clone(), now);
            dir.prune(now);
            (dir.len(), dir.iter().filter(|(_, e)| e.is_online(now)).count())
        };
        for payload in [gossip::Payload::Descriptor(descriptor), gossip::Payload::Stats(stats)] {
            let g = new_gossip(payload, GOSSIP_TTL);
            state.seen.lock().unwrap().insert(&g.msg_id);
            state.peers.broadcast(&g, None);
        }
        info!(
            "📡 gossip tick: peers={} known_nodes={known} online_nodes={online} clients={} presence_online={} call_rooms={}",
            state.peers.node_ids().len(),
            state.clients.load(Ordering::Relaxed),
            state.presence.lock().unwrap().online_count(),
            state.hub.rooms(),
        );
    }
}

struct Target {
    key: [u8; 32],
    hosts: Vec<String>,
}

/// Поддерживать нужное число исходящих соседей: bootstrap + ноды из каталога.
pub(crate) async fn dialer_loop(state: Arc<State>) {
    let bootstrap: Vec<NodeAddr> = state
        .config
        .bootstrap
        .iter()
        .filter(|s| !s.trim().is_empty())
        .filter_map(|s| match s.trim().parse() {
            Ok(a) => Some(a),
            Err(e) => {
                warn!("⚠️ invalid bootstrap address {s}: {e}");
                None
            }
        })
        .collect();
    let outbound_target = state.config.max_peers.div_ceil(2).max(1);
    let mut tick = tokio::time::interval(Duration::from_secs(state.config.peer_check_interval_secs.max(1)));

    loop {
        tick.tick().await;
        let need = outbound_target.saturating_sub(state.peers.dialing_count());
        if need == 0 {
            continue;
        }
        let mut candidates = collect_candidates(&state, &bootstrap);
        candidates.shuffle(&mut rand::thread_rng());
        // С GIT_NODES — сначала ближайшие по измеренной задержке, остальные — вперемешку после них.
        let ranked = state.ranked.lock().unwrap().clone();
        if !ranked.is_empty() {
            for r in &ranked {
                if !candidates.iter().any(|c| c.key == r.key)
                    && r.key != state.identity.noise.public
                    && !state.peers.outbound_keys().contains(&r.key)
                {
                    candidates.push(Target { key: r.key, hosts: r.hosts.clone() });
                }
            }
            let order = |key: &[u8; 32]| ranked.iter().position(|r| r.key == *key).unwrap_or(usize::MAX);
            candidates.sort_by_key(|c| order(&c.key));
        }
        let mut started = 0;
        for target in candidates {
            if started == need {
                break;
            }
            if state.peers.try_start_dial(target.key) {
                started += 1;
                tokio::spawn(dial(state.clone(), target));
            }
        }
    }
}

fn collect_candidates(state: &State, bootstrap: &[NodeAddr]) -> Vec<Target> {
    let connected: HashSet<NodeId> = state.peers.node_ids().into_iter().collect();
    let mut known_keys = HashSet::new();
    let mut out = vec![];
    for (id, e) in state.directory.lock().unwrap().iter() {
        let Ok(key) = <[u8; 32]>::try_from(e.descriptor.x25519_pk.as_slice()) else { continue };
        known_keys.insert(key);
        if *id != state.node_id && !connected.contains(id) {
            out.push(Target { key, hosts: e.descriptor.addresses.clone() });
        }
    }
    for b in bootstrap {
        if b.public_key != state.identity.noise.public && !known_keys.contains(&b.public_key) {
            out.push(Target { key: b.public_key, hosts: vec![b.host.clone()] });
        }
    }
    out
}

async fn dial(state: Arc<State>, target: Target) {
    let key = target.key;
    let connected = match run_outbound(&state, &target).await {
        Ok(()) => true,
        Err(e) => {
            debug!("🔌 dial {} failed: {e}", short_id(&key));
            false
        }
    };
    state.peers.finish_dial(key, connected);
}

/// Исходящее соединение с соседом. `Ok` — соединение было установлено (и позже закрылось).
async fn run_outbound(state: &Arc<State>, target: &Target) -> Result<(), NetError> {
    let mut last_err = NetError::Closed;
    let mut conn = None;
    for host in &target.hosts {
        let addr = NodeAddr { public_key: target.key, host: host.clone() };
        match tokio::time::timeout(DIAL_TIMEOUT, Client::connect(&addr)).await {
            Ok(Ok(c)) => {
                conn = Some(c);
                break;
            }
            Ok(Err(e)) => last_err = e,
            Err(_) => last_err = NetError::Timeout,
        }
    }
    let Some((client, mut events)) = conn else { return Err(last_err) };

    let hello = PeerHello {
        descriptor: Some(state.own_descriptor.lock().unwrap().clone()),
        session_sig: sign_session(&state.identity.signing, client.session_hash()),
    };
    let response::Body::PeerWelcome(welcome) = client.request(request::Body::PeerHello(hello), None).await? else {
        return Err(NetError::Protocol("expected PeerWelcome".into()));
    };
    let descriptor = welcome.descriptor.ok_or_else(|| NetError::Protocol("welcome without descriptor".into()))?;
    let now = now_ms();
    let node_id = verify_descriptor(&descriptor, now).map_err(|e| NetError::Protocol(e.to_string()))?;
    if descriptor.x25519_pk != target.key || node_id == state.node_id {
        return Err(NetError::Protocol("descriptor does not match dialed key".into()));
    }
    let _ = state.directory.lock().unwrap().apply_descriptor(descriptor, now);

    let (tx, mut rx) = mpsc::channel(LINK_QUEUE);
    let link = state.peers.register(node_id, tx.clone());
    let kick = Arc::new(Notify::new());
    state.peers.kicks.lock().unwrap().insert(target.key, kick.clone());
    initial_sync(state, &tx);
    info!("🔗 peer connected (outbound) node={}", short_id(&node_id));

    let st = state.clone();
    let mut inbound = tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            if let Some(event::Body::Gossip(g)) = ev.body {
                handle_gossip(&st, g, Some(node_id));
            }
        }
    });
    let keepalive = Duration::from_secs((state.config.idle_timeout_secs / 3).max(1));
    let reason = loop {
        tokio::select! {
            g = rx.recv() => match g {
                Some(g) => if let Err(e) = client.request(request::Body::Gossip(g), None).await { break e },
                None => break NetError::Closed,
            },
            _ = tokio::time::sleep(keepalive) => {
                if let Err(e) = client.request(request::Body::Ping(Ping {}), None).await { break e }
            }
            _ = &mut inbound => break NetError::Closed,
            _ = kick.notified() => break NetError::Protocol("replaced by a nearer neighbour".into()),
        }
    };
    inbound.abort();
    state.peers.kicks.lock().unwrap().remove(&target.key);
    state.peers.unregister(link);
    info!("💔 peer disconnected (outbound) node={} reason={reason}", short_id(&node_id));
    Ok(())
}
