//! Каталог нод (АРХИТЕКТУРА.md §6.3–§6.4, §16.2).
//!
//! Всё, что приходит из сети, проверяется здесь: подписи, сроки, привязка
//! `node_id = SHA-256(ed25519_pk)`. Нода и клиент используют один и тот же код —
//! клиент не доверяет «своей» ноде на слово.

use std::collections::{BTreeMap, HashSet};

use core_crypto::{sha256, verify, Ed25519Key};
use core_proto::msg::{NetNode, NodeDescriptor, NodeStats, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use prost::Message;

pub type NodeId = [u8; 32];

/// Дескриптор живёт сутки, нода переподписывает его заранее.
pub const DESCRIPTOR_TTL_MS: u64 = 24 * 60 * 60 * 1000;
/// Статистика старше этого — нода считается офлайн.
pub const STATS_FRESH_MS: u64 = 3 * 60 * 1000;
/// Допустимый сдвиг часов «в будущее».
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;
pub const MAX_ADDRESSES: usize = 8;
pub const MAX_PEERS_IN_STATS: usize = 64;
const MAX_TEXT: usize = 64;

const DESCRIPTOR_DOMAIN: &[u8] = b"CORE/v1/node-descriptor";
const STATS_DOMAIN: &[u8] = b"CORE/v1/node-stats";
const PEER_HELLO_DOMAIN: &[u8] = b"CORE/v1/peer-hello";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DirError {
    #[error("invalid key length")]
    BadKey,
    #[error("invalid signature")]
    BadSignature,
    #[error("record expired")]
    Expired,
    #[error("record is from the future")]
    FromFuture,
    #[error("malformed record: {0}")]
    Malformed(&'static str),
    #[error("unknown node")]
    UnknownNode,
}

pub fn node_id_of(ed25519_pk: &[u8]) -> NodeId {
    sha256(ed25519_pk)
}

fn signed_bytes<M: Message + Clone>(domain: &[u8], msg: &M, clear_sig: impl FnOnce(&mut M)) -> Vec<u8> {
    let mut unsigned = msg.clone();
    clear_sig(&mut unsigned);
    let mut out = domain.to_vec();
    out.extend_from_slice(&unsigned.encode_to_vec());
    out
}

// ───────────── Дескриптор ─────────────

pub fn sign_descriptor(d: &mut NodeDescriptor, key: &Ed25519Key) {
    d.ed25519_pk = key.public_key().to_vec();
    d.sig = key.sign(&signed_bytes(DESCRIPTOR_DOMAIN, d, |m| m.sig.clear())).to_vec();
}

/// Проверить дескриптор. Возвращает `node_id`.
pub fn verify_descriptor(d: &NodeDescriptor, now_ms: u64) -> Result<NodeId, DirError> {
    if d.ed25519_pk.len() != PUBLIC_KEY_LEN || d.x25519_pk.len() != PUBLIC_KEY_LEN {
        return Err(DirError::BadKey);
    }
    if d.sig.len() != SIGNATURE_LEN {
        return Err(DirError::BadSignature);
    }
    if d.addresses.is_empty() || d.addresses.len() > MAX_ADDRESSES {
        return Err(DirError::Malformed("addresses"));
    }
    if d.addresses.iter().any(|a| a.len() > 255 || !a.contains(':'))
        || d.roles.len() > 16
        || [&d.version, &d.region, &d.name].iter().any(|t| t.len() > MAX_TEXT)
    {
        return Err(DirError::Malformed("fields"));
    }
    if d.published_at_ms > now_ms + MAX_CLOCK_SKEW_MS {
        return Err(DirError::FromFuture);
    }
    if d.expires_at_ms <= now_ms || d.expires_at_ms > d.published_at_ms + 2 * DESCRIPTOR_TTL_MS {
        return Err(DirError::Expired);
    }
    if !verify(&d.ed25519_pk, &signed_bytes(DESCRIPTOR_DOMAIN, d, |m| m.sig.clear()), &d.sig) {
        return Err(DirError::BadSignature);
    }
    Ok(node_id_of(&d.ed25519_pk))
}

// ───────────── Статистика ─────────────

pub fn sign_stats(s: &mut NodeStats, key: &Ed25519Key) {
    s.node_id = node_id_of(&key.public_key()).to_vec();
    s.sig = key.sign(&signed_bytes(STATS_DOMAIN, s, |m| m.sig.clear())).to_vec();
}

pub fn verify_stats(s: &NodeStats, ed25519_pk: &[u8], now_ms: u64) -> Result<(), DirError> {
    if s.node_id.as_slice() != node_id_of(ed25519_pk) {
        return Err(DirError::UnknownNode);
    }
    if s.peers.len() > MAX_PEERS_IN_STATS || s.peers.iter().any(|p| p.len() != 32) || s.load > 10 {
        return Err(DirError::Malformed("stats"));
    }
    if s.published_at_ms > now_ms + MAX_CLOCK_SKEW_MS {
        return Err(DirError::FromFuture);
    }
    if s.published_at_ms + DESCRIPTOR_TTL_MS < now_ms {
        return Err(DirError::Expired);
    }
    if !verify(ed25519_pk, &signed_bytes(STATS_DOMAIN, s, |m| m.sig.clear()), &s.sig) {
        return Err(DirError::BadSignature);
    }
    Ok(())
}

// ───────────── PeerHello ─────────────

/// Подпись хеша Noise-сессии ключом идентичности ноды.
pub fn sign_session(key: &Ed25519Key, session_hash: &[u8]) -> Vec<u8> {
    let mut msg = PEER_HELLO_DOMAIN.to_vec();
    msg.extend_from_slice(session_hash);
    key.sign(&msg).to_vec()
}

pub fn verify_session(ed25519_pk: &[u8], session_hash: &[u8], sig: &[u8]) -> bool {
    let mut msg = PEER_HELLO_DOMAIN.to_vec();
    msg.extend_from_slice(session_hash);
    verify(ed25519_pk, &msg, sig)
}

// ───────────── Каталог ─────────────

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub descriptor: NodeDescriptor,
    pub stats: Option<NodeStats>,
}

impl DirEntry {
    pub fn is_online(&self, now_ms: u64) -> bool {
        self.stats.as_ref().is_some_and(|s| s.published_at_ms + STATS_FRESH_MS >= now_ms)
    }
}

#[derive(Debug, Default)]
pub struct Directory {
    nodes: BTreeMap<NodeId, DirEntry>,
}

impl Directory {
    /// Принять дескриптор. `Ok(true)` — это новость (стоит пересылать дальше).
    pub fn apply_descriptor(&mut self, d: NodeDescriptor, now_ms: u64) -> Result<bool, DirError> {
        let id = verify_descriptor(&d, now_ms)?;
        match self.nodes.get_mut(&id) {
            Some(e) if e.descriptor.published_at_ms >= d.published_at_ms => Ok(false),
            Some(e) => {
                e.descriptor = d;
                Ok(true)
            }
            None => {
                self.nodes.insert(id, DirEntry { descriptor: d, stats: None });
                Ok(true)
            }
        }
    }

    /// Принять статистику. Дескриптор ноды должен быть известен.
    pub fn apply_stats(&mut self, s: NodeStats, now_ms: u64) -> Result<bool, DirError> {
        let id: NodeId = s.node_id.as_slice().try_into().map_err(|_| DirError::UnknownNode)?;
        let entry = self.nodes.get_mut(&id).ok_or(DirError::UnknownNode)?;
        verify_stats(&s, &entry.descriptor.ed25519_pk, now_ms)?;
        if entry.stats.as_ref().is_some_and(|old| old.published_at_ms >= s.published_at_ms) {
            return Ok(false);
        }
        entry.stats = Some(s);
        Ok(true)
    }

    /// Удалить ноды с истёкшим дескриптором.
    pub fn prune(&mut self, now_ms: u64) -> usize {
        let before = self.nodes.len();
        self.nodes.retain(|_, e| e.descriptor.expires_at_ms > now_ms);
        before - self.nodes.len()
    }

    pub fn get(&self, id: &NodeId) -> Option<&DirEntry> {
        self.nodes.get(id)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&NodeId, &DirEntry)> {
        self.nodes.iter()
    }

    /// Страница снимка после `cursor` (не включая), пока влезает в `budget` байт.
    /// Возвращает ноды и курсор следующей страницы (`None` — конец).
    pub fn page(&self, cursor: Option<&NodeId>, budget: usize) -> (Vec<NetNode>, Option<NodeId>) {
        use std::ops::Bound::{Excluded, Unbounded};
        let start: std::ops::Bound<&NodeId> = cursor.map_or(Unbounded, Excluded);
        let mut size = 0;
        let mut out = vec![];
        let mut last = None;
        let mut iter = self.nodes.range::<NodeId, _>((start, Unbounded)).peekable();
        while let Some((id, e)) = iter.next() {
            let node = NetNode { descriptor: Some(e.descriptor.clone()), stats: e.stats.clone() };
            let len = node.encoded_len() + 8;
            if !out.is_empty() && size + len > budget {
                return (out, last);
            }
            size += len;
            out.push(node);
            last = Some(*id);
            if iter.peek().is_none() {
                return (out, None);
            }
        }
        (out, None)
    }
}

/// Клиентская проверка снимка: оставить только записи с верными подписями.
/// Статистика без валидной подписи отбрасывается, дескриптор остаётся.
pub fn verify_snapshot(nodes: Vec<NetNode>, now_ms: u64) -> Directory {
    let mut dir = Directory::default();
    let mut stats = vec![];
    for n in nodes {
        if let Some(d) = n.descriptor {
            if dir.apply_descriptor(d, now_ms).is_ok() {
                stats.extend(n.stats);
            }
        }
    }
    for s in stats {
        let _ = dir.apply_stats(s, now_ms);
    }
    dir
}

/// Связь рисуется, только если обе ноды называют друг друга соседями (§16.5).
pub fn mutual_links(dir: &Directory) -> Vec<(NodeId, NodeId)> {
    let claims: HashSet<(NodeId, NodeId)> = dir
        .iter()
        .filter_map(|(id, e)| e.stats.as_ref().map(|s| (id, s)))
        .flat_map(|(id, s)| s.peers.iter().filter_map(move |p| Some((*id, <NodeId>::try_from(p.as_slice()).ok()?))))
        .collect();
    let mut links: Vec<_> = claims.iter().filter(|(a, b)| a < b && claims.contains(&(*b, *a))).copied().collect();
    links.sort();
    links
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000_000;

    fn descriptor(key: &Ed25519Key, published: u64) -> NodeDescriptor {
        let mut d = NodeDescriptor {
            x25519_pk: vec![9; 32],
            addresses: vec!["127.0.0.1:7443".into()],
            roles: vec!["mailbox".into()],
            version: "0.1.0".into(),
            region: "NL".into(),
            name: "test".into(),
            published_at_ms: published,
            expires_at_ms: published + DESCRIPTOR_TTL_MS,
            ..Default::default()
        };
        sign_descriptor(&mut d, key);
        d
    }

    fn stats(key: &Ed25519Key, published: u64, peers: Vec<NodeId>) -> NodeStats {
        let mut s = NodeStats {
            peers: peers.into_iter().map(|p| p.to_vec()).collect(),
            clients_online: 10,
            load: 3,
            uptime_secs: 60,
            published_at_ms: published,
            ..Default::default()
        };
        sign_stats(&mut s, key);
        s
    }

    #[test]
    fn descriptor_sign_verify() {
        let key = Ed25519Key::generate();
        let d = descriptor(&key, NOW);
        assert_eq!(verify_descriptor(&d, NOW).unwrap(), node_id_of(&key.public_key()));

        let mut tampered = d.clone();
        tampered.addresses = vec!["6.6.6.6:1".into()];
        assert_eq!(verify_descriptor(&tampered, NOW), Err(DirError::BadSignature));

        // Чужой ключ подставить нельзя: node_id привязан к ключу, подпись не сойдётся.
        let mut swapped = d.clone();
        swapped.ed25519_pk = Ed25519Key::generate().public_key().to_vec();
        assert_eq!(verify_descriptor(&swapped, NOW), Err(DirError::BadSignature));

        assert_eq!(verify_descriptor(&d, NOW + DESCRIPTOR_TTL_MS + 1), Err(DirError::Expired));
        assert_eq!(verify_descriptor(&descriptor(&key, NOW + MAX_CLOCK_SKEW_MS + 1), NOW), Err(DirError::FromFuture));
    }

    #[test]
    fn directory_keeps_newest() {
        let key = Ed25519Key::generate();
        let mut dir = Directory::default();
        assert!(dir.apply_descriptor(descriptor(&key, NOW - 10), NOW).unwrap());
        assert!(!dir.apply_descriptor(descriptor(&key, NOW - 20), NOW).unwrap());
        assert!(dir.apply_descriptor(descriptor(&key, NOW), NOW).unwrap());
        assert_eq!(dir.len(), 1);

        assert!(dir.apply_stats(stats(&key, NOW - 5, vec![]), NOW).unwrap());
        assert!(!dir.apply_stats(stats(&key, NOW - 6, vec![]), NOW).unwrap());
        let id = node_id_of(&key.public_key());
        assert!(dir.get(&id).unwrap().is_online(NOW));
        assert!(!dir.get(&id).unwrap().is_online(NOW + STATS_FRESH_MS + 10));

        // Статистика, подписанная чужим ключом от имени этой ноды.
        let mut forged = stats(&Ed25519Key::generate(), NOW, vec![]);
        forged.node_id = id.to_vec();
        assert_eq!(dir.apply_stats(forged, NOW), Err(DirError::BadSignature));

        assert_eq!(dir.apply_stats(stats(&Ed25519Key::generate(), NOW, vec![]), NOW), Err(DirError::UnknownNode));
        assert_eq!(dir.prune(NOW + 2 * DESCRIPTOR_TTL_MS), 1);
    }

    #[test]
    fn pages_cover_everything() {
        let mut dir = Directory::default();
        let keys: Vec<_> = (0..40).map(|_| Ed25519Key::generate()).collect();
        for k in &keys {
            dir.apply_descriptor(descriptor(k, NOW), NOW).unwrap();
            dir.apply_stats(stats(k, NOW, vec![[1; 32]; 10]), NOW).unwrap();
        }
        let mut cursor = None;
        let mut seen = 0;
        let mut pages = 0;
        loop {
            let (nodes, next) = dir.page(cursor.as_ref(), 4000);
            assert!(!nodes.is_empty());
            seen += nodes.len();
            pages += 1;
            match next {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        assert_eq!(seen, 40);
        assert!(pages > 1);
    }

    #[test]
    fn links_must_be_mutual() {
        let (a, b, c) = (Ed25519Key::generate(), Ed25519Key::generate(), Ed25519Key::generate());
        let (ia, ib, ic) = (node_id_of(&a.public_key()), node_id_of(&b.public_key()), node_id_of(&c.public_key()));
        let nodes = vec![
            NetNode { descriptor: Some(descriptor(&a, NOW)), stats: Some(stats(&a, NOW, vec![ib, ic])) },
            NetNode { descriptor: Some(descriptor(&b, NOW)), stats: Some(stats(&b, NOW, vec![ia])) },
            // C не подтверждает связь с A.
            NetNode { descriptor: Some(descriptor(&c, NOW)), stats: Some(stats(&c, NOW, vec![])) },
        ];
        let dir = verify_snapshot(nodes, NOW);
        assert_eq!(dir.len(), 3);
        let links = mutual_links(&dir);
        assert_eq!(links, vec![if ia < ib { (ia, ib) } else { (ib, ia) }]);
    }

    #[test]
    fn session_signature() {
        let key = Ed25519Key::generate();
        let sig = sign_session(&key, b"hash-1");
        assert!(verify_session(&key.public_key(), b"hash-1", &sig));
        assert!(!verify_session(&key.public_key(), b"hash-2", &sig));
    }
}
