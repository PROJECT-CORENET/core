//! Pseudonymous, expiring presence slots, separate from the chat journal.
use std::sync::atomic::{AtomicBool, Ordering};

use core_proto::msg::{PresencePut, PresenceUpdate, PresenceWatch, MAX_PRESENCE_WATCH, PRESENCE_ID_LEN};
use openmls_traits::signatures::Signer;
use tokio::sync::Notify;

use super::*;

const TTL: u32 = 40;
const HEARTBEAT: Duration = Duration::from_secs(15);
const DOMAIN: &[u8] = b"CORE/presence/v1\0";
type Slot = [u8; PRESENCE_ID_LEN];

#[derive(Default)]
pub(super) struct State {
    active: AtomicBool,
    changed: Arc<Notify>,
    watches: Mutex<HashMap<(String, Slot), Watch>>,
}

struct Watch {
    chat: String,
    account: String,
    leaf: Vec<u8>,
    key: [u8; 32],
}

impl Client {
    pub fn set_presence(&self, active: bool) {
        let state = &self.inner.presence;
        state.active.store(active, Ordering::Release);
        state.changed.notify_one();
    }
}

fn derive(purpose: &[u8], epoch: &[u8], leaf: &[u8]) -> [u8; 32] {
    core_crypto::sha256(&[DOMAIN, purpose, epoch, leaf].concat())
}

fn slot(epoch: &[u8], leaf: &[u8]) -> Slot {
    derive(b"slot", epoch, leaf)[..PRESENCE_ID_LEN].try_into().unwrap()
}

pub(super) async fn run(weak: std::sync::Weak<Inner>) {
    let Some(initial) = weak.upgrade() else { return };
    let changed = initial.presence.changed.clone();
    drop(initial);
    let mut was_active = false;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(HEARTBEAT) => {}
            _ = changed.notified() => {}
        }
        let Some(inner) = weak.upgrade() else { return };
        let active = inner.presence.active.load(Ordering::Acquire);
        if active || was_active {
            if let Err(error) = inner.refresh_presence(active).await {
                debug!("presence heartbeat failed: {error}");
            }
        }
        was_active = active;
    }
}

impl Inner {
    async fn refresh_presence(self: &Arc<Self>, active: bool) -> Result<()> {
        let mut by_node: HashMap<String, Vec<(Ed25519Key, PresencePut)>> = HashMap::new();
        let mut watches = HashMap::new();
        {
            let engine = self.engine.lock().await;
            let leaf = engine.signer.to_public_vec();
            for chat in self.store.chats()?.into_iter().filter(|c| c.state == ChatState::Active) {
                if self.saved_id().as_deref() == Some(&chat.id) || self.is_group(&chat) {
                    continue;
                }
                let Ok(group) = engine.group(&chat) else { continue };
                if !group.is_active() {
                    continue;
                }
                let epoch =
                    group.export_secret(engine.provider.crypto(), "CORE presence slots", &[], 32).map_err(mls)?;
                let members: Vec<_> = group
                    .members()
                    .filter_map(|m| {
                        let account = String::from_utf8(m.credential.serialized_content().to_vec()).ok()?;
                        if account == self.me || self.is_blocked(&account) {
                            return None;
                        }
                        Some((account, m.signature_key))
                    })
                    .collect();
                if members.is_empty() {
                    continue;
                }

                let own_slot = slot(&epoch, &leaf);
                let auth = Ed25519Key::from_bytes(&derive(b"write", &epoch, &leaf));
                let cipher_key = derive(b"sealed", &epoch, &leaf);
                let stamp = now_ms().to_be_bytes();
                let bytes = [&stamp[..], &[u8::from(active)]].concat();
                let signed = engine
                    .signer
                    .sign(&[DOMAIN, &own_slot, &bytes].concat())
                    .map_err(|_| Error::Other("presence signature failed".into()))?;
                let nonce = random_bytes::<12>();
                let plaintext = [&bytes, signed.as_slice()].concat();
                let sealed = ChaCha20Poly1305::new((&cipher_key).into())
                    .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
                    .expect("small presence payload");
                let put = PresencePut {
                    presence_id: own_slot.to_vec(),
                    write_pk: auth.public_key().to_vec(),
                    sealed: [&nonce[..], &sealed].concat(),
                    ttl_secs: if active { TTL } else { 0 },
                };
                by_node.entry(chat.node.clone()).or_default().push((auth, put));
                if active {
                    for (account, remote_leaf) in members {
                        let id = slot(&epoch, &remote_leaf);
                        watches.insert(
                            (chat.node.clone(), id),
                            Watch {
                                chat: chat.id.clone(),
                                account,
                                key: derive(b"sealed", &epoch, &remote_leaf),
                                leaf: remote_leaf,
                            },
                        );
                    }
                }
            }
        }
        let old = std::mem::replace(&mut *self.presence.watches.lock().unwrap(), watches);
        let mut ids: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        let mut cleared: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
        {
            let current = self.presence.watches.lock().unwrap();
            for (node, id) in current.keys() {
                ids.entry(node.clone()).or_default().push(id.to_vec());
            }
            for (node, id) in old.keys().filter(|key| !current.contains_key(*key)) {
                cleared.entry(node.clone()).or_default().push(id.to_vec());
            }
        }
        for node in cleared.keys() {
            by_node.entry(node.clone()).or_default();
        }
        let mut requests = tokio::task::JoinSet::new();
        for (node, updates) in by_node {
            let inner = self.clone();
            let watch = ids.remove(&node).unwrap_or_default();
            let unwatch = cleared.remove(&node).unwrap_or_default();
            requests.spawn(async move {
                let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_secs(3), inner.conn(&node)).await else {
                    return;
                };
                for id in unwatch {
                    let _ = conn.request(request::Body::Unsubscribe(core_proto::msg::Unsubscribe { id }), None).await;
                }
                for (auth, update) in updates {
                    let send = conn.request(request::Body::PresencePut(update), Some(&auth));
                    let _ = tokio::time::timeout(Duration::from_secs(3), send).await;
                }
                for chunk in watch.chunks(MAX_PRESENCE_WATCH) {
                    let send = conn
                        .request(request::Body::PresenceWatch(PresenceWatch { presence_ids: chunk.to_vec() }), None);
                    let _ = tokio::time::timeout(Duration::from_secs(3), send).await;
                }
            });
        }
        while requests.join_next().await.is_some() {}
        Ok(())
    }

    pub(super) fn presence_update(&self, node: &str, update: PresenceUpdate) {
        let Ok(id) = Slot::try_from(update.presence_id.as_slice()) else { return };
        let watches = self.presence.watches.lock().unwrap();
        let Some(watch) = watches.get(&(node.to_owned(), id)) else { return };
        let Some((nonce, ciphertext)) = update.sealed.split_at_checked(12) else { return };
        let Ok(plain) = ChaCha20Poly1305::new((&watch.key).into()).decrypt(Nonce::from_slice(nonce), ciphertext) else {
            return;
        };
        let Some((bytes, sig)) = plain.split_at_checked(9) else { return };
        if !core_crypto::verify(&watch.leaf, &[DOMAIN, &id, bytes].concat(), sig) {
            return;
        }
        let stamp = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let now = now_ms();
        if stamp > now.saturating_add(5_000) || now.saturating_sub(stamp) > (TTL as u64 + 5) * 1000 {
            return;
        }
        let online = update.online && bytes[8] == 1 && now.saturating_sub(stamp) < TTL as u64 * 1000;
        if self.is_blocked(&watch.account) {
            return;
        }
        if let Some(listener) = self.listener.read().unwrap().clone() {
            let state = if online { "online" } else { "offline" };
            listener.typing(watch.chat.clone(), watch.account.clone(), format!("{state}:{}", hex::encode(id)));
        }
    }
}
