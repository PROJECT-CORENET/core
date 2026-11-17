//! Связывание устройств одного аккаунта (§11.3): одноразовый зашифрованный канал через очереди ноды.
//!
//! 1. Одно устройство показывает QR `core-link:…` — ноду, свою очередь и одноразовый ключ X25519.
//! 2. Другое сканирует, заводит свою очередь и шлёт `Hello`: свой ключ + (зашифровано общим секретом)
//!    адрес своей очереди и имя устройства. Дальше обе стороны говорят шифротекстом ChaCha20-Poly1305.
//! 3. Старое устройство (после подтверждения пользователем) отправляет снимок аккаунта: профиль,
//!    ссылки-приглашения во все чаты, флаги и историю — файлом в журнале на ноде, ключ — внутри канала.
//! 4. Новое устройство вступает во все чаты отдельным участником MLS (своя подпись, тот же id аккаунта):
//!    новые сообщения приходят на все устройства сразу, а состояние синхронизируется через «Избранное».
//!
//! Нода видит только две очереди и шифротекст. QR — единственный канал доверия, поэтому старое
//! устройство всегда спрашивает пользователя, прежде чем отдать аккаунт.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use core_crypto::{random_bytes, sha256, NoiseKeypair};
use core_net::{Client as NetClient, NetError, NodeAddr};
use core_proto::msg::{event, request, Event, QueueAck, QueueDel, QueueSend};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::payload::{b64, b64_opt, hex_bytes};
use crate::store::QueueRow;
use crate::{expect_done, key, new_queue, subscribe_queue, AttachmentRef, Error, Result, REQUEST_TIMEOUT};

pub const LINK_PREFIX: &str = "core-link:";
const KEY_LABEL: &[u8] = b"CORE/link/v1";

/// Чья это сторона канала: устройство, на котором аккаунт уже есть, или новое.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkRole {
    New,
    Existing,
}

/// Содержимое QR.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LinkOffer {
    pub v: u8,
    pub node: String,
    #[serde(with = "hex_bytes")]
    pub queue: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub pk: Vec<u8>,
    pub role: LinkRole,
    /// Имя показывающего устройства («MacBook», «iPhone»).
    pub name: String,
}

impl LinkOffer {
    pub fn encode(&self) -> String {
        format!("{LINK_PREFIX}{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).unwrap()))
    }

    pub fn decode(text: &str) -> Option<Self> {
        let body = text.trim().strip_prefix(LINK_PREFIX)?;
        let offer: Self = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).ok()?).ok()?;
        (offer.v == 1 && offer.pk.len() == 32 && !offer.queue.is_empty()).then_some(offer)
    }
}

#[derive(Serialize, Deserialize)]
struct Hello {
    #[serde(with = "hex_bytes")]
    pk: Vec<u8>,
    #[serde(with = "b64")]
    sealed: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct HelloInner {
    #[serde(with = "hex_bytes")]
    queue: Vec<u8>,
    name: String,
    role: LinkRole,
}

/// Сообщения внутри канала (после `Hello`).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub(crate) enum LinkMsg {
    /// Старое → новое: id аккаунта и снимок (зашифрованный файл в журнале на ноде канала).
    Account { account_id: String, snapshot: Box<AttachmentRef> },
    /// Новое → старое: снимок принят, вступаю в чаты.
    Linked,
    /// Пользователь отказал.
    Declined,
}

/// Снимок аккаунта для нового устройства.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub name: String,
    #[serde(default, with = "b64_opt")]
    pub avatar: Option<Vec<u8>>,
    #[serde(default)]
    pub media: Option<String>,
    /// Ссылка во «Избранное» (группа из своих устройств).
    #[serde(default)]
    pub saved: Option<SnapChat>,
    pub chats: Vec<SnapChat>,
    /// Настройки приложения (папки и т. п.): ключ → (значение, ts).
    #[serde(default)]
    pub app: Vec<(String, String, u64)>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct SnapChat {
    pub link: String,
    pub gid: String,
    pub title: String,
    pub custom_title: bool,
    pub pinned: bool,
    pub muted: bool,
    pub archived: bool,
    pub owner: bool,
    pub unread: u32,
    pub last_ms: u64,
    pub members: Vec<SnapMember>,
    pub messages: Vec<SnapMessage>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct SnapMember {
    pub id: String,
    pub name: String,
    #[serde(default, with = "b64_opt")]
    pub avatar: Option<Vec<u8>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct SnapMessage {
    pub id: String,
    pub sender: String,
    pub ts: u64,
    pub status: i64,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub att: Option<AttachmentRef>,
    #[serde(default)]
    pub reply_to: Option<String>,
    #[serde(default)]
    pub link: Option<crate::LinkPreview>,
    #[serde(default)]
    pub fwd: Option<String>,
    #[serde(default)]
    pub fwd_id: Option<String>,
    /// (эмодзи, ключ поставившего).
    #[serde(default)]
    pub reactions: Vec<(String, String)>,
    #[serde(default)]
    pub edited_ms: u64,
    #[serde(default)]
    pub edit_id: String,
}

struct Peer {
    queue: Vec<u8>,
    key: [u8; 32],
    name: String,
}

/// Одноразовый канал между двумя устройствами. Живёт, пока идёт связывание.
pub struct LinkChannel {
    pub(crate) conn: Arc<NetClient>,
    events: tokio::sync::Mutex<mpsc::Receiver<Event>>,
    pub(crate) node: String,
    queue: QueueRow,
    keys: NoiseKeypair,
    role: LinkRole,
    name: String,
    /// Открытый ключ из QR — участвует в выводе общего ключа с обеих сторон.
    offer_pk: [u8; 32],
    offer: Option<String>,
    peer: Mutex<Option<Peer>>,
}

fn derive(shared: &[u8; 32], offer_pk: &[u8; 32], scanner_pk: &[u8; 32]) -> [u8; 32] {
    let mut input = KEY_LABEL.to_vec();
    input.extend_from_slice(shared);
    input.extend_from_slice(offer_pk);
    input.extend_from_slice(scanner_pk);
    sha256(&input)
}

/// Шифрование с одноразовым nonce впереди (сообщений в канале несколько — нулевой nonce нельзя).
fn seal(key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    let nonce: [u8; 12] = random_bytes();
    let mut out = nonce.to_vec();
    out.extend(ChaCha20Poly1305::new(key.into()).encrypt(Nonce::from_slice(&nonce), plain).expect("encrypt"));
    out
}

fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < 12 {
        return Err(Error::Other("link: short message".into()));
    }
    ChaCha20Poly1305::new(key.into())
        .decrypt(Nonce::from_slice(&sealed[..12]), &sealed[12..])
        .map_err(|_| Error::Other("link: cannot decrypt".into()))
}

async fn connect(node: &str) -> Result<(Arc<NetClient>, mpsc::Receiver<Event>)> {
    let addr: NodeAddr = node.parse().map_err(|_| Error::Other(format!("bad node address {node}")))?;
    let (client, events) =
        tokio::time::timeout(REQUEST_TIMEOUT, NetClient::connect(&addr)).await.map_err(|_| NetError::Timeout)??;
    Ok((Arc::new(client), events))
}

impl LinkChannel {
    /// Показать QR: канал ждёт, пока его отсканирует другое устройство.
    pub async fn offer(node: &str, role: LinkRole, name: &str) -> Result<Self> {
        let (conn, events) = connect(node).await?;
        let queue = new_queue(&conn, "link", node).await?;
        subscribe_queue(&conn, &queue).await?;
        let keys = NoiseKeypair::generate();
        let offer = LinkOffer {
            v: 1,
            node: node.to_string(),
            queue: queue.sender_id.clone(),
            pk: keys.public.to_vec(),
            role,
            name: name.to_string(),
        }
        .encode();
        info!("🔗 link offer ({role:?}) on {}", crate::short(node));
        Ok(Self {
            conn,
            events: tokio::sync::Mutex::new(events),
            node: node.to_string(),
            queue,
            offer_pk: keys.public,
            keys,
            role,
            name: name.to_string(),
            offer: Some(offer),
            peer: Mutex::new(None),
        })
    }

    /// Отсканировали QR другого устройства: открываем канал и представляемся.
    pub async fn scan(qr: &str, role: LinkRole, name: &str) -> Result<Self> {
        let offer = LinkOffer::decode(qr).ok_or_else(|| Error::Other("Это не QR-код подключения устройства".into()))?;
        if offer.role == role {
            return Err(Error::Other(match role {
                LinkRole::New => "Этот QR — с нового устройства. Отсканируйте его устройством, где вы уже вошли".into(),
                LinkRole::Existing => {
                    "Этот QR — с устройства, где вы уже вошли. Отсканируйте QR нового устройства".into()
                }
            }));
        }
        let (conn, events) = connect(&offer.node).await?;
        let queue = new_queue(&conn, "link", &offer.node).await?;
        subscribe_queue(&conn, &queue).await?;
        let keys = NoiseKeypair::generate();
        let offer_pk: [u8; 32] = offer.pk.as_slice().try_into().unwrap();
        let k = derive(&keys.shared_secret(&offer_pk), &offer_pk, &keys.public);
        let inner = HelloInner { queue: queue.sender_id.clone(), name: name.to_string(), role };
        let hello = Hello { pk: keys.public.to_vec(), sealed: seal(&k, &serde_json::to_vec(&inner).unwrap()) };
        let body = serde_json::to_vec(&hello).unwrap();
        expect_done(
            conn.request(request::Body::QueueSend(QueueSend { sender_id: offer.queue.clone(), body }), None).await?,
        )?;
        info!("🔗 link hello sent to {:?} device «{}»", offer.role, offer.name);
        Ok(Self {
            conn,
            events: tokio::sync::Mutex::new(events),
            node: offer.node.clone(),
            queue,
            keys,
            role,
            name: name.to_string(),
            offer_pk,
            offer: None,
            peer: Mutex::new(Some(Peer { queue: offer.queue, key: k, name: offer.name })),
        })
    }

    /// Строка для QR (только у показывающей стороны).
    pub fn qr(&self) -> Option<String> {
        self.offer.clone()
    }

    pub fn role(&self) -> LinkRole {
        self.role
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Имя устройства на той стороне (известно сразу у сканирующего, после `Hello` — у показывающего).
    pub fn peer_name(&self) -> Option<String> {
        self.peer.lock().unwrap().as_ref().map(|p| p.name.clone())
    }

    /// Дождаться, пока QR отсканируют. Возвращает имя того устройства.
    pub async fn wait_peer(&self, timeout: Duration) -> Result<String> {
        if let Some(name) = self.peer_name() {
            return Ok(name);
        }
        tokio::time::timeout(timeout, async {
            loop {
                let body = self.next_body().await?;
                if self.peer.lock().unwrap().is_some() {
                    continue;
                }
                let Ok(hello) = serde_json::from_slice::<Hello>(&body) else { continue };
                let Ok(pk) = <[u8; 32]>::try_from(hello.pk.as_slice()) else { continue };
                let k = derive(&self.keys.shared_secret(&pk), &self.offer_pk, &pk);
                let Ok(plain) = open(&k, &hello.sealed) else {
                    debug!("link: hello with wrong key ignored");
                    continue;
                };
                let Ok(inner) = serde_json::from_slice::<HelloInner>(&plain) else { continue };
                if inner.role == self.role {
                    warn!("⚠️ link: peer has the same role, ignored");
                    continue;
                }
                info!("🔗 link peer «{}» connected", inner.name);
                let name = inner.name.clone();
                *self.peer.lock().unwrap() = Some(Peer { queue: inner.queue, key: k, name: inner.name });
                return Ok(name);
            }
        })
        .await
        .map_err(|_| Error::Other("Время ожидания истекло".into()))?
    }

    pub(crate) async fn send(&self, msg: &LinkMsg) -> Result<()> {
        let (queue, k) = {
            let peer = self.peer.lock().unwrap();
            let p = peer.as_ref().ok_or(Error::NotReady)?;
            (p.queue.clone(), p.key)
        };
        let body = seal(&k, &serde_json::to_vec(msg).unwrap());
        expect_done(self.conn.request(request::Body::QueueSend(QueueSend { sender_id: queue, body }), None).await?)
    }

    pub(crate) async fn recv(&self, timeout: Duration) -> Result<LinkMsg> {
        tokio::time::timeout(timeout, async {
            loop {
                let body = self.next_body().await?;
                let Some(k) = self.peer.lock().unwrap().as_ref().map(|p| p.key) else { continue };
                let Ok(plain) = open(&k, &body) else { continue };
                match serde_json::from_slice::<LinkMsg>(&plain) {
                    Ok(msg) => return Ok(msg),
                    Err(e) => debug!("link: unknown message: {e}"),
                }
            }
        })
        .await
        .map_err(|_| Error::Other("Время ожидания истекло".into()))?
    }

    /// Отказать той стороне (пользователь не подтвердил).
    pub async fn decline(&self) -> Result<()> {
        self.send(&LinkMsg::Declined).await
    }

    /// Следующее сообщение в нашей очереди (с подтверждением ноде).
    async fn next_body(&self) -> Result<Vec<u8>> {
        let mut events = self.events.lock().await;
        loop {
            let ev = events.recv().await.ok_or_else(|| Error::Other("Соединение с нодой потеряно".into()))?;
            let Some(event::Body::QueueMessage(m)) = ev.body else { continue };
            if m.recipient_id != self.queue.recipient_id {
                continue;
            }
            let ack = QueueAck { recipient_id: m.recipient_id.clone(), msg_id: m.msg_id };
            let _ = self.conn.request(request::Body::QueueAck(ack), Some(&key(&self.queue.recipient_sk))).await;
            return Ok(m.body);
        }
    }

    /// Убрать свою очередь с ноды.
    pub async fn close(&self) {
        let del = QueueDel { recipient_id: self.queue.recipient_id.clone() };
        let _ = self.conn.request(request::Body::QueueDel(del), Some(&key(&self.queue.recipient_sk))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offer_roundtrip() {
        let offer = LinkOffer {
            v: 1,
            node: "core://ab@host:1".into(),
            queue: vec![1, 2, 3],
            pk: vec![7; 32],
            role: LinkRole::New,
            name: "MacBook".into(),
        };
        let qr = offer.encode();
        assert!(qr.starts_with(LINK_PREFIX));
        assert_eq!(LinkOffer::decode(&qr), Some(offer));
        assert_eq!(LinkOffer::decode("core-invite:abc"), None);
    }

    #[test]
    fn sealed_messages_use_fresh_nonces() {
        let k = [3u8; 32];
        let (a, b) = (seal(&k, b"x"), seal(&k, b"x"));
        assert_ne!(a, b);
        assert_eq!(open(&k, &a).unwrap(), b"x");
        assert!(open(&[4u8; 32], &a).is_err());
    }
}
