//! Клиентское ядро CORE (§9–§11): аккаунт, чаты с E2E-шифрованием MLS (RFC 9420), приглашения,
//! вложения, локальная база. Транспорт — ноды: журнал на чат, очереди для приглашений.
//!
//! Как устроен чат:
//! 1. Создатель заводит MLS-группу, журнал на ноде и очередь-приглашение → ссылка `core-invite:…`.
//! 2. Вступающий кладёт в очередь свой KeyPackage и адрес очереди для ответа.
//! 3. Создатель добавляет его в группу (коммит — в журнал через compare-and-swap по эпохе),
//!    отвечает Welcome + ключами журнала, зашифрованными экспортёром MLS новой эпохи.
//! 4. Сообщения — MLS application messages в журнале; нода видит только шифротекст.

mod calls;
mod link;
mod media;
pub mod payload;
mod store;
mod sync;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use core_crypto::{random_bytes, Ed25519Key};
use core_net::{Client as NetClient, NetError, NodeAddr};
use core_proto::msg::{
    event, request, response, Event, LogAppend, LogCommit, LogEntry, LogNew, LogRead, LogWatch, QueueAck, QueueDel,
    QueueNew, QueueSend, QueueSub,
};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub use calls::{media as call_media, Call, CallPeer, MAX_VIDEO_FRAME, RING_TIMEOUT_MS};
pub use link::{LinkChannel, LinkOffer, LinkRole};
pub use payload::{AttachmentRef, DeviceRecord, Invite, LinkPreview};
use payload::{JoinReply, JoinRequest, LogCreds, MirrorCreds, Payload, SyncOp};
use store::{ChatRow, MemberRow, MessageRow, MirrorRow, QueueRow, Store};
pub use store::{ChatState, MessageStatus};
pub use sync::link_receive_account;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const CREDS_LABEL: &str = "CORE/v1/log-creds";
/// Прикладное сообщение должно поместиться в блоб журнала вместе с обёрткой MLS.
const MAX_PAYLOAD: usize = 12 * 1024;
/// Общая настройка аккаунта со списком заблокированных (id собеседников).
pub const BLOCKED_KEY: &str = "blocked";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const RECONNECT_EVERY: Duration = Duration::from_secs(3);
/// Нода чата недоступна дольше этого — переезжаем на резервный журнал.
const FAILOVER_AFTER: Duration = Duration::from_secs(45);

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("network: {0}")]
    Net(#[from] NetError),
    #[error("node refused: {0}")]
    Node(String),
    #[error("storage: {0}")]
    Store(#[from] rusqlite::Error),
    #[error("mls: {0}")]
    Mls(String),
    #[error("invalid invite link")]
    BadInvite,
    #[error("chat not found")]
    NoChat,
    #[error("chat is not ready yet")]
    NotReady,
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

fn mls<E: std::fmt::Debug>(e: E) -> Error {
    Error::Mls(format!("{e:?}"))
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

fn new_id() -> String {
    hex::encode(random_bytes::<12>())
}

fn key(bytes: &[u8]) -> Ed25519Key {
    Ed25519Key::from_bytes(bytes.try_into().expect("32-byte key"))
}

/// Колбэк для интерфейса: что-то изменилось (в чате `chat_id` или в списке чатов).
pub trait Listener: Send + Sync {
    fn changed(&self, chat_id: Option<String>);
    /// Участник `member_id` печатает или что-то отправляет (`kind`: text, voice, photo, file).
    fn typing(&self, _chat_id: String, _member_id: String, _kind: String) {}
    /// Другое устройство аккаунта изменило настройку приложения `key` (папки и т. п.) или список устройств (`devices`).
    fn synced(&self, _key: String) {}
    /// Звонок изменился: вызов, ответ, конец, кто-то вошёл/вышел, выключил микрофон или камеру.
    fn call_changed(&self, _call_id: String) {}
    /// Кадр звонка от участника `peer` (`kind` — `call_media::*`). Вызывается часто и не на главном потоке.
    fn call_media(&self, _call_id: String, _peer: String, _kind: u8, _data: Vec<u8>) {}
}

// ───────────────────────────── Публичные модели ─────────────────────────────

#[derive(Clone, Debug)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub avatar: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct Chat {
    pub id: String,
    pub title: String,
    pub is_group: bool,
    pub state: ChatState,
    pub node: String,
    pub unread: u32,
    pub muted: bool,
    pub pinned: bool,
    pub last_ms: u64,
    pub last_message: Option<Message>,
    pub avatar: Option<Vec<u8>>,
    pub members: Vec<Member>,
    pub can_invite: bool,
    /// Чат «Избранное».
    pub is_saved: bool,
    /// Группу создали мы: можем удалять участников.
    pub is_owner: bool,
    /// Нода резервного журнала (переписка переедет туда, если нода чата пропадёт).
    pub backup_node: Option<String>,
    /// В архиве: скрыт из основного списка. Новое сообщение возвращает чат, если он не заглушён.
    pub archived: bool,
    /// MLS group id (hex) — одинаковый на всех устройствах аккаунта, в отличие от локального `id`.
    pub gid: Option<String>,
}

/// Устройство аккаунта (для списка устройств и карты сети).
#[derive(Clone, Debug)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub node: String,
    pub is_this: bool,
    /// Когда устройство последний раз о себе сообщало (мс).
    pub seen_ms: u64,
}

#[derive(Clone, Debug)]
pub struct Member {
    pub id: String,
    pub name: String,
    pub avatar: Option<Vec<u8>>,
    pub is_me: bool,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub id: String,
    pub chat_id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub outgoing: bool,
    pub ts: u64,
    pub text: String,
    pub status: MessageStatus,
    pub attachment: Option<AttachmentRef>,
    pub local_path: Option<String>,
    pub reply_to: Option<String>,
    pub link: Option<LinkPreview>,
    /// Пересланное: имя автора оригинала.
    pub forwarded_from: Option<String>,
    /// Ключ автора оригинала (открыть профиль). Нет — пересылающий не знал его.
    pub forwarded_from_id: Option<String>,
    /// Реакции в порядке появления.
    pub reactions: Vec<Reaction>,
    pub edited_ms: u64,
}

/// Одна реакция под сообщением: эмодзи, сколько поставили и есть ли среди них моя.
#[derive(Clone, Debug, PartialEq)]
pub struct Reaction {
    pub emoji: String,
    pub count: u32,
    pub mine: bool,
    /// Кто поставил — ключи участников в порядке появления.
    pub senders: Vec<String>,
}

/// Реакция — одно эмодзи (с модификаторами), не произвольный текст.
const MAX_REACTION_BYTES: usize = 32;

/// Автор пересылаемого: имя и, если известен, ключ.
#[derive(Clone, Debug)]
struct Forward {
    name: String,
    id: Option<String>,
}

impl Forward {
    fn new(name: &str, id: Option<String>) -> Option<Self> {
        let name = name.trim();
        (!name.is_empty()).then(|| Self { name: name.to_string(), id: id.filter(|k| Self::valid_id(k)) })
    }

    /// Ключ участника — 64 hex-символа.
    fn valid_id(key: &str) -> bool {
        key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit())
    }
}

/// Новое вложение от интерфейса: файл уже на диске, превью и метаданные посчитаны на устройстве.
#[derive(Clone, Debug, Default)]
pub struct OutgoingAttachment {
    pub path: String,
    pub kind: String,
    pub name: String,
    pub mime: String,
    pub thumb: Option<Vec<u8>>,
    pub width: u32,
    pub height: u32,
    pub duration_ms: u64,
    pub waveform: Option<Vec<u8>>,
    /// Показать получателю размытым до нажатия.
    pub spoiler: bool,
    pub spoiler_hearts: bool,
    /// Пересылка: имя автора оригинала.
    pub forwarded_from: Option<String>,
    /// Пересылка: ключ автора оригинала.
    pub forwarded_from_id: Option<String>,
}

/// Что скачивать само и сколько места отдавать под файлы.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MediaSettings {
    pub auto_photos: bool,
    pub auto_videos: bool,
    pub auto_voice: bool,
    pub auto_files: bool,
    /// Автоматически качаются только файлы не больше этого размера.
    pub auto_max_bytes: u64,
    /// Предел кэша вложений; 0 — без ограничений. Сверх предела удаляются самые старые файлы.
    pub cache_limit_bytes: u64,
}

impl Default for MediaSettings {
    fn default() -> Self {
        Self {
            auto_photos: true,
            auto_videos: true,
            auto_voice: true,
            auto_files: false,
            auto_max_bytes: media::AUTO_DOWNLOAD,
            cache_limit_bytes: 0,
        }
    }
}

impl MediaSettings {
    fn auto_download(&self, a: &AttachmentRef) -> bool {
        let kind = match a.kind.as_str() {
            "photo" => self.auto_photos,
            "video" | "video_note" => self.auto_videos,
            "voice" => self.auto_voice,
            _ => self.auto_files,
        };
        kind && a.size <= self.auto_max_bytes
    }
}

#[derive(Clone, Debug, Default)]
pub struct StorageUsage {
    pub photos: u64,
    pub videos: u64,
    pub voice: u64,
    pub files: u64,
    pub database: u64,
}

const MEDIA_SETTINGS_KEY: &str = "media_settings";
const SAVED_CHAT_KEY: &str = "saved_chat";
const SAVED_TITLE: &str = "Избранное";
/// Снимок аккаунта от другого устройства ещё не разобран (вступаем в чаты).
const LINK_PENDING_KEY: &str = "link.pending";
const DEVICE_ID_KEY: &str = "device.id";
/// Сколько последних сообщений каждого чата уходит новому устройству.
const LINK_HISTORY: u32 = 1000;

// ───────────────────────────── Клиент ─────────────────────────────

#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    store: Store,
    me: String,
    engine: tokio::sync::Mutex<Engine>,
    conns: Mutex<HashMap<String, Arc<NetClient>>>,
    push_nodes: Mutex<std::collections::HashSet<String>>,
    connecting: tokio::sync::Mutex<()>,
    events: mpsc::UnboundedSender<(String, Event)>,
    listener: RwLock<Option<Arc<dyn Listener>>>,
    default_node: RwLock<String>,
    downloading: Mutex<std::collections::HashSet<String>>,
    /// Сообщения, которые сейчас отправляются (повтор не запускается второй раз).
    sending: Mutex<std::collections::HashSet<String>>,
    /// Чтобы «Избранное» не создалось дважды при одновременных вызовах.
    saved_lock: tokio::sync::Mutex<()>,
    /// Ноды, где можно заводить резервные журналы (обычно — основная сеть пользователя).
    backup_nodes: RwLock<Vec<String>>,
    mirror_lock: tokio::sync::Mutex<()>,
    /// С какого момента нода не отвечает.
    down_since: Mutex<HashMap<String, Instant>>,
    failover_after: RwLock<Duration>,
    /// Чаты, по которым скоро уйдёт отчёт о доставке (один на пачку сообщений).
    delivery_pending: Mutex<std::collections::HashSet<String>>,
    /// Рантайм, в котором открыт клиент: синхронные вызовы из приложения (не из tokio) запускают фон через него.
    rt: tokio::runtime::Handle,
    calls: calls::Calls,
}

struct InFlight<'a> {
    ids: &'a Mutex<std::collections::HashSet<String>>,
    id: &'a str,
}

impl<'a> InFlight<'a> {
    fn claim(ids: &'a Mutex<std::collections::HashSet<String>>, id: &'a str) -> Option<Self> {
        ids.lock().unwrap().insert(id.to_owned()).then(|| Self { ids, id })
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.ids.lock().unwrap().remove(self.id);
    }
}

/// Всё, что меняет состояние MLS, — строго по очереди под этим замком.
struct Engine {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
}

impl Engine {
    fn create_config() -> MlsGroupCreateConfig {
        MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .padding_size(64)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(32, 5000))
            .build()
    }

    fn join_config() -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .padding_size(64)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(32, 5000))
            .build()
    }

    fn group(&self, chat: &ChatRow) -> Result<MlsGroup> {
        let gid = chat.group_id.as_ref().ok_or(Error::NotReady)?;
        MlsGroup::load(self.provider.storage(), &GroupId::from_slice(gid))
            .map_err(mls)?
            .ok_or_else(|| Error::Mls("group state missing".into()))
    }

    fn save(&self, store: &Store) -> Result<()> {
        store.save_mls(&self.provider.storage().values.read().unwrap())?;
        Ok(())
    }

    fn creds_key(&self, group: &MlsGroup) -> Result<[u8; 32]> {
        let k = group.export_secret(self.provider.crypto(), CREDS_LABEL, &[], 32).map_err(mls)?;
        Ok(k.try_into().unwrap())
    }
}

fn seal(key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    ChaCha20Poly1305::new(key.into()).encrypt(Nonce::from_slice(&[0; 12]), plain).expect("encrypt")
}

fn open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(key.into())
        .decrypt(Nonce::from_slice(&[0; 12]), sealed)
        .map_err(|_| Error::Mls("cannot decrypt log credentials".into()))
}

impl Client {
    /// Открыть (или создать) аккаунт в каталоге `dir`. `default_node` — нода для новых чатов.
    pub async fn open(dir: &Path, default_node: &str) -> Result<Self> {
        Self::open_with_key(dir, default_node, None).await
    }

    /// То же, но база зашифрована SQLCipher ключом `db_key` (32 байта; хранит приложение —
    /// например, под Secure Enclave). Старая открытая база шифруется при первом открытии.
    pub async fn open_with_key(dir: &Path, default_node: &str, db_key: Option<&[u8]>) -> Result<Self> {
        std::fs::create_dir_all(dir.join("media")).map_err(|e| Error::Other(e.to_string()))?;
        if db_key.is_some_and(|k| k.len() != 32) {
            return Err(Error::Other("database key must be 32 bytes".into()));
        }
        let store = Store::open(&dir.join("client.db"), db_key)?;
        let moved = store.rebase_media(&dir.join("media"))?;
        if moved > 0 {
            info!("📁 media paths moved to the current data dir: {moved}");
        }

        let provider = OpenMlsRustCrypto::default();
        *provider.storage().values.write().unwrap() = store.load_mls()?;

        // id аккаунта общий для всех устройств (на новом его кладёт связывание), подпись MLS — своя у каждого.
        let me = match store.get("account.id")? {
            Some(id) => String::from_utf8(id).unwrap(),
            None => {
                let id = hex::encode(random_bytes::<16>());
                store.set("account.id", id.as_bytes())?;
                info!("🆔 new account {id}");
                id
            }
        };
        let signer: SignatureKeyPair = match store.get("account.signer")? {
            Some(signer) => serde_json::from_slice(&signer).map_err(mls)?,
            None => {
                let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls)?;
                store.set("account.signer", &serde_json::to_vec(&signer).map_err(mls)?)?;
                signer
            }
        };
        store.set(sync::SIG_KEY, sync::sig_hex(&signer).as_bytes())?;
        if store.get(DEVICE_ID_KEY)?.is_none() {
            store.set(DEVICE_ID_KEY, hex::encode(random_bytes::<8>()).as_bytes())?;
        }
        signer.store(provider.storage()).map_err(mls)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(me.as_bytes().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };

        let (tx, rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            dir: dir.to_path_buf(),
            store,
            me,
            engine: tokio::sync::Mutex::new(Engine { provider, signer, credential }),
            conns: Mutex::default(),
            push_nodes: Mutex::default(),
            connecting: tokio::sync::Mutex::new(()),
            events: tx,
            listener: RwLock::new(None),
            default_node: RwLock::new(default_node.to_string()),
            downloading: Mutex::default(),
            sending: Mutex::default(),
            saved_lock: tokio::sync::Mutex::default(),
            backup_nodes: RwLock::default(),
            mirror_lock: tokio::sync::Mutex::default(),
            delivery_pending: Mutex::default(),
            rt: tokio::runtime::Handle::current(),
            down_since: Mutex::default(),
            failover_after: RwLock::new(FAILOVER_AFTER),
            calls: calls::Calls::default(),
        });
        tokio::spawn(event_worker(Arc::downgrade(&inner), rx));
        tokio::spawn(reconnect_loop(Arc::downgrade(&inner)));
        tokio::spawn(retry_loop(Arc::downgrade(&inner)));
        tokio::spawn(mirror_read_loop(Arc::downgrade(&inner)));
        let client = Self { inner };
        {
            // Догрузка пропущенного: пока приложение было закрыто, загрузка прервалась или файл
            // пришёл с другого своего устройства. Чуть позже — чтобы успело подняться соединение.
            // Слабая ссылка: закрытый за это время клиент не держит базу открытой.
            let weak = Arc::downgrade(&client.inner);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                if let Some(inner) = weak.upgrade() {
                    inner.resume_downloads().await;
                }
            });
        }
        if client.inner.store.get(LINK_PENDING_KEY)?.is_some() {
            let c = client.clone();
            tokio::spawn(async move { c.finish_link().await });
        }
        Ok(client)
    }

    pub fn set_listener(&self, listener: Arc<dyn Listener>) {
        *self.inner.listener.write().unwrap() = Some(listener);
    }

    pub async fn register_push(
        &self,
        gateway: &str,
        sandbox: bool,
        alert: Option<Vec<u8>>,
        voip: Option<Vec<u8>>,
    ) -> Result<()> {
        let inner = &self.inner;
        let gateway = inner.conn(gateway).await?;
        let mut first_error = None;
        for chat in inner.store.chats()?.into_iter().filter(|chat| chat.state == ChatState::Active) {
            if inner.saved_id().as_deref() == Some(&chat.id) {
                continue;
            }
            if let Err(error) =
                inner.register_log_push(&gateway, &chat, sandbox, alert.as_deref(), voip.as_deref()).await
            {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub fn set_default_node(&self, node: &str) {
        *self.inner.default_node.write().unwrap() = node.to_string();
    }

    pub fn data_dir(&self) -> &Path {
        &self.inner.dir
    }

    /// Ноды для резервных журналов. Для чатов без резерва он заводится сразу (в фоне).
    pub fn set_backup_nodes(&self, nodes: Vec<String>) {
        *self.inner.backup_nodes.write().unwrap() = nodes;
        let inner = self.inner.clone();
        tokio::spawn(async move { inner.ensure_mirrors().await });
    }

    /// Через сколько недоступности ноды переезжать на резерв (по умолчанию 45 с; для тестов).
    pub fn set_failover_after(&self, after: Duration) {
        *self.inner.failover_after.write().unwrap() = after;
    }

    /// Завести недостающие резервные журналы и дождаться результата.
    pub async fn ensure_mirrors(&self) {
        self.inner.ensure_mirrors().await;
    }

    // ── профиль ──

    pub fn profile(&self) -> Result<Profile> {
        let s = &self.inner.store;
        Ok(Profile {
            id: self.inner.me.clone(),
            name: s.get("profile.name")?.map(|v| String::from_utf8_lossy(&v).into_owned()).unwrap_or_default(),
            avatar: s.get("profile.avatar")?,
        })
    }

    /// Сохранить имя/аватар и разослать во все чаты (внутри MLS — нода их не видит).
    pub async fn set_profile(&self, name: &str, avatar: Option<Vec<u8>>) -> Result<()> {
        let s = &self.inner.store;
        s.set("profile.name", name.trim().as_bytes())?;
        match &avatar {
            Some(a) => s.set("profile.avatar", a)?,
            None => s.delete("profile.avatar")?,
        }
        for chat in s.chats()?.into_iter().filter(|c| c.state == ChatState::Active) {
            if let Err(e) = self.inner.send_payload(&chat, &self.inner.profile_payload()?).await {
                warn!("⚠️ profile broadcast to {} failed: {e}", chat.id);
            }
        }
        self.inner.notify(None);
        Ok(())
    }

    // ── чаты ──

    /// Новый чат: MLS-группа, журнал и очередь-приглашение на ноде. Возвращает (id чата, ссылку).
    pub async fn create_chat(&self, title: Option<&str>) -> Result<(String, String)> {
        let chat = self.create_group(title).await?;
        let link = self.invite_link(&chat.id).await?;
        self.inner.notify(None);
        self.inner.announce_chat(&chat.id);
        Ok((chat.id, link))
    }

    /// «Избранное»: MLS-группа из одного участника со своим журналом на ноде
    /// (заметки и пересланное; основа для синхронизации между своими устройствами).
    pub async fn saved_chat(&self) -> Result<String> {
        let _guard = self.inner.saved_lock.lock().await;
        if let Some(id) = self.inner.saved_id() {
            if self.inner.store.chat(&id)?.is_some() {
                return Ok(id);
            }
        }
        // Новое устройство ещё вступает в «Избранное» аккаунта — своё заводить нельзя.
        if self.inner.store.get(LINK_PENDING_KEY)?.is_some() {
            return Err(Error::NotReady);
        }
        let chat = self.create_group(Some(SAVED_TITLE)).await?;
        self.inner.store.set(SAVED_CHAT_KEY, chat.id.as_bytes())?;
        info!("⭐ saved messages chat {}", chat.id);
        self.inner.notify(None);
        Ok(chat.id)
    }

    async fn create_group(&self, title: Option<&str>) -> Result<ChatRow> {
        let node = self.inner.default_node.read().unwrap().clone();
        let conn = self.inner.conn(&node).await?;
        let (write, read) = (Ed25519Key::generate(), Ed25519Key::generate());
        let log_id = random_bytes::<32>().to_vec();
        expect_done(
            conn.request(
                request::Body::LogNew(LogNew {
                    log_id: log_id.clone(),
                    write_pk: write.public_key().to_vec(),
                    read_pk: read.public_key().to_vec(),
                }),
                None,
            )
            .await?,
        )?;

        let engine = self.inner.engine.lock().await;
        let group =
            MlsGroup::new(&engine.provider, &engine.signer, &Engine::create_config(), engine.credential.clone())
                .map_err(mls)?;
        engine.save(&self.inner.store)?;
        drop(engine);

        let title = title.map(str::trim).filter(|t| !t.is_empty());
        let chat = ChatRow {
            id: new_id(),
            group_id: Some(group.group_id().as_slice().to_vec()),
            title: title.unwrap_or("Новый чат").to_string(),
            custom_title: title.is_some(),
            node: node.clone(),
            log_id,
            write_sk: write.to_bytes().to_vec(),
            read_sk: read.to_bytes().to_vec(),
            read_offset: 0,
            state: ChatState::Active,
            created_ms: now_ms(),
            last_ms: now_ms(),
            unread: 0,
            muted: false,
            pinned: false,
        };
        self.inner.store.insert_chat(&chat)?;
        self.inner.store.set(&owner_key(&chat.id), b"1")?;
        self.inner.watch_chat(&conn, &chat).await?;
        info!("💬 chat {} created on {}", chat.id, short(&node));
        Ok(chat)
    }

    /// Ссылка-приглашение в чат (создаёт очередь при первом вызове). Многоразовая.
    pub async fn invite_link(&self, chat_id: &str) -> Result<String> {
        if self.inner.saved_id().as_deref() == Some(chat_id) {
            return Err(Error::Other("saved messages can't be shared".into()));
        }
        self.inner.invite_link(chat_id).await
    }

    /// Вступить по ссылке. Чат появляется сразу в состоянии `Joining`, Welcome приходит асинхронно.
    pub async fn accept_invite(&self, link: &str) -> Result<String> {
        self.inner.accept_invite(link, None).await
    }

    pub fn chats(&self) -> Result<Vec<Chat>> {
        let mut out = vec![];
        for row in self.inner.store.chats()? {
            out.push(self.inner.chat_model(row)?);
        }
        out.sort_by(|a, b| b.pinned.cmp(&a.pinned).then(b.last_ms.cmp(&a.last_ms)));
        Ok(out)
    }

    pub fn chat(&self, chat_id: &str) -> Result<Chat> {
        let row = self.inner.store.chat(chat_id)?.ok_or(Error::NoChat)?;
        self.inner.chat_model(row)
    }

    pub fn messages(&self, chat_id: &str, limit: u32, before: Option<&str>) -> Result<Vec<Message>> {
        let names = self.inner.member_names(chat_id)?;
        Ok(self
            .inner
            .store
            .messages(chat_id, limit, before)?
            .into_iter()
            .map(|m| self.inner.message_model(m, &names))
            .collect())
    }

    pub async fn rename_chat(&self, chat_id: &str, title: &str) -> Result<()> {
        let chat = self.inner.store.chat(chat_id)?.ok_or(Error::NoChat)?;
        let title = title.trim();
        self.inner.store.set_title(chat_id, title, !title.is_empty())?;
        self.inner.send_payload(&chat, &Payload::Title { title: title.to_string() }).await?;
        self.inner.notify(Some(chat_id.into()));
        Ok(())
    }

    /// Удалить участника из группы (MLS-коммит: он больше не расшифрует новые сообщения).
    pub async fn remove_member(&self, chat_id: &str, member_id: &str) -> Result<()> {
        self.inner.remove_member(chat_id, member_id).await
    }

    /// Выйти из группы: попросить оставшихся удалить нас и убрать чат с устройства.
    pub async fn leave_chat(&self, chat_id: &str) -> Result<()> {
        if let Some(chat) = self.inner.store.chat(chat_id)?.filter(|c| c.state == ChatState::Active) {
            if let Err(e) = self.inner.send_payload(&chat, &Payload::Leave).await {
                warn!("⚠️ leave notice for chat {chat_id} not delivered: {e}");
            }
        }
        info!("👋 left chat {chat_id}");
        self.delete_chat(chat_id)
    }

    pub fn set_muted(&self, chat_id: &str, muted: bool) -> Result<()> {
        self.inner.store.set_flag(chat_id, "muted", muted)?;
        self.inner.notify(Some(chat_id.into()));
        self.inner.sync_flags(chat_id);
        Ok(())
    }

    /// «Печатает…»: сообщить участникам, что мы набираем текст или готовим вложение.
    /// Частоту ограничивает приложение (раз в несколько секунд).
    pub async fn send_typing(&self, chat_id: &str, kind: &str) -> Result<()> {
        let chat = self.inner.store.chat(chat_id)?.ok_or(Error::NoChat)?;
        if chat.state != ChatState::Active || self.inner.saved_id().as_deref() == Some(chat_id) {
            return Ok(());
        }
        self.inner.send_payload(&chat, &Payload::Typing { kind: kind.into(), ts: now_ms() }).await.map(drop)
    }

    /// Убрать в архив / вернуть. Сообщения и участие в чате не меняются.
    pub fn set_archived(&self, chat_id: &str, archived: bool) -> Result<()> {
        if archived {
            self.inner.store.set(&archive_key(chat_id), b"1")?;
        } else {
            self.inner.store.delete(&archive_key(chat_id))?;
        }
        self.inner.notify(None);
        self.inner.sync_flags(chat_id);
        Ok(())
    }

    pub fn set_pinned(&self, chat_id: &str, pinned: bool) -> Result<()> {
        self.inner.store.set_flag(chat_id, "pinned", pinned)?;
        self.inner.notify(None);
        self.inner.sync_flags(chat_id);
        Ok(())
    }

    /// Прочитано: сбросить счётчик и отправить отчёт о прочтении участникам.
    pub async fn mark_read(&self, chat_id: &str) -> Result<()> {
        let had = self.inner.store.clear_unread(chat_id)?;
        if had > 0 {
            if let Some(chat) = self.inner.store.chat(chat_id)?.filter(|c| c.state == ChatState::Active) {
                let up_to = self.inner.store.max_incoming_ts(chat_id)?;
                // Отчёт о прочтении уходит и своим устройствам (они в той же группе) — у них счётчик тоже сбросится.
                self.inner.send_payload(&chat, &Payload::Read { up_to }).await?;
            }
            self.inner.notify(None);
        }
        Ok(())
    }

    pub fn mark_unread(&self, chat_id: &str) -> Result<()> {
        self.inner.store.touch_chat(chat_id, 0, 1)?;
        self.inner.notify(None);
        if let Some(gid) = self.inner.gid(chat_id) {
            self.inner.sync(SyncOp::MarkUnread { gid });
        }
        Ok(())
    }

    /// Удалить чат на этом устройстве (участники продолжат переписку без нас).
    pub fn delete_chat(&self, chat_id: &str) -> Result<()> {
        if let Some(gid) = self.inner.gid(chat_id) {
            self.inner.sync(SyncOp::DeleteChat { gid });
        }
        self.inner.delete_chat(chat_id)
    }

    pub fn clear_history(&self, chat_id: &str) -> Result<()> {
        self.inner.store.clear_history(chat_id)?;
        self.inner.notify(Some(chat_id.into()));
        if let Some(gid) = self.inner.gid(chat_id) {
            self.inner.sync(SyncOp::ClearHistory { gid });
        }
        Ok(())
    }

    pub fn drafts(&self) -> Result<std::collections::HashMap<String, String>> {
        Ok(self.inner.store.drafts()?)
    }

    pub fn set_draft(&self, chat_id: &str, text: &str) -> Result<()> {
        Ok(self.inner.store.set_draft(chat_id, text)?)
    }

    // ── сообщения ──

    /// `link` — превью ссылки, подготовленное на устройстве отправителя (необязательно).
    pub async fn send_text(
        &self,
        chat_id: &str,
        text: &str,
        reply_to: Option<String>,
        link: Option<LinkPreview>,
    ) -> Result<String> {
        let text = text.trim();
        if text.is_empty() {
            return Err(Error::Other("empty message".into()));
        }
        let link = link.and_then(LinkPreview::sanitized);
        self.inner.send_message(chat_id, text.to_string(), None, reply_to, None, link, None).await
    }

    /// Переслать текст: у получателя над ним будет «Переслано от `from`»; по `from_id` открывается профиль автора.
    pub async fn forward_text(
        &self,
        chat_id: &str,
        text: &str,
        link: Option<LinkPreview>,
        from: &str,
        from_id: Option<String>,
    ) -> Result<String> {
        let text = text.trim();
        if text.is_empty() {
            return Err(Error::Other("empty message".into()));
        }
        let link = link.and_then(LinkPreview::sanitized);
        let from = Forward::new(from, from_id);
        self.inner.send_message(chat_id, text.to_string(), None, None, None, link, from).await
    }

    /// Отправить файл: копия кладётся в медиатеку, шифруется и выгружается кусками в отдельный журнал.
    pub async fn send_attachment(&self, chat_id: &str, att: OutgoingAttachment, caption: &str) -> Result<String> {
        let id = new_id();
        self.send_attachment_with_id(chat_id, att, caption, id).await
    }

    /// Stable id allows the share queue to retry its hand-off after the app was terminated.
    pub async fn accept_shared(
        &self,
        chat_id: &str,
        id: String,
        text: &str,
        attachment: Option<OutgoingAttachment>,
    ) -> Result<()> {
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Other("invalid shared message id".into()));
        }
        if let Some(message) = self.inner.store.message(&id)? {
            return if message.chat_id == chat_id && message.outgoing {
                Ok(())
            } else {
                Err(Error::Other("shared message id already in use".into()))
            };
        }
        let result = match attachment {
            Some(attachment) => self.send_attachment_with_id(chat_id, attachment, text, id.clone()).await,
            None if !text.trim().is_empty() => {
                self.inner.send_message(chat_id, text.trim().into(), None, None, Some(id.clone()), None, None).await
            }
            None => return Err(Error::Other("empty shared message".into())),
        };
        // Once persisted, the normal outbox owns delivery, even if the first attempt failed.
        if self.inner.store.message(&id)?.is_some_and(|m| m.chat_id == chat_id && m.outgoing) {
            return Ok(());
        }
        result.map(drop)
    }

    async fn send_attachment_with_id(
        &self,
        chat_id: &str,
        att: OutgoingAttachment,
        caption: &str,
        id: String,
    ) -> Result<String> {
        let ext = Path::new(&att.name).extension().and_then(|e| e.to_str()).unwrap_or("bin");
        let local = self.inner.dir.join("media").join(format!("{id}.{ext}"));
        std::fs::copy(&att.path, &local).map_err(|e| Error::Other(format!("read file: {e}")))?;
        let size = std::fs::metadata(&local).map(|m| m.len()).unwrap_or(0);
        if size > media::MAX_FILE {
            let _ = std::fs::remove_file(&local);
            return Err(Error::Other("file is larger than 100 MB".into()));
        }
        let fwd = att.forwarded_from.and_then(|f| Forward::new(&f, att.forwarded_from_id));
        let mut thumb = att.thumb;
        if thumb.as_ref().is_some_and(|t| t.len() > 8 * 1024) {
            thumb = None;
        }
        let draft = AttachmentRef {
            kind: att.kind,
            name: att.name,
            mime: att.mime,
            size,
            thumb,
            w: att.width,
            h: att.height,
            duration_ms: att.duration_ms,
            wave: att.waveform,
            spoiler: att.spoiler,
            spoiler_hearts: att.spoiler && att.spoiler_hearts,
            ..Default::default()
        };
        self.inner
            .send_message(chat_id, caption.trim().to_string(), Some((draft, local)), None, Some(id), None, fwd)
            .await
    }

    /// Повторить отправку сообщения с ошибкой (как в Telegram — нажатием на «!»).
    pub async fn retry_message(&self, message_id: &str) -> Result<()> {
        self.inner.retry(message_id).await
    }

    /// Доля переданного вложения сообщения (выгрузка или загрузка) или `None`, если передачи нет.
    pub fn transfer_progress(&self, message_id: &str) -> Option<f32> {
        media::progress(message_id)
    }

    /// Скачать вложение (маленькие скачиваются сами). Возвращает путь к файлу.
    pub async fn download(&self, message_id: &str) -> Result<String> {
        self.inner.download(message_id).await
    }

    pub fn delete_message_locally(&self, message_id: &str) -> Result<()> {
        if let Some(m) = self.inner.store.message(message_id)? {
            if let Some(gid) = self.inner.gid(&m.chat_id) {
                self.inner.sync(SyncOp::DeleteLocal { gid, id: m.id.clone() });
            }
            self.inner.delete_message_locally(&m);
        }
        Ok(())
    }

    /// Поставить реакцию (`None` или пустая строка — снять). Одна на участника: новая заменяет прежнюю.
    pub async fn react(&self, message_id: &str, emoji: Option<&str>) -> Result<()> {
        let m = self.inner.store.message(message_id)?.ok_or(Error::Other("no such message".into()))?;
        let emoji = emoji.map(str::trim).filter(|e| !e.is_empty());
        if emoji.is_some_and(|e| e.len() > MAX_REACTION_BYTES) {
            return Err(Error::Other("reaction is too long".into()));
        }
        let chat = self.inner.store.chat(&m.chat_id)?.ok_or(Error::NoChat)?;
        self.inner.store.set_reaction(&m.id, &self.inner.me, emoji, now_ms())?;
        self.inner.notify(Some(m.chat_id.clone()));
        let payload = Payload::React { id: m.id, emoji: emoji.unwrap_or_default().to_string() };
        self.inner.send_payload(&chat, &payload).await.map(drop)
    }

    /// Изменить своё отправленное сообщение. Медиа и исходное время не меняются.
    pub async fn edit_message(&self, message_id: &str, text: &str) -> Result<()> {
        let m = self.inner.store.message(message_id)?.ok_or(Error::Other("no such message".into()))?;
        if m.sender_id != self.inner.me || !m.outgoing {
            return Err(Error::Other("only the author can edit a message".into()));
        }
        if matches!(m.status, MessageStatus::Sending | MessageStatus::Failed) {
            return Err(Error::Other("message must be sent before editing".into()));
        }
        if text.trim().is_empty() && m.attachment.is_none() {
            return Err(Error::Other("message cannot be empty".into()));
        }
        if m.text == text {
            return Ok(());
        }
        let chat = self.inner.store.chat(&m.chat_id)?.ok_or(Error::NoChat)?;
        if chat.state != ChatState::Active {
            return Err(Error::NotReady);
        }
        let ts = now_ms().max(m.edited_ms.saturating_add(1));
        let edit_id = new_id();
        let payload = Payload::Edit { id: m.id.clone(), text: text.into(), ts, edit_id: edit_id.clone() };
        // Do not change local text if the node rejects the edit; the composer can retry it.
        self.inner.send_payload(&chat, &payload).await?;
        self.inner.store.edit_message(&chat.id, &self.inner.me, &m.id, text, ts, &edit_id)?;
        self.inner.notify(Some(chat.id));
        Ok(())
    }

    /// Удалить у всех: своё сообщение удаляется и у участников.
    pub async fn delete_message_for_all(&self, message_id: &str) -> Result<()> {
        let Some(m) = self.inner.store.message(message_id)? else { return Ok(()) };
        if m.outgoing {
            let chat = self.inner.store.chat(&m.chat_id)?.ok_or(Error::NoChat)?;
            self.inner.send_payload(&chat, &Payload::Delete { id: m.id.clone() }).await?;
        }
        self.delete_message_locally(message_id)
    }

    // ── хранилище ──

    pub fn media_settings(&self) -> MediaSettings {
        self.inner.media_settings()
    }

    /// Сохранить настройки и сразу применить новый лимит кэша.
    pub fn set_media_settings(&self, settings: &MediaSettings) -> Result<()> {
        let json = serde_json::to_string(settings).unwrap();
        self.inner.store.set(MEDIA_SETTINGS_KEY, json.as_bytes())?;
        self.inner.enforce_cache_limit(None)?;
        self.inner.sync(SyncOp::Media { json });
        Ok(())
    }

    // ── несколько устройств ──

    /// Настройка приложения, общая для всех устройств аккаунта (`value` — JSON; чаты в нём — по `gid`).
    pub fn set_app_setting(&self, key: &str, value: &str) -> Result<()> {
        let ts = now_ms();
        self.inner.store_app_setting(key, value, ts)?;
        self.inner.sync(SyncOp::App { key: key.into(), value: value.into(), ts });
        Ok(())
    }

    pub fn app_setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self.inner.app_setting(key)?.map(|(v, _)| v))
    }

    /// Это устройство: имя, платформа и нода подключения. Рассылается остальным устройствам (для карты и списка).
    pub fn set_device(&self, name: &str, platform: &str, node: &str) -> Result<()> {
        let this = self.inner.this_device()?;
        let changed = this.name != name || this.platform != platform || this.node != node;
        let record = DeviceRecord {
            id: this.id,
            name: name.into(),
            platform: platform.into(),
            node: node.into(),
            sig: this.sig,
            ts: now_ms(),
        };
        self.inner.store.set(&device_key(&record.id), &serde_json::to_vec(&record).unwrap())?;
        if changed {
            self.inner.sync(SyncOp::Device(record));
        }
        Ok(())
    }

    /// Все устройства аккаунта, это — первым.
    pub fn devices(&self) -> Result<Vec<Device>> {
        self.inner.devices()
    }

    /// Отключить другое устройство: оно удаляется из всех чатов и само стирает аккаунт.
    pub async fn remove_device(&self, device_id: &str) -> Result<()> {
        self.inner.remove_device(device_id).await
    }

    /// Старое устройство: отправить аккаунт новому по открытому каналу (пользователь уже подтвердил).
    pub async fn link_send_account(&self, ch: &LinkChannel) -> Result<()> {
        self.link_send(ch).await
    }

    pub fn storage_usage(&self) -> Result<StorageUsage> {
        let mut u = StorageUsage::default();
        for (_, kind, path) in self.inner.store.media_files()? {
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            match kind.as_str() {
                "photo" => u.photos += size,
                "video" | "video_note" => u.videos += size,
                "voice" => u.voice += size,
                _ => u.files += size,
            }
        }
        for f in ["client.db", "client.db-wal"] {
            u.database += std::fs::metadata(self.inner.dir.join(f)).map(|m| m.len()).unwrap_or(0);
        }
        Ok(u)
    }

    /// Очистить кэш вложений: файлы удаляются, сообщения остаются (можно скачать снова).
    pub fn clear_media(&self, kinds: &[String]) -> Result<u64> {
        let mut freed = 0;
        for (_, kind, path) in self.inner.store.media_files()? {
            let k = match kind.as_str() {
                "video_note" => "video",
                "photo" | "video" | "voice" => kind.as_str(),
                _ => "file",
            };
            if kinds.is_empty() || kinds.iter().any(|x| x == k) {
                freed += std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                let _ = std::fs::remove_file(&path);
            }
        }
        // Пути к удалённым файлам больше не валидны.
        for m in self.inner.store.media_files()? {
            if !Path::new(&m.2).exists() {
                self.inner.store.clear_file_paths_for(&m.2)?;
            }
        }
        self.inner.notify(None);
        Ok(freed)
    }

    /// Подождать, пока клиент разберёт входящие события (для тестов).
    pub async fn settle(&self) {
        let _ = self.inner.engine.lock().await;
    }
}

// ───────────────────────────── Внутреннее ─────────────────────────────

impl Inner {
    fn notify(&self, chat_id: Option<String>) {
        if let Some(l) = self.listener.read().unwrap().clone() {
            l.changed(chat_id);
        }
    }

    fn profile_payload(&self) -> Result<Payload> {
        let name =
            self.store.get("profile.name")?.map(|v| String::from_utf8_lossy(&v).into_owned()).unwrap_or_default();
        let avatar = self.store.get("profile.avatar")?.filter(|a| a.len() <= 9 * 1024);
        Ok(Payload::Profile { name, avatar })
    }

    fn member_names(&self, chat_id: &str) -> Result<HashMap<String, String>> {
        Ok(self.store.members(chat_id)?.into_iter().map(|m| (m.member_id, m.name)).collect())
    }

    fn message_model(&self, m: MessageRow, names: &HashMap<String, String>) -> Message {
        let sender_name = if m.outgoing { String::new() } else { names.get(&m.sender_id).cloned().unwrap_or_default() };
        let mut reactions: Vec<Reaction> = Vec::new();
        for (emoji, sender) in self.store.reactions(&m.id).unwrap_or_default() {
            let mine = sender == self.me;
            match reactions.iter_mut().find(|r| r.emoji == emoji) {
                Some(r) => {
                    r.count += 1;
                    r.mine |= mine;
                    r.senders.push(sender);
                }
                None => reactions.push(Reaction { emoji, count: 1, mine, senders: vec![sender] }),
            }
        }
        Message {
            id: m.id,
            chat_id: m.chat_id,
            sender_name,
            sender_id: m.sender_id,
            outgoing: m.outgoing,
            ts: m.ts,
            text: m.text,
            status: m.status,
            attachment: m.attachment,
            local_path: m.file_path.filter(|p| Path::new(p).exists()),
            reply_to: m.reply_to,
            link: m.link,
            forwarded_from: m.fwd,
            forwarded_from_id: m.fwd_id,
            reactions,
            edited_ms: m.edited_ms,
        }
    }

    fn chat_model(&self, row: ChatRow) -> Result<Chat> {
        let others: Vec<MemberRow> =
            self.store.members(&row.id)?.into_iter().filter(|m| m.member_id != self.me).collect();
        let names = others.iter().map(|m| (m.member_id.clone(), m.name.clone())).collect();
        let is_saved = self.saved_id().as_deref() == Some(row.id.as_str());
        let is_group = !is_saved && (row.custom_title || others.len() > 1);
        let title = if row.custom_title || others.is_empty() {
            row.title.clone()
        } else {
            let list: Vec<&str> =
                others.iter().map(|m| m.name.as_str()).map(|n| if n.is_empty() { "Без имени" } else { n }).collect();
            list.join(", ")
        };
        let avatar = if is_group { None } else { others.first().and_then(|m| m.avatar.clone()) };
        let mut members: Vec<Member> = others
            .into_iter()
            .map(|m| Member { id: m.member_id, name: m.name, avatar: m.avatar, is_me: false })
            .collect();
        let me = self.profile_payload()?;
        if let Payload::Profile { name, avatar } = me {
            members.insert(0, Member { id: self.me.clone(), name, avatar, is_me: true });
        }
        let is_owner = self.store.get(&owner_key(&row.id))?.is_some();
        let backup_node = self.store.mirror(&row.id)?.map(|m| m.node);
        let archived = self.store.get(&archive_key(&row.id))?.is_some();
        let gid = row.group_id.as_deref().map(hex::encode);
        Ok(Chat {
            gid,
            last_message: self.store.last_message(&row.id)?.map(|m| self.message_model(m, &names)),
            id: row.id,
            title,
            is_group,
            state: row.state,
            node: row.node,
            unread: row.unread,
            muted: row.muted,
            pinned: row.pinned,
            last_ms: row.last_ms,
            avatar,
            members,
            can_invite: row.state == ChatState::Active && !is_saved,
            is_saved,
            is_owner,
            backup_node,
            archived,
        })
    }

    // ── группы ──

    async fn remove_member(self: &Arc<Self>, chat_id: &str, member_id: &str) -> Result<()> {
        if member_id == self.me {
            return Err(Error::Other("use leave_chat to leave".into()));
        }
        let mut engine = self.engine.lock().await;
        for _attempt in 0..3 {
            let chat = self.store.chat(chat_id)?.ok_or(Error::NoChat)?;
            let mut group = engine.group(&chat)?;
            // У аккаунта может быть несколько устройств — удаляем все его листья.
            let indices: Vec<LeafNodeIndex> = group
                .members()
                .filter(|m| m.credential.serialized_content() == member_id.as_bytes())
                .map(|m| m.index)
                .collect();
            if indices.is_empty() {
                // Уже удалён (например, кто-то успел раньше).
                self.store.delete_member(chat_id, member_id)?;
                return Ok(());
            }
            let (commit, _, _) = group.remove_members(&engine.provider, &engine.signer, &indices).map_err(mls)?;
            let conn = self.conn(&chat.node).await?;
            let body = request::Body::LogCommit(LogCommit {
                log_id: chat.log_id.clone(),
                epoch: group.epoch().as_u64(),
                blob: commit.tls_serialize_detached().map_err(mls)?,
            });
            match conn.request(body, Some(&key(&chat.write_sk))).await? {
                response::Body::LogAppended(a) => {
                    self.store.add_own_offset(&chat.id, a.offset)?;
                    group.merge_pending_commit(&engine.provider).map_err(mls)?;
                    engine.save(&self.store)?;
                    self.store.delete_member(chat_id, member_id)?;
                    info!("➖ member {} removed from chat {chat_id}", &member_id[..8.min(member_id.len())]);
                    self.notify(Some(chat_id.into()));
                    return Ok(());
                }
                response::Body::CommitConflict(c) => {
                    group.clear_pending_commit(engine.provider.storage()).map_err(mls)?;
                    engine.save(&self.store)?;
                    if let Some(winner) = c.winner {
                        self.process_entry(&mut engine, &chat, winner).await?;
                    }
                }
                other => {
                    group.clear_pending_commit(engine.provider.storage()).map_err(mls)?;
                    engine.save(&self.store)?;
                    return Err(refused(other));
                }
            }
        }
        Err(Error::Other("commit conflicts, giving up".into()))
    }

    /// Удаление из обработчика входящих: явный `Send`-тип разрывает рекурсию
    /// remove_member → process_entry → apply_payload → remove_member.
    fn remove_member_task(
        self: Arc<Self>,
        chat_id: String,
        member_id: String,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            if let Err(e) = self.remove_member(&chat_id, &member_id).await {
                warn!("⚠️ removing member who left failed: {e}");
            }
        })
    }

    // ── резервные журналы ──

    /// Для каждого активного чата без резерва — журнал на другой ноде; ключи уходят участникам внутри MLS.
    async fn ensure_mirrors(self: &Arc<Self>) {
        let _guard = self.mirror_lock.lock().await;
        let candidates = self.backup_nodes.read().unwrap().clone();
        if candidates.is_empty() {
            return;
        }
        for chat in self.store.chats().unwrap_or_default() {
            if chat.state != ChatState::Active || self.store.mirror(&chat.id).ok().flatten().is_some() {
                continue;
            }
            let chat_key = node_key(&chat.node);
            let Some(target) = candidates.iter().find(|n| node_key(n) != chat_key) else { continue };
            if let Err(e) = self.create_mirror(&chat, target).await {
                debug!("mirror for chat {} on {} failed: {e}", chat.id, short(target));
            }
        }
    }

    async fn create_mirror(self: &Arc<Self>, chat: &ChatRow, target: &str) -> Result<()> {
        let conn = self.conn(target).await?;
        let (write, read) = (Ed25519Key::generate(), Ed25519Key::generate());
        let log_id = random_bytes::<32>().to_vec();
        let new = LogNew {
            log_id: log_id.clone(),
            write_pk: write.public_key().to_vec(),
            read_pk: read.public_key().to_vec(),
        };
        expect_done(conn.request(request::Body::LogNew(new), None).await?)?;
        let creds = MirrorCreds {
            node: target.to_string(),
            log_id,
            write_sk: write.to_bytes().to_vec(),
            read_sk: read.to_bytes().to_vec(),
        };
        // Сначала участникам: если ключи не ушли, резерв бесполезен.
        self.send_payload(chat, &Payload::Mirror(creds.clone())).await?;
        self.store.set_mirror(&chat.id, &mirror_row(creds))?;
        info!("🪞 chat {} mirrored on {}", chat.id, short(target));
        self.notify(Some(chat.id.clone()));
        Ok(())
    }

    /// Нода чата давно молчит, а резервная отвечает — переезжаем.
    async fn failover(self: &Arc<Self>, chat: &ChatRow) -> Result<()> {
        let Some(mirror) = self.store.mirror(&chat.id)? else { return Ok(()) };
        let conn = self.conn(&mirror.node).await?;
        let _engine = self.engine.lock().await;
        if self.store.mirror(&chat.id)?.is_none_or(|current| current.log_id != mirror.log_id) {
            return Ok(());
        }
        if self.store.swap_to_mirror(&chat.id)?.is_none() {
            return Ok(());
        }
        let moved = self.store.chat(&chat.id)?.ok_or(Error::NoChat)?;
        self.watch_chat(&conn, &moved).await?;
        warn!("🛟 chat {} moved from {} to backup {}", chat.id, short(&chat.node), short(&mirror.node));
        self.notify(None);
        Ok(())
    }

    async fn read_mirror(self: &Arc<Self>, chat_id: &str, mirror: MirrorRow) -> Result<()> {
        let conn = self.conn(&mirror.node).await?;
        let read = key(&mirror.read_sk);
        let response = conn
            .request(
                request::Body::LogRead(LogRead {
                    log_id: mirror.log_id.clone(),
                    from_offset: mirror.read_offset,
                    limit: 32,
                }),
                Some(&read),
            )
            .await?;
        let entries = match response {
            response::Body::LogEntries(entries) => entries.entries,
            other => return Err(refused(other)),
        };
        for entry in entries {
            let engine = self.engine.lock().await;
            let Some(chat) = self.store.chat(chat_id)?.filter(|c| c.state == ChatState::Active) else { break };
            let Some(current) = self.store.mirror(chat_id)?.filter(|m| m.log_id == mirror.log_id) else { break };
            if entry.offset < current.read_offset {
                continue;
            }
            let mut group = engine.group(&chat)?;
            if let Some(msg) = MlsMessageIn::tls_deserialize_exact(&entry.blob)
                .ok()
                .and_then(|msg| msg.try_into_protocol_message().ok())
            {
                // Обновление состава проводит только активный журнал. Будущую эпоху дочитаем позже.
                if msg.epoch() > group.epoch() || (msg.is_handshake_message() && msg.epoch() == group.epoch()) {
                    break;
                }
                if !msg.is_handshake_message() {
                    if let Ok(processed) = group.process_message(&engine.provider, msg) {
                        let sender = String::from_utf8_lossy(processed.credential().serialized_content()).into_owned();
                        if let ProcessedMessageContent::ApplicationMessage(app) = processed.into_content() {
                            engine.save(&self.store)?;
                            if let Ok(payload) = serde_json::from_slice::<Payload>(&app.into_bytes()) {
                                self.apply_payload(&chat, &sender, payload, &engine).await?;
                            }
                        }
                    }
                }
            }
            self.store.advance_mirror(chat_id, &mirror.log_id, entry.offset + 1)?;
        }
        Ok(())
    }

    // ── сеть ──

    async fn conn(self: &Arc<Self>, node: &str) -> Result<Arc<NetClient>> {
        if let Some(c) = self.conns.lock().unwrap().get(node) {
            return Ok(c.clone());
        }
        let _guard = self.connecting.lock().await;
        if let Some(c) = self.conns.lock().unwrap().get(node) {
            return Ok(c.clone());
        }
        let addr: NodeAddr = node.parse().map_err(|_| Error::Other(format!("bad node address {node}")))?;
        let (client, mut events) =
            tokio::time::timeout(REQUEST_TIMEOUT, NetClient::connect(&addr)).await.map_err(|_| NetError::Timeout)??;
        let client = Arc::new(client);
        if matches!(
            tokio::time::timeout(Duration::from_secs(1), client.request(request::Body::Ping(Default::default()), None)).await,
            Ok(Ok(response::Body::Pong(pong))) if pong.push_forwarding
        ) {
            self.push_nodes.lock().unwrap().insert(node.to_owned());
        }
        self.conns.lock().unwrap().insert(node.to_string(), client.clone());
        debug!("🔌 connected to {}", short(node));

        // Насос событий: только пересылает в общий обработчик, чтобы не блокировать чтение ответов.
        let (tx, weak, node_s, me) = (self.events.clone(), Arc::downgrade(self), node.to_string(), client.clone());
        self.rt.spawn(async move {
            while let Some(ev) = events.recv().await {
                if tx.send((node_s.clone(), ev)).is_err() {
                    return;
                }
            }
            if let Some(inner) = weak.upgrade() {
                let mut conns = inner.conns.lock().unwrap();
                if conns.get(&node_s).is_some_and(|c| Arc::ptr_eq(c, &me)) {
                    conns.remove(&node_s);
                    inner.push_nodes.lock().unwrap().remove(&node_s);
                }
                debug!("🔌 disconnected from {}", short(&node_s));
            }
        });

        self.subscribe_all(node, &client).await;
        Ok(client)
    }

    async fn subscribe_all(&self, node: &str, conn: &NetClient) {
        let chats = self.store.chats().unwrap_or_default();
        for chat in chats.iter().filter(|c| c.node == node && c.state == ChatState::Active) {
            if let Err(e) = self.watch_chat(conn, chat).await {
                warn!("⚠️ watch chat {} failed: {e}", chat.id);
            }
        }
        for table in ["invites", "joins"] {
            for q in self.store.queues(table).unwrap_or_default().iter().filter(|q| q.node == node) {
                if let Err(e) = subscribe_queue(conn, q).await {
                    warn!("⚠️ queue subscribe failed: {e}");
                }
            }
        }
    }

    async fn watch_chat(&self, conn: &NetClient, chat: &ChatRow) -> Result<()> {
        let body = request::Body::LogWatch(LogWatch { log_id: chat.log_id.clone(), from_offset: chat.read_offset });
        expect_done(conn.request(body, Some(&key(&chat.read_sk))).await?)
    }

    fn push_slot(&self, log: &[u8], domain: &[u8]) -> Vec<u8> {
        core_crypto::sha256(&[domain, self.device_id().as_bytes(), log].concat())[..16].to_vec()
    }

    async fn register_log_push(
        self: &Arc<Self>,
        gateway: &NetClient,
        chat: &ChatRow,
        sandbox: bool,
        alert: Option<&[u8]>,
        voip: Option<&[u8]>,
    ) -> Result<()> {
        use core_proto::msg::{NotifySet, PushRegister};
        let conn = self.conn(&chat.node).await?;
        if !self.push_nodes.lock().unwrap().contains(&chat.node) {
            return Ok(());
        }
        let scope = self.push_slot(&chat.log_id, b"CORE/Push/scope");
        let register = |token: Option<&[u8]>, voip| {
            let token = token.map(<[u8]>::to_vec);
            let scope = scope.clone();
            async move {
                let Some(token) = token else { return Ok(vec![]) };
                let request = request::Body::PushRegister(PushRegister { token, sandbox, voip, scope });
                match gateway.request(request, None).await? {
                    response::Body::PushRegistered(registered) => Ok(registered.capability),
                    other => Err(refused(other)),
                }
            }
        };
        let (alert, voip) = tokio::try_join!(register(alert.filter(|_| !chat.muted), false), register(voip, true))?;
        let route = NotifySet {
            log_id: chat.log_id.clone(),
            slot: self.push_slot(&chat.log_id, b"CORE/Push/slot"),
            alert,
            voip,
        };
        expect_done(conn.request(request::Body::NotifySet(route), Some(&key(&chat.read_sk))).await?)
    }

    /// Зашифровать и положить прикладное сообщение в журнал чата.
    async fn send_payload(self: &Arc<Self>, chat: &ChatRow, payload: &Payload) -> Result<u64> {
        let bytes = serde_json::to_vec(payload).unwrap();
        if bytes.len() > MAX_PAYLOAD {
            return Err(Error::Other("message is too large".into()));
        }
        let conn = self.conn(&chat.node).await?;
        let engine = self.engine.lock().await;
        let mut group = engine.group(chat)?;
        let out = group.create_message(&engine.provider, &engine.signer, &bytes).map_err(mls)?;
        engine.save(&self.store)?;
        let blob = out.tls_serialize_detached().map_err(mls)?;
        let write = key(&chat.write_sk);
        let mut append = LogAppend { log_id: chat.log_id.clone(), blob, ..Default::default() };
        if self.push_nodes.lock().unwrap().contains(&chat.node) {
            append.alert = matches!(payload, Payload::Message { .. });
            if let Payload::Call { id, op: payload::CallOp::Ring { .. } } = payload {
                append.call_id = hex::decode(id).unwrap_or_default();
            }
            if append.alert || !append.call_id.is_empty() {
                append.sender_slot = self.push_slot(&chat.log_id, b"CORE/Push/slot");
            }
        }
        let resp = conn.request(request::Body::LogAppend(append), Some(&write));
        match tokio::time::timeout(REQUEST_TIMEOUT, resp).await.map_err(|_| NetError::Timeout)?? {
            response::Body::LogAppended(a) => {
                self.store.add_own_offset(&chat.id, a.offset)?;
                Ok(a.offset)
            }
            other => Err(refused(other)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_message(
        self: &Arc<Self>,
        chat_id: &str,
        text: String,
        attachment: Option<(AttachmentRef, PathBuf)>,
        reply_to: Option<String>,
        id: Option<String>,
        link: Option<LinkPreview>,
        fwd: Option<Forward>,
    ) -> Result<String> {
        let chat = self.store.chat(chat_id)?.ok_or(Error::NoChat)?;
        if chat.state != ChatState::Active {
            return Err(Error::NotReady);
        }
        let id = id.unwrap_or_else(new_id);
        let ts = now_ms();
        let (att, local) = match attachment {
            Some((a, p)) => (Some(a), Some(p.to_string_lossy().into_owned())),
            None => (None, None),
        };
        let row = MessageRow {
            id: id.clone(),
            chat_id: chat_id.into(),
            sender_id: self.me.clone(),
            outgoing: true,
            ts,
            text,
            attachment: att,
            status: MessageStatus::Sending,
            file_path: local,
            reply_to,
            link,
            fwd: fwd.as_ref().map(|f| f.name.clone()),
            fwd_id: fwd.and_then(|f| f.id),
            edited_ms: 0,
            edit_id: String::new(),
        };
        if !self.store.insert_message_touch(&row, ts, 0)? {
            return Err(Error::Other("message id already in use".into()));
        }
        self.notify(Some(chat_id.into()));
        self.deliver(&chat, &id).await.map(|_| id)
    }

    /// Выгрузить вложение (если ещё не выгружено) и отправить сообщение в чат; статус — «отправлено» или «ошибка».
    /// Повтор безопасен: получатели отбрасывают дубликаты по id.
    async fn deliver(self: &Arc<Self>, chat: &ChatRow, id: &str) -> Result<()> {
        let _claim = InFlight::claim(&self.sending, id).ok_or(Error::Other("already sending".into()))?;
        let row = self.store.message(id)?.ok_or(Error::Other("message not found".into()))?;
        if matches!(row.status, MessageStatus::Sent | MessageStatus::Read) {
            return Ok(());
        }
        self.store.set_status(id, MessageStatus::Sending)?;
        self.notify(Some(chat.id.clone()));
        let local = row.file_path.clone();
        let result = async {
            let att = match row.attachment {
                Some(mut a) if a.key.is_empty() => {
                    let path = local.as_deref().ok_or(Error::Other("attachment file is gone".into()))?;
                    let conn = self.conn(&chat.node).await?;
                    media::upload(&conn, &chat.node, Path::new(path), &mut a, Some(id)).await?;
                    self.store.set_attachment(id, &a)?;
                    Some(a)
                }
                other => other,
            };
            let payload = Payload::Message {
                id: id.to_owned(),
                ts: row.ts,
                text: row.text,
                att: att.map(Box::new),
                reply_to: row.reply_to,
                link: row.link.map(Box::new),
                fwd_id: row.fwd_id,
                fwd: row.fwd,
            };
            self.send_payload(chat, &payload).await
        }
        .await;

        self.store.finish_delivery(id, result.is_ok(), now_ms())?;
        if let Err(e) = &result {
            warn!("⚠️ message {id} not sent: {e}");
        } else if local.is_some() {
            self.enforce_cache_limit(local.as_deref())?;
        }
        self.notify(Some(chat.id.clone()));
        result.map(drop)
    }

    /// Повторить отправку своего неотправленного сообщения.
    async fn retry(self: &Arc<Self>, message_id: &str) -> Result<()> {
        let row = self.store.message(message_id)?.ok_or(Error::Other("message not found".into()))?;
        if !row.outgoing || row.status == MessageStatus::Sent || row.status == MessageStatus::Read {
            return Ok(());
        }
        let chat = self.store.chat(&row.chat_id)?.ok_or(Error::NoChat)?;
        if chat.state != ChatState::Active {
            return Err(Error::NotReady);
        }
        info!("🔁 retrying message {message_id}");
        self.deliver(&chat, message_id).await
    }

    /// Автоповтор: всё неотправленное (ошибки и «зависшие» после перезапуска) — по порядку.
    async fn retry_unsent(self: &Arc<Self>) {
        let Ok(ids) = self.store.unsent_outgoing() else { return };
        let now = now_ms();
        let mut waiting = std::collections::HashSet::new();
        for (id, chat_id, retry_at) in ids {
            if waiting.contains(&chat_id) {
                continue;
            }
            if retry_at > now || self.sending.lock().unwrap().contains(&id) {
                waiting.insert(chat_id);
                continue;
            }
            if let Err(e) = self.retry(&id).await {
                debug!("retry of {id} failed: {e}");
                waiting.insert(chat_id);
            }
        }
    }

    fn saved_id(&self) -> Option<String> {
        self.store.get(SAVED_CHAT_KEY).ok().flatten().and_then(|v| String::from_utf8(v).ok())
    }

    fn media_settings(&self) -> MediaSettings {
        self.store
            .get(MEDIA_SETTINGS_KEY)
            .ok()
            .flatten()
            .and_then(|v| serde_json::from_slice(&v).ok())
            .unwrap_or_default()
    }

    /// Удалять самые старые файлы, пока кэш больше предела. `keep` — только что полученный файл.
    fn enforce_cache_limit(&self, keep: Option<&str>) -> Result<u64> {
        let limit = self.media_settings().cache_limit_bytes;
        if limit == 0 {
            return Ok(0);
        }
        let files: Vec<(String, u64)> = self
            .store
            .media_files_by_age()?
            .into_iter()
            .map(|p| {
                let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                (p, size)
            })
            .collect();
        let mut total: u64 = files.iter().map(|f| f.1).sum();
        let mut freed = 0;
        for (path, size) in files {
            if total <= limit {
                break;
            }
            if Some(path.as_str()) == keep {
                continue;
            }
            let _ = std::fs::remove_file(&path);
            self.store.clear_file_paths_for(&path)?;
            total -= size;
            freed += size;
        }
        if freed > 0 {
            info!("🧹 cache limit: freed {freed} bytes");
            self.notify(None);
        }
        Ok(freed)
    }

    /// Собеседник в списке блокировок (общая настройка аккаунта `blocked` — JSON-массив id).
    fn is_blocked(&self, member_id: &str) -> bool {
        self.app_setting(BLOCKED_KEY)
            .ok()
            .flatten()
            .and_then(|(v, _)| serde_json::from_str::<Vec<String>>(&v).ok())
            .is_some_and(|ids| ids.iter().any(|id| id == member_id))
    }

    /// Скачать по правилам автозагрузки то, чего нет на устройстве (до 40 последних вложений).
    async fn resume_downloads(self: &Arc<Self>) {
        let settings = self.media_settings();
        let Ok(rows) = self.store.missing_media(40) else { return };
        let todo: Vec<String> = rows
            .into_iter()
            .filter(|m| m.attachment.as_ref().is_some_and(|a| settings.auto_download(a)))
            .map(|m| m.id)
            .collect();
        if todo.is_empty() {
            return;
        }
        info!("⏬ resuming {} auto-downloads", todo.len());
        for id in todo {
            if let Err(e) = self.download(&id).await {
                warn!("⚠️ resume download {id}: {e}");
            }
        }
    }

    async fn download(self: &Arc<Self>, message_id: &str) -> Result<String> {
        let _claim =
            InFlight::claim(&self.downloading, message_id).ok_or(Error::Other("already downloading".into()))?;
        let m = self.store.message(message_id)?.ok_or(Error::Other("message not found".into()))?;
        if let Some(p) = m.file_path.as_ref().filter(|p| Path::new(p).exists()) {
            return Ok(p.clone());
        }
        let a = m.attachment.ok_or(Error::Other("no attachment".into()))?;
        let result = async {
            let conn = self.conn(&a.node).await?;
            let ext = Path::new(&a.name).extension().and_then(|e| e.to_str()).unwrap_or("bin");
            let path = self.dir.join("media").join(format!("{}.{ext}", m.id));
            media::download(&conn, &a, &path, Some(&m.id)).await?;
            let path = path.to_string_lossy().into_owned();
            self.store.set_file_path(&m.id, Some(&path))?;
            self.enforce_cache_limit(Some(&path))?;
            Ok(path)
        }
        .await;
        self.notify(Some(m.chat_id));
        result
    }

    // ── обработка входящего ──

    async fn handle_event(self: &Arc<Self>, node: &str, ev: Event) -> Result<()> {
        match ev.body {
            Some(event::Body::LogEvent(e)) => {
                let Some(entry) = e.entry else { return Ok(()) };
                if let Some(chat) = self.store.chat_by_log(&e.log_id)? {
                    let mut engine = self.engine.lock().await;
                    self.process_entry(&mut engine, &chat, entry).await?;
                }
            }
            Some(event::Body::QueueMessage(m)) => {
                let invite = self.store.queues("invites")?.into_iter().find(|q| q.recipient_id == m.recipient_id);
                let join = self.store.queues("joins")?.into_iter().find(|q| q.recipient_id == m.recipient_id);
                let (q, res) = match (invite, join) {
                    (Some(q), _) => {
                        let r = self.handle_join_request(&q, &m.body).await;
                        (q, r)
                    }
                    (_, Some(q)) => {
                        let r = self.handle_join_reply(&q, &m.body).await;
                        (q, r)
                    }
                    _ => return Ok(()),
                };
                if let Err(e) = &res {
                    warn!("⚠️ queue message in chat {} dropped: {e}", q.chat_id);
                }
                let conn = self.conn(node).await?;
                let ack = QueueAck { recipient_id: q.recipient_id.clone(), msg_id: m.msg_id };
                conn.request(request::Body::QueueAck(ack), Some(&key(&q.recipient_sk))).await?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Мы пригласили — кто-то прислал KeyPackage. Добавляем в группу и отвечаем Welcome.
    async fn handle_join_request(self: &Arc<Self>, invite: &QueueRow, body: &[u8]) -> Result<()> {
        let req: JoinRequest = serde_json::from_slice(body).map_err(|e| Error::Other(e.to_string()))?;
        let mut engine = self.engine.lock().await;
        let key_package = KeyPackageIn::tls_deserialize_exact(&req.key_package)
            .map_err(mls)?
            .validate(engine.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(mls)?;

        for _attempt in 0..3 {
            let chat = self.store.chat(&invite.chat_id)?.ok_or(Error::NoChat)?;
            let mut group = engine.group(&chat)?;
            let others = group.members().count() > 1;
            let (commit, welcome, _) =
                group.add_members(&engine.provider, &engine.signer, std::slice::from_ref(&key_package)).map_err(mls)?;

            let mut from_offset = chat.read_offset;
            if others {
                // Коммит виден остальным участникам — публикуем через compare-and-swap по эпохе.
                let conn = self.conn(&chat.node).await?;
                let blob = commit.tls_serialize_detached().map_err(mls)?;
                let body = request::Body::LogCommit(LogCommit {
                    log_id: chat.log_id.clone(),
                    epoch: group.epoch().as_u64(),
                    blob,
                });
                match conn.request(body, Some(&key(&chat.write_sk))).await? {
                    response::Body::LogAppended(a) => {
                        self.store.add_own_offset(&chat.id, a.offset)?;
                        from_offset = from_offset.max(a.offset + 1);
                    }
                    response::Body::CommitConflict(c) => {
                        // Кто-то успел раньше: откатываем свой коммит, применяем победителя и пробуем снова.
                        group.clear_pending_commit(engine.provider.storage()).map_err(mls)?;
                        engine.save(&self.store)?;
                        if let Some(winner) = c.winner {
                            self.process_entry(&mut engine, &chat, winner).await?;
                        }
                        continue;
                    }
                    other => {
                        group.clear_pending_commit(engine.provider.storage()).map_err(mls)?;
                        engine.save(&self.store)?;
                        return Err(refused(other));
                    }
                }
            }
            group.merge_pending_commit(&engine.provider).map_err(mls)?;
            engine.save(&self.store)?;

            let creds = LogCreds {
                log_id: chat.log_id.clone(),
                write_sk: chat.write_sk.clone(),
                read_sk: chat.read_sk.clone(),
                from_offset,
            };
            let sealed = seal(&engine.creds_key(&group)?, &serde_json::to_vec(&creds).unwrap());
            let reply = JoinReply { welcome: welcome.tls_serialize_detached().map_err(mls)?, creds: sealed };
            drop(engine);

            let conn = self.conn(&invite.node).await?;
            let body = serde_json::to_vec(&reply).unwrap();
            expect_done(conn.request(request::Body::QueueSend(QueueSend { sender_id: req.reply, body }), None).await?)?;
            info!("➕ member added to chat {}", chat.id);
            // Новичок не видит сообщений до своего вступления — представимся заново.
            let _ = self.send_payload(&chat, &self.profile_payload()?).await;
            if chat.custom_title {
                let _ = self.send_payload(&chat, &Payload::Title { title: chat.title.clone() }).await;
            }
            self.notify(Some(chat.id));
            return Ok(());
        }
        Err(Error::Other("commit conflicts, giving up".into()))
    }

    /// Мы вступали — пришёл Welcome. Входим в группу и подписываемся на журнал.
    async fn handle_join_reply(self: &Arc<Self>, join: &QueueRow, body: &[u8]) -> Result<()> {
        let reply: JoinReply = serde_json::from_slice(body).map_err(|e| Error::Other(e.to_string()))?;
        let engine = self.engine.lock().await;
        let welcome = match MlsMessageIn::tls_deserialize_exact(&reply.welcome).map_err(mls)?.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(Error::Mls("expected Welcome".into())),
        };
        let group = StagedWelcome::new_from_welcome(&engine.provider, &Engine::join_config(), welcome, None)
            .map_err(mls)?
            .into_group(&engine.provider)
            .map_err(mls)?;
        let creds: LogCreds = serde_json::from_slice(&open(&engine.creds_key(&group)?, &reply.creds)?)
            .map_err(|e| Error::Other(e.to_string()))?;
        engine.save(&self.store)?;
        drop(engine);

        self.store.activate_chat(
            &join.chat_id,
            group.group_id().as_slice(),
            &creds.log_id,
            &creds.write_sk,
            &creds.read_sk,
            creds.from_offset,
        )?;
        let conn = self.conn(&join.node).await?;
        let _ = conn
            .request(
                request::Body::QueueDel(QueueDel { recipient_id: join.recipient_id.clone() }),
                Some(&key(&join.recipient_sk)),
            )
            .await;
        self.store.delete_queue("joins", &join.chat_id)?;
        let chat = self.store.chat(&join.chat_id)?.ok_or(Error::NoChat)?;
        self.watch_chat(&conn, &chat).await?;
        info!("✅ joined chat {}", chat.id);
        let _ = self.send_payload(&chat, &self.profile_payload()?).await;
        self.notify(None);
        // Вступили сами (не по команде своего устройства) — пусть остальные устройства тоже вступят.
        if self.store.get(&quiet_key(&chat.id))?.is_none() {
            self.announce_chat(&chat.id);
        } else {
            self.store.delete(&quiet_key(&chat.id))?;
        }
        if self.saved_id().as_deref() == Some(chat.id.as_str()) {
            self.announce_device();
        }
        Ok(())
    }

    async fn process_entry(self: &Arc<Self>, engine: &mut Engine, chat: &ChatRow, entry: LogEntry) -> Result<()> {
        // Читаем текущее смещение заново: событие могло прийти повторно после переподписки.
        let Some(chat) = self.store.chat(&chat.id)?.filter(|current| current.log_id == chat.log_id) else {
            return Ok(());
        };
        if entry.offset < chat.read_offset {
            return Ok(());
        }
        self.store.set_read_offset(&chat.id, entry.offset + 1)?;
        if self.store.is_own_offset(&chat.id, entry.offset)? {
            return Ok(());
        }
        let mut group = engine.group(&chat)?;
        let processed = MlsMessageIn::tls_deserialize_exact(&entry.blob)
            .map_err(mls)
            .and_then(|m| m.try_into_protocol_message().map_err(mls))
            .and_then(|m| group.process_message(&engine.provider, m).map_err(mls));
        let processed = match processed {
            Ok(p) => p,
            Err(e) => {
                debug!("skip entry {} in chat {}: {e}", entry.offset, chat.id);
                return Ok(());
            }
        };
        let sender = String::from_utf8_lossy(processed.credential().serialized_content()).into_owned();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => {
                engine.save(&self.store)?;
                if let Ok(payload) = serde_json::from_slice::<Payload>(&app.into_bytes()) {
                    self.apply_payload(&chat, &sender, payload, engine).await?;
                }
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                let removed = commit.self_removed();
                let added = commit.add_proposals().count() > 0;
                let gone: Vec<String> = commit
                    .remove_proposals()
                    .filter_map(|p| group.member(p.remove_proposal().removed()).cloned())
                    .map(|c| String::from_utf8_lossy(c.serialized_content()).into_owned())
                    .collect();
                group.merge_staged_commit(&engine.provider, *commit).map_err(mls)?;
                engine.save(&self.store)?;
                for id in gone {
                    self.store.delete_member(&chat.id, &id)?;
                }
                if removed {
                    self.store.set_chat_state(&chat.id, ChatState::Left)?;
                    self.notify(None);
                } else if added {
                    // Представиться новичку (он не видит прошлых сообщений) — уже вне замка.
                    let (inner, chat) = (self.clone(), chat.clone());
                    self.rt.spawn(async move {
                        if let Ok(p) = inner.profile_payload() {
                            let _ = inner.send_payload(&chat, &p).await;
                        }
                    });
                }
            }
            ProcessedMessageContent::ProposalMessage(p) => {
                group.store_pending_proposal(engine.provider.storage(), *p).map_err(mls)?;
                engine.save(&self.store)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Отчёт о доставке — с небольшой задержкой, одним на пачку (догоняя историю, не шлём по отчёту на сообщение).
    fn schedule_delivery_receipt(self: &Arc<Self>, chat_id: &str) {
        if !self.delivery_pending.lock().unwrap().insert(chat_id.to_string()) {
            return;
        }
        let (inner, chat_id) = (self.clone(), chat_id.to_string());
        self.rt.spawn(async move {
            tokio::time::sleep(Duration::from_millis(700)).await;
            inner.delivery_pending.lock().unwrap().remove(&chat_id);
            let Ok(Some(chat)) = inner.store.chat(&chat_id) else { return };
            if chat.state != ChatState::Active {
                return;
            }
            let Ok(up_to) = inner.store.max_incoming_ts(&chat_id) else { return };
            if let Err(e) = inner.send_payload(&chat, &Payload::Delivered { up_to }).await {
                warn!("⚠️ delivery receipt failed: {e}");
            }
        });
    }

    async fn apply_payload(
        self: &Arc<Self>,
        chat: &ChatRow,
        sender: &str,
        payload: Payload,
        engine: &Engine,
    ) -> Result<()> {
        // Заблокированный собеседник: его сообщения, реакции и «печатает…» не принимаются
        // (служебное — профиль, состав группы — применяется, иначе разойдётся состояние MLS).
        if sender != self.me
            && matches!(
                payload,
                Payload::Message { .. }
                    | Payload::Edit { .. }
                    | Payload::React { .. }
                    | Payload::Typing { .. }
                    | Payload::Call { .. }
            )
            && self.is_blocked(sender)
        {
            debug!("🚫 dropped payload from blocked {}", short(sender));
            return Ok(());
        }
        match payload {
            Payload::Message { id, ts, text, att, reply_to, link, fwd, fwd_id } => {
                // С другого своего устройства — это наше исходящее.
                let mine = sender == self.me;
                let settings = self.media_settings();
                let auto = att.as_ref().is_some_and(|a| settings.auto_download(a));
                let row = MessageRow {
                    id: id.clone(),
                    chat_id: chat.id.clone(),
                    sender_id: sender.into(),
                    outgoing: mine,
                    ts,
                    text,
                    attachment: att.map(|a| *a),
                    status: if mine { MessageStatus::Sent } else { MessageStatus::Received },
                    file_path: None,
                    reply_to,
                    link: link.and_then(|l| l.sanitized()),
                    fwd: fwd.map(|f| f.chars().take(64).collect()),
                    fwd_id: fwd_id.filter(|k| Forward::valid_id(k)),
                    edited_ms: 0,
                    edit_id: String::new(),
                };
                let inserted = if mine {
                    self.store.insert_message_touch(&row, ts, 0)?
                } else {
                    self.store.insert_message_touch(&row, ts.max(now_ms().min(ts + 60_000)), 1)?
                };
                if inserted && mine {
                    if auto {
                        let inner = self.clone();
                        self.rt.spawn(async move {
                            if let Err(e) = inner.download(&id).await {
                                warn!("⚠️ auto-download failed: {e}");
                            }
                        });
                    }
                } else if inserted {
                    self.schedule_delivery_receipt(&chat.id);
                    // Как в Telegram: новое сообщение достаёт чат из архива, если он не заглушён.
                    if !chat.muted {
                        self.store.delete(&archive_key(&chat.id))?;
                    }
                    if auto {
                        let inner = self.clone();
                        self.rt.spawn(async move {
                            if let Err(e) = inner.download(&id).await {
                                warn!("⚠️ auto-download failed: {e}");
                            }
                        });
                    }
                }
            }
            Payload::Edit { id, text, ts, edit_id } => {
                if text.len() <= MAX_PAYLOAD && edit_id.len() <= 64 {
                    let valid = self.store.message(&id)?.is_some_and(|m| {
                        m.chat_id == chat.id
                            && m.sender_id == sender
                            && (!text.trim().is_empty() || m.attachment.is_some())
                    });
                    if valid {
                        self.store.edit_message(&chat.id, sender, &id, &text, ts, &edit_id)?;
                    }
                }
            }
            Payload::Profile { name, avatar } if sender == self.me => {
                // Профиль поменяли на другом устройстве.
                self.store.set("profile.name", name.as_bytes())?;
                match &avatar {
                    Some(a) => self.store.set("profile.avatar", a)?,
                    None => self.store.delete("profile.avatar")?,
                }
                self.notify(None);
            }
            Payload::Profile { name, avatar } => {
                self.store.upsert_member(&chat.id, sender, &name, avatar.as_deref())?;
            }
            Payload::Title { title } => {
                self.store.set_title(&chat.id, &title, !title.is_empty())?;
            }
            Payload::Read { up_to } if sender == self.me => {
                // Прочитано на другом своём устройстве.
                self.store.set_read_up_to(&chat.id, up_to)?;
                self.notify(None);
            }
            Payload::Read { up_to } => {
                self.store.mark_outgoing_read(&chat.id, up_to)?;
            }
            Payload::Typing { kind, ts } => {
                // Догоняя историю, старые «печатает…» не показываем.
                if sender != self.me && now_ms().saturating_sub(ts) < TYPING_FRESH_MS {
                    if let Some(l) = self.listener.read().unwrap().clone() {
                        l.typing(chat.id.clone(), sender.to_string(), kind);
                    }
                }
            }
            Payload::Delivered { .. } if sender == self.me => {}
            Payload::Delivered { up_to } => {
                self.store.mark_outgoing_delivered(&chat.id, up_to)?;
            }
            Payload::SyncChat { link, gid } => {
                if sender == self.me && self.saved_id().as_deref() == Some(chat.id.as_str()) {
                    self.join_synced_chat(link, gid);
                }
            }
            Payload::Call { id, op } => {
                self.apply_call(chat, sender, id, op)?;
            }
            Payload::Sync(op) => {
                if sender == self.me && self.saved_id().as_deref() == Some(chat.id.as_str()) {
                    self.apply_sync(op)?;
                }
            }
            Payload::Mirror(creds) => {
                if node_key(&creds.node) != node_key(&chat.node) {
                    self.store.set_mirror(&chat.id, &mirror_row(creds))?;
                }
            }
            Payload::Leave => {
                // Удаляет один, детерминированно: участник с наименьшим id среди оставшихся.
                let group = engine.group(chat)?;
                let remover = group
                    .members()
                    .map(|m| String::from_utf8_lossy(m.credential.serialized_content()).into_owned())
                    .filter(|id| id != sender)
                    .min();
                if remover.as_deref() == Some(self.me.as_str()) {
                    self.rt.spawn(self.clone().remove_member_task(chat.id.clone(), sender.to_string()));
                }
            }
            Payload::React { id, emoji } => {
                let emoji = Some(emoji.trim()).filter(|e| !e.is_empty() && e.len() <= MAX_REACTION_BYTES);
                if self.store.message(&id)?.is_some_and(|m| m.chat_id == chat.id) {
                    self.store.set_reaction(&id, sender, emoji, now_ms())?;
                }
            }
            Payload::Delete { id } => {
                if let Some(m) = self.store.message(&id)?.filter(|m| m.sender_id == sender && m.chat_id == chat.id) {
                    if let Some(p) = m.file_path {
                        let _ = std::fs::remove_file(p);
                    }
                    self.store.delete_message(&id)?;
                }
            }
        }
        self.notify(Some(chat.id.clone()));
        Ok(())
    }
}

async fn event_worker(inner: std::sync::Weak<Inner>, mut rx: mpsc::UnboundedReceiver<(String, Event)>) {
    while let Some((node, ev)) = rx.recv().await {
        let Some(inner) = inner.upgrade() else { return };
        if let Err(e) = inner.handle_event(&node, ev).await {
            warn!("⚠️ event handling failed: {e}");
        }
    }
}

/// Держит соединения со всеми нодами, где есть наши чаты и очереди; после обрыва переподписывается.
async fn reconnect_loop(inner: std::sync::Weak<Inner>) {
    loop {
        {
            let Some(inner) = inner.upgrade() else { return };
            let mut nodes: Vec<String> = inner.store.chats().unwrap_or_default().into_iter().map(|c| c.node).collect();
            for table in ["invites", "joins"] {
                nodes.extend(inner.store.queues(table).unwrap_or_default().into_iter().map(|q| q.node));
            }
            nodes.sort();
            nodes.dedup();
            let mut reconnected = false;
            for node in nodes {
                let connected = inner.conns.lock().unwrap().contains_key(&node);
                if !connected {
                    match inner.conn(&node).await {
                        Ok(_) => {
                            reconnected |= inner.down_since.lock().unwrap().remove(&node).is_some();
                        }
                        Err(e) => {
                            debug!("reconnect to {} failed: {e}", short(&node));
                            inner.down_since.lock().unwrap().entry(node).or_insert_with(Instant::now);
                        }
                    }
                } else {
                    inner.down_since.lock().unwrap().remove(&node);
                }
            }
            // Связь вернулась — догружаем то, что не скачалось, пока её не было.
            if reconnected {
                let inner = inner.clone();
                tokio::spawn(async move {
                    inner.resume_downloads().await;
                });
            }
            // Нода чата пропала надолго — переезд на резервный журнал.
            let after = *inner.failover_after.read().unwrap();
            let dead: Vec<String> = inner
                .down_since
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, since)| since.elapsed() >= after)
                .map(|(n, _)| n.clone())
                .collect();
            for chat in inner.store.chats().unwrap_or_default() {
                if chat.state == ChatState::Active && dead.contains(&chat.node) {
                    if let Err(e) = inner.failover(&chat).await {
                        debug!("failover of chat {} failed: {e}", chat.id);
                    }
                }
            }
            // После переезда у чата снова нет резерва — заводим новый.
            if !dead.is_empty() {
                inner.ensure_mirrors().await;
            }
        }
        tokio::time::sleep(RECONNECT_EVERY).await;
    }
}

async fn retry_loop(inner: std::sync::Weak<Inner>) {
    loop {
        tokio::time::sleep(RECONNECT_EVERY).await;
        let Some(inner) = inner.upgrade() else { return };
        inner.retry_unsent().await;
    }
}

async fn mirror_read_loop(inner: std::sync::Weak<Inner>) {
    loop {
        tokio::time::sleep(RECONNECT_EVERY).await;
        let Some(inner) = inner.upgrade() else { return };
        for chat in inner.store.chats().unwrap_or_default().into_iter().filter(|c| c.state == ChatState::Active) {
            if let Ok(Some(mirror)) = inner.store.mirror(&chat.id) {
                if let Err(error) = inner.read_mirror(&chat.id, mirror).await {
                    debug!("mirror read for {} failed: {error}", chat.id);
                }
            }
        }
    }
}

async fn new_queue(conn: &NetClient, chat_id: &str, node: &str) -> Result<QueueRow> {
    let recipient = Ed25519Key::generate();
    match conn
        .request(request::Body::QueueNew(QueueNew { recipient_auth_pk: recipient.public_key().to_vec() }), None)
        .await?
    {
        response::Body::QueueCreated(q) => Ok(QueueRow {
            chat_id: chat_id.into(),
            node: node.into(),
            recipient_id: q.recipient_id,
            recipient_sk: recipient.to_bytes().to_vec(),
            sender_id: q.sender_id,
        }),
        other => Err(refused(other)),
    }
}

async fn subscribe_queue(conn: &NetClient, q: &QueueRow) -> Result<()> {
    let body = request::Body::QueueSub(QueueSub { recipient_id: q.recipient_id.clone() });
    expect_done(conn.request(body, Some(&key(&q.recipient_sk))).await?)
}

fn expect_done(resp: response::Body) -> Result<()> {
    match resp {
        response::Body::Done(_) => Ok(()),
        other => Err(refused(other)),
    }
}

fn refused(resp: response::Body) -> Error {
    Error::Node(format!("unexpected response {resp:?}").chars().take(200).collect())
}

/// «Печатает…» старше этого — уже неактуально.
const TYPING_FRESH_MS: u64 = 10_000;

fn archive_key(chat_id: &str) -> String {
    format!("archived:{chat_id}")
}

/// Чат, в который вступили по команде своего устройства: о нём уже знают, объявлять не нужно.
fn quiet_key(chat_id: &str) -> String {
    format!("quiet.{chat_id}")
}

fn device_key(id: &str) -> String {
    format!("device.rec.{id}")
}

fn owner_key(chat_id: &str) -> String {
    format!("owner:{chat_id}")
}

fn mirror_row(c: MirrorCreds) -> MirrorRow {
    MirrorRow { node: c.node, log_id: c.log_id, write_sk: c.write_sk, read_sk: c.read_sk, read_offset: 0 }
}

/// Одна и та же нода может быть записана разными адресами — сравниваем по ключу.
fn node_key(node: &str) -> String {
    node.parse::<NodeAddr>().map(|a| hex::encode(a.public_key)).unwrap_or_else(|_| node.to_string())
}

fn short(node: &str) -> String {
    node.rsplit('@').next().unwrap().to_string()
}

#[cfg(test)]
mod edit_tests {
    use super::*;
    use core_node::{Config, Node, NodeIdentity};

    async fn wait(mut f: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(15), async {
            while !f() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authenticated_member_cannot_edit_another_author_or_chat() {
        let node = Node::bind(
            Config { listen: "127.0.0.1:0".into(), ..Default::default() },
            NodeIdentity::generate(),
            core_node::Store::open_in_memory().unwrap(),
        )
        .await
        .unwrap();
        let addr = node.address().to_string();
        tokio::spawn(node.run());
        let dir = tempfile::tempdir().unwrap();
        let alice = Client::open(&dir.path().join("alice"), &addr).await.unwrap();
        let bob = Client::open(&dir.path().join("bob"), &addr).await.unwrap();
        let (a_chat, link) = alice.create_chat(None).await.unwrap();
        let b_chat = bob.accept_invite(&link).await.unwrap();
        wait(|| bob.chat(&b_chat).unwrap().state == ChatState::Active).await;
        let id = alice.send_text(&a_chat, "original", None, None).await.unwrap();
        wait(|| !bob.messages(&b_chat, 10, None).unwrap().is_empty()).await;
        let chat = bob.inner.store.chat(&b_chat).unwrap().unwrap();
        let forged = Payload::Edit { id: id.clone(), text: "forged".into(), ts: now_ms(), edit_id: new_id() };
        bob.inner.send_payload(&chat, &forged).await.unwrap();
        bob.send_text(&b_chat, "barrier", None, None).await.unwrap();
        wait(|| alice.messages(&a_chat, 10, None).unwrap().len() == 2).await;
        assert_eq!(alice.messages(&a_chat, 10, None).unwrap()[0].text, "original");
        assert_eq!(alice.messages(&a_chat, 10, None).unwrap()[0].edited_ms, 0);

        // Even the correct author cannot target a message in a different chat.
        let (other, link) = alice.create_chat(None).await.unwrap();
        let b_other = bob.accept_invite(&link).await.unwrap();
        wait(|| bob.chat(&b_other).unwrap().state == ChatState::Active).await;
        let chat = alice.inner.store.chat(&other).unwrap().unwrap();
        alice.inner.send_payload(&chat, &forged).await.unwrap();
        alice.send_text(&other, "barrier", None, None).await.unwrap();
        wait(|| bob.messages(&b_other, 10, None).unwrap().len() == 1).await;
        assert_eq!(bob.messages(&b_chat, 10, None).unwrap()[0].text, "original");
        assert_eq!(bob.messages(&b_chat, 10, None).unwrap()[0].edited_ms, 0);
    }
}
