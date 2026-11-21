//! Сервер ноды: приём соединений, Noise, обработка команд, подписки, соседи.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use core_directory::{verify_descriptor, verify_session, Directory, NodeId};
use core_net::{NetError, NodeAddr};
use core_proto::frame::{FrameType, MAX_BODY, MEDIA_MAX_BODY};
use core_proto::msg::{
    event, request, response, CommitConflict, Done, ErrorCode, ErrorReply, Event, Gossip, LogAppended, LogEntries,
    LogEntry, LogEvent, NetSnapshotReply, NodeDescriptor, PeerWelcome, Pong, QueueCreated, RelayFrame, Request,
    Response, LOG_ID_LEN, MAX_BLOB, MAX_PRESENCE_SEALED, MAX_PRESENCE_WATCH, MAX_ROOMS_PER_CONN, MSG_ID_LEN,
    PRESENCE_ID_LEN, PUBLIC_KEY_LEN, QUEUE_ID_LEN, ROOM_ID_LEN,
};
use prost::Message;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::hub::Hub;
use crate::peers::{self, Peers, SeenCache};
use crate::presence::{PresenceError, PresenceTable};
use crate::store::{Store, StoreError};
use crate::{now_ms, short_id, Config, NodeIdentity};

const OUTBOUND_QUEUE: usize = 256;
const CATCH_UP_BATCH: u32 = 64;
const MAX_READ_LIMIT: u32 = 256;
/// Запас в кадре на обёртку ответа.
const RESPONSE_BUDGET: usize = MAX_BODY - 256;

/// Префиксы ключей подписок соединения: один и тот же ID не путается между типами.
const SUB_QUEUE: u8 = 0;
const SUB_LOG: u8 = 1;
const SUB_PRESENCE: u8 = 2;
const SUB_PEER_LINK: u8 = 3;
const SUB_ROOM: u8 = 4;

/// Номера соединений — чтобы не пересылать кадр звонка его же отправителю.
static NEXT_CONN: AtomicU64 = AtomicU64::new(1);

pub(crate) struct State {
    pub identity: NodeIdentity,
    pub node_id: NodeId,
    pub store: Store,
    pub hub: Hub,
    pub config: Config,
    pub directory: Mutex<Directory>,
    pub peers: Peers,
    pub seen: Mutex<SeenCache>,
    pub presence: Mutex<PresenceTable>,
    pub push: Option<crate::push::Gateway>,
    push_forward: Option<mpsc::Sender<core_proto::msg::PushNotify>>,
    pub own_descriptor: Mutex<NodeDescriptor>,
    /// Клиентские соединения (без соседей-нод).
    pub clients: AtomicUsize,
    pub connections: AtomicUsize,
    pub started: Instant,
    /// Ноды по задержке (только с `git_nodes`): дозвон начинается с ближайших.
    pub ranked: Mutex<Vec<crate::discovery::Ranked>>,
}

pub struct Node {
    listener: TcpListener,
    state: Arc<State>,
}

impl Node {
    pub async fn bind(config: Config, identity: NodeIdentity, store: Store) -> std::io::Result<Self> {
        let listener = TcpListener::bind(&config.listen).await?;
        let local = listener.local_addr()?;
        let primary = config.public_host.clone().unwrap_or_else(|| local.to_string());
        let mut addresses = vec![primary];
        addresses.extend(config.extra_addresses.iter().filter(|a| !a.trim().is_empty()).map(|a| a.trim().to_string()));

        let now = now_ms();
        let own_descriptor = peers::make_descriptor(&identity, addresses, &config, now);
        let mut directory = Directory::default();
        let _ = directory.apply_descriptor(own_descriptor.clone(), now);

        let push = crate::push::Gateway::from_env(&identity).map_err(std::io::Error::other)?;
        let push_forward = crate::push::forwarder()?;
        let state = State {
            push,
            push_forward,
            node_id: identity.node_id(),
            identity,
            store,
            hub: Hub::default(),
            config,
            directory: Mutex::new(directory),
            peers: Peers::default(),
            seen: Mutex::default(),
            presence: Mutex::default(),
            own_descriptor: Mutex::new(own_descriptor),
            clients: AtomicUsize::new(0),
            connections: AtomicUsize::new(0),
            started: Instant::now(),
            ranked: Mutex::default(),
        };
        Ok(Self { listener, state: Arc::new(state) })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Адрес для клиентов: первый адрес из дескриптора (`public_host` или фактический сокет).
    pub fn address(&self) -> NodeAddr {
        let host = self.state.own_descriptor.lock().unwrap().addresses[0].clone();
        self.state.identity.address(&host)
    }

    pub async fn run(self) -> std::io::Result<()> {
        let state = self.state;
        tokio::spawn(cleanup_loop(state.clone()));
        tokio::spawn(presence_loop(state.clone()));
        tokio::spawn(peers::publisher_loop(state.clone()));
        tokio::spawn(peers::dialer_loop(state.clone()));
        tokio::spawn(crate::discovery::discovery_loop(state.clone()));
        let limit = Arc::new(Semaphore::new(state.config.max_connections));

        loop {
            let stream = match self.listener.accept().await {
                Ok((stream, _peer)) => stream,
                Err(e) => {
                    // Например, кончились файловые дескрипторы — не роняем ноду.
                    warn!("⚠️ accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                debug!("🚦 connection limit reached, rejecting");
                continue;
            };
            let state = state.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = handle_connection(state, stream).await {
                    debug!("🔌 connection closed with error: {e}");
                }
            });
        }
    }
}

async fn cleanup_loop(state: Arc<State>) {
    let mut tick = tokio::time::interval(Duration::from_secs(state.config.cleanup_interval_secs.max(1)));
    loop {
        tick.tick().await;
        let result = state.store.cleanup(
            now_ms(),
            state.config.queue_ttl_secs.saturating_mul(1000),
            state.config.log_ttl_secs.saturating_mul(1000),
        );
        match result {
            Ok(stats) => info!(
                "🧹 TTL cleanup: queue_messages={} log_entries={} logs={}",
                stats.queue_messages, stats.log_entries, stats.logs
            ),
            Err(e) => warn!("⚠️ TTL cleanup failed: {e}"),
        }
    }
}

/// Раз в секунду: перевести в офлайн тех, чей heartbeat истёк.
async fn presence_loop(state: Arc<State>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let expired = state.presence.lock().unwrap().expire(now_ms());
        for update in expired {
            let id = update.presence_id.clone();
            state.hub.publish_presence(&id, update);
        }
    }
}

// ───────────────────────────── Соединение ─────────────────────────────

type Outbound = mpsc::Sender<(FrameType, Vec<u8>)>;

struct Conn {
    state: Arc<State>,
    session_hash: Vec<u8>,
    out: Outbound,
    /// Активные подписки этого соединения: [тип] + ID → задача пересылки.
    subscriptions: HashMap<Vec<u8>, JoinHandle<()>>,
    /// Если это соседняя нода: её node_id и ID связи в `Peers`.
    peer: Option<(NodeId, u64)>,
    /// Медиа-соединение звонка: только команды комнат.
    media: bool,
    id: u64,
}

fn sub_key(kind: u8, id: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + id.len());
    key.push(kind);
    key.extend_from_slice(id);
    key
}

async fn handle_connection(state: Arc<State>, stream: TcpStream) -> Result<(), NetError> {
    let session = core_net::accept(stream, &state.identity.noise.private).await?;
    let mut reader = session.reader;
    let mut writer = session.writer;
    let media = session.mode == core_net::session::Mode::Media;
    state.connections.fetch_add(1, Ordering::Relaxed);
    // Медиа-соединение — второе соединение того же клиента, в счётчик клиентов не входит.
    if !media {
        state.clients.fetch_add(1, Ordering::Relaxed);
    }

    let (out, mut out_rx) = mpsc::channel::<(FrameType, Vec<u8>)>(OUTBOUND_QUEUE);
    let writer_task = tokio::spawn(async move {
        while let Some((ty, body)) = out_rx.recv().await {
            if writer.send(ty, &body).await.is_err() {
                break;
            }
        }
    });

    let idle = Duration::from_secs(state.config.idle_timeout_secs);
    let mut conn = Conn {
        state: state.clone(),
        session_hash: session.handshake_hash,
        out,
        subscriptions: HashMap::new(),
        peer: None,
        media,
        id: NEXT_CONN.fetch_add(1, Ordering::Relaxed),
    };

    let result = loop {
        let (ty, body) = match tokio::time::timeout(idle, reader.recv()).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(NetError::Closed)) | Err(_) => break Ok(()),
            Ok(Err(e)) => break Err(e),
        };
        if ty != FrameType::Request {
            break Err(NetError::Protocol("only requests are expected from a client".into()));
        }
        let req = match Request::decode(&*body) {
            Ok(req) => req,
            Err(e) => break Err(e.into()),
        };
        let resp = conn.handle(&req);
        // `corr_id = 0` — команда без ответа (кадры звонка).
        if req.corr_id == 0 {
            continue;
        }
        if conn.out.send((FrameType::Response, resp.encode_to_vec())).await.is_err() {
            break Ok(());
        }
    };

    for (_, task) in conn.subscriptions.drain() {
        task.abort();
    }
    match conn.peer.take() {
        Some((node_id, link)) => {
            state.peers.unregister(link);
            info!("💔 peer disconnected (inbound) node={}", short_id(&node_id));
        }
        None if !media => {
            state.clients.fetch_sub(1, Ordering::Relaxed);
        }
        None => {}
    }
    state.connections.fetch_sub(1, Ordering::Relaxed);
    drop(conn);
    // Все отправители закрыты → writer допишет очередь и завершится.
    let _ = writer_task.await;
    result
}

/// Ошибка обработки команды → `ErrorReply` клиенту.
struct Fail(ErrorCode, String);

impl Fail {
    fn bad(msg: impl Into<String>) -> Self {
        Self(ErrorCode::BadRequest, msg.into())
    }

    /// Одинаковый ответ на «нет такого объекта» и «неверная подпись»: по ответу нельзя понять,
    /// существует ли чужая очередь/журнал.
    fn auth() -> Self {
        Self(ErrorCode::Auth, "auth".into())
    }
}

impl From<StoreError> for Fail {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound => Self(ErrorCode::NotFound, "not found".into()),
            StoreError::AlreadyExists => Self(ErrorCode::AlreadyExists, "already exists".into()),
            StoreError::Quota => Self(ErrorCode::QuotaExceeded, "queue is full".into()),
            StoreError::StaleEpoch => Self(ErrorCode::Conflict, "stale epoch".into()),
            StoreError::Conflict(_) => Self(ErrorCode::Conflict, "commit conflict".into()),
            StoreError::Sql(e) => {
                warn!("💥 storage error: {e}");
                Self(ErrorCode::Internal, "internal error".into())
            }
        }
    }
}

fn check_len(value: &[u8], len: usize, field: &str) -> Result<(), Fail> {
    if value.len() == len {
        Ok(())
    } else {
        Err(Fail::bad(format!("{field}: expected {len} bytes")))
    }
}

fn check_blob(blob: &[u8]) -> Result<(), Fail> {
    if blob.len() > MAX_BLOB {
        return Err(Fail(ErrorCode::TooLarge, format!("max {MAX_BLOB} bytes")));
    }
    Ok(())
}

impl Conn {
    fn handle(&mut self, req: &Request) -> Response {
        let body = self
            .dispatch(req)
            .unwrap_or_else(|Fail(code, message)| response::Body::Error(ErrorReply { code: code as i32, message }));
        Response { corr_id: req.corr_id, body: Some(body) }
    }

    fn verify(&self, req: &Request, public_key: &[u8]) -> Result<(), Fail> {
        if core_crypto::verify(public_key, &req.signing_bytes(&self.session_hash), &req.auth_sig) {
            Ok(())
        } else {
            Err(Fail::auth())
        }
    }

    fn dispatch(&mut self, req: &Request) -> Result<response::Body, Fail> {
        use request::Body as B;
        use response::Body as R;

        let Some(body) = &req.body else { return Err(Fail::bad("empty request")) };
        let store = &self.state.store;
        let now = now_ms();

        // Медиа-соединение — только для звонков; обычное — без команд комнат.
        let relay = matches!(body, B::RelayJoin(_) | B::RelayLeave(_) | B::RelaySend(_));
        if self.media != relay && !matches!(body, B::Ping(_)) {
            return Err(Fail::bad("command is not allowed on this connection"));
        }

        match body {
            B::Ping(_) => Ok(R::Pong(Pong { time_ms: now, push_forwarding: self.state.push_forward.is_some() })),
            B::PushRegister(registration) => {
                let push = self.state.push.as_ref().ok_or_else(|| Fail::bad("push gateway unavailable"))?;
                let capability = push.register(registration).map_err(|_| Fail::bad("push registration refused"))?;
                Ok(R::PushRegistered(core_proto::msg::PushRegistered { capability }))
            }
            B::PushNotify(notification) => {
                let push = self.state.push.as_ref().ok_or_else(|| Fail::bad("push gateway unavailable"))?;
                push.notify(notification).map_err(|_| Fail::auth())?;
                Ok(R::Done(Done {}))
            }

            // ───── Звонки ─────
            B::RelayJoin(c) => {
                check_len(&c.room_id, ROOM_ID_LEN, "room_id")?;
                let joined = self.subscriptions.keys().filter(|k| k.first() == Some(&SUB_ROOM)).count();
                if joined >= MAX_ROOMS_PER_CONN && !self.subscriptions.contains_key(&sub_key(SUB_ROOM, &c.room_id)) {
                    return Err(Fail(ErrorCode::QuotaExceeded, format!("max {MAX_ROOMS_PER_CONN} rooms")));
                }
                self.join_room(c.room_id.clone());
                Ok(R::Done(Done {}))
            }

            B::RelayLeave(c) => {
                self.unsubscribe(SUB_ROOM, &c.room_id);
                Ok(R::Done(Done {}))
            }

            B::RelaySend(c) => {
                // Слать можно только в комнату, в которой состоишь.
                if !self.subscriptions.contains_key(&sub_key(SUB_ROOM, &c.room_id)) {
                    return Err(Fail::auth());
                }
                if c.data.len() > MEDIA_MAX_BODY {
                    return Err(Fail(ErrorCode::TooLarge, format!("max {MEDIA_MAX_BODY} bytes")));
                }
                self.state.hub.publish_room(&c.room_id, (self.id, c.data.clone()));
                Ok(R::Done(Done {}))
            }

            // ───── Очереди ─────
            B::QueueNew(c) => {
                check_len(&c.recipient_auth_pk, PUBLIC_KEY_LEN, "recipient_auth_pk")?;
                let (recipient_id, sender_id) = store.queue_new(&c.recipient_auth_pk, now)?;
                Ok(R::QueueCreated(QueueCreated { recipient_id, sender_id }))
            }

            B::QueueSecure(c) => {
                self.verify_recipient(req, &c.recipient_id)?;
                check_len(&c.sender_auth_pk, PUBLIC_KEY_LEN, "sender_auth_pk")?;
                store.queue_secure(&c.recipient_id, &c.sender_auth_pk)?;
                Ok(R::Done(Done {}))
            }

            B::QueueSend(c) => {
                check_blob(&c.body)?;
                let (recipient_id, sender_pk) = store.queue_by_sender(&c.sender_id)?.ok_or_else(Fail::auth)?;
                if let Some(pk) = sender_pk {
                    self.verify(req, &pk)?;
                }
                let item = store.queue_push(&recipient_id, &c.body, now, self.state.config.max_queue_messages)?;
                self.state.hub.publish_queue(&recipient_id, item);
                Ok(R::Done(Done {}))
            }

            B::QueueSub(c) => {
                self.verify_recipient(req, &c.recipient_id)?;
                self.subscribe_queue(c.recipient_id.clone());
                Ok(R::Done(Done {}))
            }

            B::QueueAck(c) => {
                self.verify_recipient(req, &c.recipient_id)?;
                check_len(&c.msg_id, MSG_ID_LEN, "msg_id")?;
                if !store.queue_ack(&c.recipient_id, &c.msg_id)? {
                    return Err(StoreError::NotFound.into());
                }
                Ok(R::Done(Done {}))
            }

            B::QueueDel(c) => {
                self.verify_recipient(req, &c.recipient_id)?;
                store.queue_delete(&c.recipient_id)?;
                self.unsubscribe(SUB_QUEUE, &c.recipient_id);
                Ok(R::Done(Done {}))
            }

            // ───── Журналы ─────
            B::LogNew(c) => {
                check_len(&c.log_id, LOG_ID_LEN, "log_id")?;
                check_len(&c.write_pk, PUBLIC_KEY_LEN, "write_pk")?;
                check_len(&c.read_pk, PUBLIC_KEY_LEN, "read_pk")?;
                store.log_new(&c.log_id, &c.write_pk, &c.read_pk, now)?;
                Ok(R::Done(Done {}))
            }

            B::NotifySet(c) => {
                if self.state.push_forward.is_none() {
                    return Err(Fail::bad("push forwarding unavailable"));
                }
                check_len(&c.slot, 16, "notification slot")?;
                for handle in [&c.alert, &c.voip] {
                    if !handle.is_empty() {
                        check_len(handle, 32, "notification capability")?;
                    }
                }
                let keys = store.log_keys(&c.log_id)?.ok_or_else(Fail::auth)?;
                self.verify(req, &keys.read_pk)?;
                store.notify_set(c, now)?;
                Ok(R::Done(Done {}))
            }

            B::LogAppend(c) => {
                check_blob(&c.blob)?;
                let keys = store.log_keys(&c.log_id)?.ok_or_else(Fail::auth)?;
                self.verify(req, &keys.write_pk)?;
                if !c.call_id.is_empty() {
                    check_len(&c.call_id, 12, "call id")?;
                }
                if c.alert || !c.call_id.is_empty() {
                    check_len(&c.sender_slot, 16, "sender notification slot")?;
                }
                let entry = store.log_append(&c.log_id, &c.blob, now)?;
                let offset = entry.offset;
                self.state.hub.publish_log(&c.log_id, entry);
                if let Some(forward) = self.state.push_forward.as_ref().filter(|_| c.alert || !c.call_id.is_empty()) {
                    match store.notify_targets(&c.log_id, &c.sender_slot, !c.call_id.is_empty(), now) {
                        Ok(targets) => {
                            for capability in targets {
                                if forward
                                    .try_send(core_proto::msg::PushNotify { capability, call_id: c.call_id.clone() })
                                    .is_err()
                                {
                                    debug!("push forwarding queue full");
                                    break;
                                }
                            }
                        }
                        Err(_) => warn!("failed to look up notification routes"),
                    }
                }
                Ok(R::LogAppended(LogAppended { offset }))
            }

            B::LogCommit(c) => {
                check_blob(&c.blob)?;
                let keys = store.log_keys(&c.log_id)?.ok_or_else(Fail::auth)?;
                self.verify(req, &keys.write_pk)?;
                match store.log_commit(&c.log_id, c.epoch, &c.blob, now) {
                    Ok(entry) => {
                        let offset = entry.offset;
                        self.state.hub.publish_log(&c.log_id, entry);
                        Ok(R::LogAppended(LogAppended { offset }))
                    }
                    Err(StoreError::Conflict(winner)) => {
                        Ok(R::CommitConflict(CommitConflict { winner: Some(*winner) }))
                    }
                    Err(e) => Err(e.into()),
                }
            }

            B::LogRead(c) => {
                let keys = store.log_keys(&c.log_id)?.ok_or_else(Fail::auth)?;
                self.verify(req, &keys.read_pk)?;
                let limit = c.limit.clamp(1, MAX_READ_LIMIT);
                let entries = fit_in_frame(store.log_read(&c.log_id, c.from_offset, limit)?);
                let next_offset = entries.last().map_or(c.from_offset, |e| e.offset + 1);
                Ok(R::LogEntries(LogEntries { entries, next_offset }))
            }

            B::LogWatch(c) => {
                let keys = store.log_keys(&c.log_id)?.ok_or_else(Fail::auth)?;
                self.verify(req, &keys.read_pk)?;
                self.subscribe_log(c.log_id.clone(), c.from_offset);
                Ok(R::Done(Done {}))
            }

            B::Unsubscribe(c) => {
                for kind in [SUB_QUEUE, SUB_LOG, SUB_PRESENCE] {
                    self.unsubscribe(kind, &c.id);
                }
                Ok(R::Done(Done {}))
            }

            // ───── Сеть нод ─────
            B::PeerHello(h) => self.peer_hello(h, now),

            B::Gossip(g) => {
                let Some((node_id, _)) = self.peer else { return Err(Fail::auth()) };
                peers::handle_gossip(&self.state, g.clone(), Some(node_id));
                Ok(R::Done(Done {}))
            }

            B::NetSnapshot(c) => {
                let cursor: Option<NodeId> = match c.cursor.as_slice() {
                    [] => None,
                    bytes => Some(bytes.try_into().map_err(|_| Fail::bad("cursor: expected 32 bytes"))?),
                };
                let (nodes, next) = self.state.directory.lock().unwrap().page(cursor.as_ref(), RESPONSE_BUDGET);
                Ok(R::NetSnapshotReply(NetSnapshotReply {
                    nodes,
                    next_cursor: next.map(|n| n.to_vec()).unwrap_or_default(),
                    self_id: self.state.node_id.to_vec(),
                }))
            }

            // ───── Presence ─────
            B::PresencePut(c) => {
                check_len(&c.presence_id, PRESENCE_ID_LEN, "presence_id")?;
                check_len(&c.write_pk, PUBLIC_KEY_LEN, "write_pk")?;
                if c.sealed.len() > MAX_PRESENCE_SEALED {
                    return Err(Fail(ErrorCode::TooLarge, format!("max {MAX_PRESENCE_SEALED} bytes")));
                }
                self.verify(req, &c.write_pk)?;
                let update = self
                    .state
                    .presence
                    .lock()
                    .unwrap()
                    .put(&c.presence_id, &c.write_pk, &c.sealed, c.ttl_secs, now)
                    .map_err(|e| match e {
                        PresenceError::WrongKey => Fail::auth(),
                        PresenceError::Full => Fail(ErrorCode::QuotaExceeded, "presence table is full".into()),
                    })?;
                if let Some(update) = update {
                    self.state.hub.publish_presence(&c.presence_id, update);
                }
                Ok(R::Done(Done {}))
            }

            B::PresenceWatch(c) => {
                if c.presence_ids.len() > MAX_PRESENCE_WATCH {
                    return Err(Fail::bad(format!("max {MAX_PRESENCE_WATCH} ids per request")));
                }
                for id in &c.presence_ids {
                    check_len(id, PRESENCE_ID_LEN, "presence_id")?;
                }
                for id in &c.presence_ids {
                    self.subscribe_presence(id.clone());
                }
                Ok(R::Done(Done {}))
            }
        }
    }

    fn verify_recipient(&self, req: &Request, recipient_id: &[u8]) -> Result<(), Fail> {
        if recipient_id.len() != QUEUE_ID_LEN {
            return Err(Fail::auth());
        }
        let queue = self.state.store.queue_auth(recipient_id)?.ok_or_else(Fail::auth)?;
        self.verify(req, &queue.recipient_auth_pk)
    }

    /// Соседняя нода представляется: проверяем дескриптор и владение ключом в этой сессии.
    fn peer_hello(&mut self, h: &core_proto::msg::PeerHello, now: u64) -> Result<response::Body, Fail> {
        if self.peer.is_some() {
            return Err(Fail::bad("already introduced"));
        }
        let descriptor = h.descriptor.clone().ok_or_else(|| Fail::bad("descriptor required"))?;
        let node_id = verify_descriptor(&descriptor, now).map_err(|e| Fail(ErrorCode::Auth, e.to_string()))?;
        if !verify_session(&descriptor.ed25519_pk, &self.session_hash, &h.session_sig) {
            return Err(Fail::auth());
        }
        if node_id == self.state.node_id {
            return Err(Fail::bad("cannot peer with itself"));
        }
        if self.state.peers.len() >= self.state.config.max_peers * 2 {
            return Err(Fail(ErrorCode::QuotaExceeded, "too many peers".into()));
        }
        let _ = self.state.directory.lock().unwrap().apply_descriptor(descriptor, now);

        let (tx, mut rx) = mpsc::channel::<Gossip>(peers::LINK_QUEUE);
        let link = self.state.peers.register(node_id, tx.clone());
        peers::initial_sync(&self.state, &tx);
        let out = self.out.clone();
        let task = tokio::spawn(async move {
            while let Some(g) = rx.recv().await {
                if send_event(&out, event::Body::Gossip(g)).await.is_err() {
                    return;
                }
            }
        });
        self.subscriptions.insert(sub_key(SUB_PEER_LINK, &[]), task);
        self.peer = Some((node_id, link));
        self.state.clients.fetch_sub(1, Ordering::Relaxed);
        info!("🔗 peer connected (inbound) node={}", short_id(&node_id));

        let own = self.state.own_descriptor.lock().unwrap().clone();
        Ok(response::Body::PeerWelcome(PeerWelcome { descriptor: Some(own) }))
    }

    /// Комната звонка: кадры других участников — сразу в соединение; не успевает — теряются
    /// (для живого звука и видео задержка хуже потери).
    fn join_room(&mut self, room_id: Vec<u8>) {
        let mut rx = self.state.hub.join_room(&room_id);
        let out = self.out.clone();
        let me = self.id;
        let room = room_id.clone();
        let task = tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok((from, data)) if from != me => {
                        let ev =
                            Event { body: Some(event::Body::RelayFrame(RelayFrame { room_id: room.clone(), data })) };
                        match out.try_send((FrameType::Event, ev.encode_to_vec())) {
                            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
                            Err(mpsc::error::TrySendError::Closed(_)) => return,
                        }
                    }
                    Ok(_) | Err(RecvError::Lagged(_)) => {}
                    Err(RecvError::Closed) => return,
                }
            }
        });
        self.replace_subscription(SUB_ROOM, &room_id, task);
    }

    fn unsubscribe(&mut self, kind: u8, id: &[u8]) {
        if let Some(task) = self.subscriptions.remove(&sub_key(kind, id)) {
            task.abort();
        }
    }

    fn replace_subscription(&mut self, kind: u8, id: &[u8], task: JoinHandle<()>) {
        if let Some(old) = self.subscriptions.insert(sub_key(kind, id), task) {
            old.abort();
        }
    }

    /// Подписка на очередь: сначала всё недоставленное, затем новые сообщения.
    fn subscribe_queue(&mut self, recipient_id: Vec<u8>) {
        // Подписываемся на hub ДО чтения хранилища, чтобы не потерять сообщения между ними.
        let mut rx = self.state.hub.subscribe_queue(&recipient_id);
        let state = self.state.clone();
        let out = self.out.clone();
        let rid = recipient_id.clone();

        let task = tokio::spawn(async move {
            let mut last_seq = 0i64;
            if queue_catch_up(&state, &rid, &mut last_seq, &out).await.is_err() {
                return;
            }
            loop {
                match rx.recv().await {
                    Ok((seq, msg)) if seq > last_seq => {
                        last_seq = seq;
                        if send_event(&out, event::Body::QueueMessage(msg)).await.is_err() {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => {
                        if queue_catch_up(&state, &rid, &mut last_seq, &out).await.is_err() {
                            return;
                        }
                    }
                    Err(RecvError::Closed) => return,
                }
            }
        });
        self.replace_subscription(SUB_QUEUE, &recipient_id, task);
    }

    /// Подписка на журнал с `from`: история из хранилища, затем новые записи.
    fn subscribe_log(&mut self, log_id: Vec<u8>, from: u64) {
        let mut rx = self.state.hub.subscribe_log(&log_id);
        let state = self.state.clone();
        let out = self.out.clone();
        let id = log_id.clone();

        let task = tokio::spawn(async move {
            let mut next = from;
            if log_catch_up(&state, &id, &mut next, &out).await.is_err() {
                return;
            }
            loop {
                match rx.recv().await {
                    Ok(entry) if entry.offset == next => {
                        next += 1;
                        if send_log_event(&out, &id, entry).await.is_err() {
                            return;
                        }
                    }
                    // Пропуск — дочитываем из хранилища.
                    Ok(entry) if entry.offset > next => {
                        if log_catch_up(&state, &id, &mut next, &out).await.is_err() {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(_)) => {
                        if log_catch_up(&state, &id, &mut next, &out).await.is_err() {
                            return;
                        }
                    }
                    Err(RecvError::Closed) => return,
                }
            }
        });
        self.replace_subscription(SUB_LOG, &log_id, task);
    }

    /// Подписка на статус: текущее состояние сразу (если известно), затем изменения.
    fn subscribe_presence(&mut self, presence_id: Vec<u8>) {
        let mut rx = self.state.hub.subscribe_presence(&presence_id);
        let state = self.state.clone();
        let out = self.out.clone();
        let id = presence_id.clone();

        let task = tokio::spawn(async move {
            let current = state.presence.lock().unwrap().get(&id);
            if let Some(update) = current {
                if send_event(&out, event::Body::PresenceUpdate(update)).await.is_err() {
                    return;
                }
            }
            loop {
                match rx.recv().await {
                    Ok(update) => {
                        if send_event(&out, event::Body::PresenceUpdate(update)).await.is_err() {
                            return;
                        }
                    }
                    Err(RecvError::Lagged(_)) => {
                        let current = state.presence.lock().unwrap().get(&id);
                        if let Some(update) = current {
                            if send_event(&out, event::Body::PresenceUpdate(update)).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(RecvError::Closed) => return,
                }
            }
        });
        self.replace_subscription(SUB_PRESENCE, &presence_id, task);
    }
}

/// Оставить столько записей, сколько влезает в один кадр ответа (минимум одну).
fn fit_in_frame(entries: Vec<LogEntry>) -> Vec<LogEntry> {
    let mut size = 0;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let len = entry.encoded_len() + 8;
        if !out.is_empty() && size + len > RESPONSE_BUDGET {
            break;
        }
        size += len;
        out.push(entry);
    }
    out
}

async fn queue_catch_up(state: &State, rid: &[u8], last_seq: &mut i64, out: &Outbound) -> Result<(), ()> {
    loop {
        let batch = state.store.queue_pending(rid, *last_seq, CATCH_UP_BATCH).map_err(|_| ())?;
        if batch.is_empty() {
            return Ok(());
        }
        for (seq, msg) in batch {
            *last_seq = seq;
            send_event(out, event::Body::QueueMessage(msg)).await?;
        }
    }
}

async fn log_catch_up(state: &State, log_id: &[u8], next: &mut u64, out: &Outbound) -> Result<(), ()> {
    loop {
        let batch = state.store.log_read(log_id, *next, CATCH_UP_BATCH).map_err(|_| ())?;
        if batch.is_empty() {
            return Ok(());
        }
        for entry in batch {
            *next = entry.offset + 1;
            send_log_event(out, log_id, entry).await?;
        }
    }
}

async fn send_log_event(out: &Outbound, log_id: &[u8], entry: LogEntry) -> Result<(), ()> {
    send_event(out, event::Body::LogEvent(LogEvent { log_id: log_id.to_vec(), entry: Some(entry) })).await
}

async fn send_event(out: &Outbound, body: event::Body) -> Result<(), ()> {
    let ev = Event { body: Some(body) };
    out.send((FrameType::Event, ev.encode_to_vec())).await.map_err(|_| ())
}
