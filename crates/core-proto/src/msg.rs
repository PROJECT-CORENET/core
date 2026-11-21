//! Сообщения клиент ↔ нода (АРХИТЕКТУРА.md §23.3).
//!
//! Описаны через prost-derive, без .proto и protoc: формат на проводе — обычный protobuf,
//! поэтому позже можно выгрузить схему для других языков без смены формата.

use prost::Message;

/// Максимальный размер полезной нагрузки (сообщения очереди / записи журнала).
/// Оставляет запас в кадре под идентификаторы, подпись и обёртку.
pub const MAX_BLOB: usize = 15 * 1024;
pub const QUEUE_ID_LEN: usize = 24;
pub const MSG_ID_LEN: usize = 16;
pub const LOG_ID_LEN: usize = 32;
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

const AUTH_DOMAIN: &[u8] = b"CORE/v1/request-auth";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ErrorCode {
    Unspecified = 0,
    BadRequest = 1,
    /// Неверная подпись ИЛИ объект не найден (не раскрываем, существует ли ID).
    Auth = 2,
    NotFound = 3,
    AlreadyExists = 4,
    TooLarge = 5,
    QuotaExceeded = 6,
    Conflict = 7,
    Internal = 8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum EntryKind {
    Message = 0,
    Commit = 1,
}

// ───────────────────────────── Запросы ─────────────────────────────

#[derive(Clone, PartialEq, Message)]
pub struct Request {
    #[prost(uint64, tag = "1")]
    pub corr_id: u64,
    /// Ed25519-подпись над [`Request::signing_bytes`]. Пусто для неподписываемых команд.
    #[prost(bytes = "vec", tag = "2")]
    pub auth_sig: Vec<u8>,
    #[prost(
        oneof = "request::Body",
        tags = "10, 11, 12, 13, 14, 15, 16, 20, 21, 22, 23, 24, 25, 30, 31, 32, 40, 41, 50, 51, 52, 60, 61, 62"
    )]
    pub body: Option<request::Body>,
}

pub mod request {
    use super::*;

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "10")]
        Ping(Ping),
        #[prost(message, tag = "11")]
        QueueNew(QueueNew),
        #[prost(message, tag = "12")]
        QueueSecure(QueueSecure),
        #[prost(message, tag = "13")]
        QueueSend(QueueSend),
        #[prost(message, tag = "14")]
        QueueSub(QueueSub),
        #[prost(message, tag = "15")]
        QueueAck(QueueAck),
        #[prost(message, tag = "16")]
        QueueDel(QueueDel),
        #[prost(message, tag = "20")]
        LogNew(LogNew),
        #[prost(message, tag = "21")]
        LogAppend(LogAppend),
        #[prost(message, tag = "22")]
        LogCommit(LogCommit),
        #[prost(message, tag = "23")]
        LogRead(LogRead),
        #[prost(message, tag = "24")]
        LogWatch(LogWatch),
        #[prost(message, tag = "25")]
        Unsubscribe(Unsubscribe),
        #[prost(message, tag = "30")]
        PeerHello(PeerHello),
        #[prost(message, tag = "31")]
        Gossip(Gossip),
        #[prost(message, tag = "32")]
        NetSnapshot(NetSnapshot),
        #[prost(message, tag = "40")]
        PresencePut(PresencePut),
        #[prost(message, tag = "41")]
        PresenceWatch(PresenceWatch),
        /// Звонки (только в медиа-соединении): войти в комнату, выйти, переслать кадр остальным.
        #[prost(message, tag = "50")]
        RelayJoin(RelayJoin),
        #[prost(message, tag = "51")]
        RelayLeave(RelayLeave),
        /// Без ответа (`corr_id = 0`): кадр звонка не ждёт подтверждения.
        #[prost(message, tag = "52")]
        RelaySend(RelaySend),
        #[prost(message, tag = "60")]
        PushRegister(PushRegister),
        #[prost(message, tag = "61")]
        PushNotify(PushNotify),
        #[prost(message, tag = "62")]
        NotifySet(NotifySet),
    }
}

impl Request {
    /// Байты, которые подписываются ключом авторизации.
    ///
    /// Привязаны к хешу Noise-рукопожатия: подпись из одной сессии нельзя
    /// воспроизвести в другой (защита от replay).
    pub fn signing_bytes(&self, session_hash: &[u8]) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.auth_sig.clear();
        let encoded = unsigned.encode_to_vec();
        let mut out = Vec::with_capacity(AUTH_DOMAIN.len() + 2 + session_hash.len() + encoded.len());
        out.extend_from_slice(AUTH_DOMAIN);
        out.extend_from_slice(&(session_hash.len() as u16).to_be_bytes());
        out.extend_from_slice(session_hash);
        out.extend_from_slice(&encoded);
        out
    }
}

/// Register an APNs token over the gateway's Noise connection.
#[derive(Clone, PartialEq, Message)]
pub struct PushRegister {
    #[prost(bytes = "vec", tag = "1")]
    pub token: Vec<u8>,
    #[prost(bool, tag = "2")]
    pub sandbox: bool,
    #[prost(bool, tag = "3")]
    pub voip: bool,
    #[prost(bytes = "vec", tag = "4")]
    pub scope: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PushRegistered {
    #[prost(bytes = "vec", tag = "1")]
    pub capability: Vec<u8>,
}

pub const MAX_PUSH_PREVIEW: usize = 2700;

/// Opaque notification capability. A 12-byte call identifier is required for VoIP.
#[derive(Clone, PartialEq, Message)]
pub struct PushNotify {
    #[prost(bytes = "vec", tag = "1")]
    pub capability: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub call_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub preview: Vec<u8>,
}

/// Attach a device's opaque routes to a journal. Signed with the journal read key.
#[derive(Clone, PartialEq, Message)]
pub struct NotifySet {
    #[prost(bytes = "vec", tag = "1")]
    pub log_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub slot: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub alert: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub voip: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct Ping {}

/// Создать очередь. Подписи не требует (в будущем — анонимный токен, §19).
#[derive(Clone, PartialEq, Message)]
pub struct QueueNew {
    #[prost(bytes = "vec", tag = "1")]
    pub recipient_auth_pk: Vec<u8>,
}

/// Закрепить ключ отправителя: после этого писать в очередь может только он.
/// Подпись: ключ получателя.
#[derive(Clone, PartialEq, Message)]
pub struct QueueSecure {
    #[prost(bytes = "vec", tag = "1")]
    pub recipient_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub sender_auth_pk: Vec<u8>,
}

/// Подпись: ключ отправителя, если очередь закреплена; иначе не нужна.
#[derive(Clone, PartialEq, Message)]
pub struct QueueSend {
    #[prost(bytes = "vec", tag = "1")]
    pub sender_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub body: Vec<u8>,
}

/// Подписка: нода шлёт все недоставленные сообщения и новые по мере поступления.
/// Подпись: ключ получателя.
#[derive(Clone, PartialEq, Message)]
pub struct QueueSub {
    #[prost(bytes = "vec", tag = "1")]
    pub recipient_id: Vec<u8>,
}

/// Подтверждение получения — только после него сообщение удаляется. Подпись: ключ получателя.
#[derive(Clone, PartialEq, Message)]
pub struct QueueAck {
    #[prost(bytes = "vec", tag = "1")]
    pub recipient_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub msg_id: Vec<u8>,
}

/// Подпись: ключ получателя.
#[derive(Clone, PartialEq, Message)]
pub struct QueueDel {
    #[prost(bytes = "vec", tag = "1")]
    pub recipient_id: Vec<u8>,
}

/// Создать журнал. `log_id` выбирает клиент (выводится из MLS-эпохи, §11.4).
#[derive(Clone, PartialEq, Message)]
pub struct LogNew {
    #[prost(bytes = "vec", tag = "1")]
    pub log_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub write_pk: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub read_pk: Vec<u8>,
}

/// Подпись: ключ записи.
#[derive(Clone, PartialEq, Message)]
pub struct LogAppend {
    #[prost(bytes = "vec", tag = "1")]
    pub log_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub blob: Vec<u8>,
    #[prost(bool, tag = "3")]
    pub alert: bool,
    #[prost(bytes = "vec", tag = "4")]
    pub call_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub sender_slot: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub preview: Vec<u8>,
}

/// MLS-коммит: принимается, только если для `epoch` коммита ещё нет (compare-and-swap).
/// Подпись: ключ записи.
#[derive(Clone, PartialEq, Message)]
pub struct LogCommit {
    #[prost(bytes = "vec", tag = "1")]
    pub log_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub epoch: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub blob: Vec<u8>,
}

/// Подпись: ключ чтения.
#[derive(Clone, PartialEq, Message)]
pub struct LogRead {
    #[prost(bytes = "vec", tag = "1")]
    pub log_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub from_offset: u64,
    #[prost(uint32, tag = "3")]
    pub limit: u32,
}

/// Подписка на журнал начиная с `from_offset`. Подпись: ключ чтения.
#[derive(Clone, PartialEq, Message)]
pub struct LogWatch {
    #[prost(bytes = "vec", tag = "1")]
    pub log_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub from_offset: u64,
}

// ───────────────────────────── Ответы ─────────────────────────────

#[derive(Clone, PartialEq, Message)]
pub struct Response {
    #[prost(uint64, tag = "1")]
    pub corr_id: u64,
    #[prost(oneof = "response::Body", tags = "10, 11, 12, 13, 14, 15, 16, 17, 18, 19")]
    pub body: Option<response::Body>,
}

pub mod response {
    use super::*;

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "10")]
        Done(Done),
        #[prost(message, tag = "11")]
        Error(ErrorReply),
        #[prost(message, tag = "12")]
        Pong(Pong),
        #[prost(message, tag = "13")]
        QueueCreated(QueueCreated),
        #[prost(message, tag = "14")]
        LogAppended(LogAppended),
        #[prost(message, tag = "15")]
        LogEntries(LogEntries),
        #[prost(message, tag = "16")]
        CommitConflict(CommitConflict),
        #[prost(message, tag = "17")]
        PeerWelcome(PeerWelcome),
        #[prost(message, tag = "18")]
        NetSnapshotReply(NetSnapshotReply),
        #[prost(message, tag = "19")]
        PushRegistered(PushRegistered),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct Done {}

#[derive(Clone, PartialEq, Message)]
pub struct ErrorReply {
    #[prost(enumeration = "ErrorCode", tag = "1")]
    pub code: i32,
    #[prost(string, tag = "2")]
    pub message: String,
}

#[derive(Clone, PartialEq, Message)]
pub struct Pong {
    #[prost(uint64, tag = "1")]
    pub time_ms: u64,
    #[prost(bool, tag = "2")]
    pub push_forwarding: bool,
    #[prost(bool, tag = "3")]
    pub push_previews: bool,
}

#[derive(Clone, PartialEq, Message)]
pub struct QueueCreated {
    #[prost(bytes = "vec", tag = "1")]
    pub recipient_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub sender_id: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct LogAppended {
    #[prost(uint64, tag = "1")]
    pub offset: u64,
}

#[derive(Clone, PartialEq, Message)]
pub struct LogEntries {
    #[prost(message, repeated, tag = "1")]
    pub entries: Vec<LogEntry>,
    /// С какого offset читать дальше.
    #[prost(uint64, tag = "2")]
    pub next_offset: u64,
}

/// Коммит для этой эпохи уже принят — клиент применяет победителя и повторяет на следующей эпохе.
#[derive(Clone, PartialEq, Message)]
pub struct CommitConflict {
    #[prost(message, optional, tag = "1")]
    pub winner: Option<LogEntry>,
}

#[derive(Clone, PartialEq, Message)]
pub struct LogEntry {
    #[prost(uint64, tag = "1")]
    pub offset: u64,
    #[prost(enumeration = "EntryKind", tag = "2")]
    pub kind: i32,
    /// Эпоха MLS для коммитов, 0 для обычных сообщений.
    #[prost(uint64, tag = "3")]
    pub epoch: u64,
    #[prost(uint64, tag = "4")]
    pub received_at_ms: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub blob: Vec<u8>,
}

// ───────────────────────────── События ─────────────────────────────

#[derive(Clone, PartialEq, Message)]
pub struct Event {
    #[prost(oneof = "event::Body", tags = "1, 2, 3, 4, 5")]
    pub body: Option<event::Body>,
}

pub mod event {
    use super::*;

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Body {
        #[prost(message, tag = "1")]
        QueueMessage(QueueMessage),
        #[prost(message, tag = "2")]
        LogEvent(LogEvent),
        #[prost(message, tag = "3")]
        PresenceUpdate(PresenceUpdate),
        /// Gossip от ноды-соседа, которая приняла наше соединение (§6.4).
        #[prost(message, tag = "4")]
        Gossip(Gossip),
        /// Кадр звонка от другого участника комнаты.
        #[prost(message, tag = "5")]
        RelayFrame(RelayFrame),
    }
}

#[derive(Clone, PartialEq, Message)]
pub struct QueueMessage {
    #[prost(bytes = "vec", tag = "1")]
    pub recipient_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub msg_id: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub received_at_ms: u64,
    #[prost(bytes = "vec", tag = "4")]
    pub body: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct LogEvent {
    #[prost(bytes = "vec", tag = "1")]
    pub log_id: Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub entry: Option<LogEntry>,
}

// ───────────────────────── Подписки, сеть нод, presence ─────────────────────────

/// Отменить подписку (очередь, журнал или presence) без закрытия соединения.
#[derive(Clone, PartialEq, Message)]
pub struct Unsubscribe {
    #[prost(bytes = "vec", tag = "1")]
    pub id: Vec<u8>,
}

pub const PRESENCE_ID_LEN: usize = 16;

// ───── Звонки: комната-ретранслятор ─────
//
// Нода пересылает кадры участникам комнаты и ничего не хранит. Содержимое зашифровано
// ключом звонка (его знают только участники чата — он приходит внутри MLS). Id комнаты
// случайный; нода не знает, чей это звонок.

pub const ROOM_ID_LEN: usize = 16;
/// Сколько комнат одновременно в одном медиа-соединении (групповой звонок — одна комната).
pub const MAX_ROOMS_PER_CONN: usize = 4;

#[derive(Clone, PartialEq, Message)]
pub struct RelayJoin {
    #[prost(bytes = "vec", tag = "1")]
    pub room_id: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RelayLeave {
    #[prost(bytes = "vec", tag = "1")]
    pub room_id: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RelaySend {
    #[prost(bytes = "vec", tag = "1")]
    pub room_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct RelayFrame {
    #[prost(bytes = "vec", tag = "1")]
    pub room_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub data: Vec<u8>,
}
/// Максимальный размер зашифрованного статуса.
pub const MAX_PRESENCE_SEALED: usize = 1024;
pub const MAX_PRESENCE_WATCH: usize = 256;

/// Подписанное описание ноды (§6.3). Подпись — Ed25519-ключом идентичности ноды,
/// `node_id = SHA-256(ed25519_pk)`. Связывает Noise-ключ (X25519) с идентичностью.
#[derive(Clone, PartialEq, Message)]
pub struct NodeDescriptor {
    #[prost(bytes = "vec", tag = "1")]
    pub ed25519_pk: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub x25519_pk: Vec<u8>,
    /// `host:port`, по которым к ноде подключаются.
    #[prost(string, repeated, tag = "3")]
    pub addresses: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    pub roles: Vec<String>,
    #[prost(string, tag = "5")]
    pub version: String,
    /// Код страны (заявленный нодой), например "NL".
    #[prost(string, tag = "6")]
    pub region: String,
    /// Человекочитаемое имя ноды (необязательно).
    #[prost(string, tag = "7")]
    pub name: String,
    #[prost(uint64, tag = "8")]
    pub published_at_ms: u64,
    #[prost(uint64, tag = "9")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "15")]
    pub sig: Vec<u8>,
}

/// Динамическая статистика ноды для карты сети (§16.2). Подпись — ключом идентичности ноды.
#[derive(Clone, PartialEq, Message)]
pub struct NodeStats {
    #[prost(bytes = "vec", tag = "1")]
    pub node_id: Vec<u8>,
    /// node_id нод, с которыми сейчас есть соединение.
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub peers: Vec<Vec<u8>>,
    /// Число клиентов, округлённое вниз до 5 (§16.2).
    #[prost(uint32, tag = "3")]
    pub clients_online: u32,
    /// Нагрузка 0..=10.
    #[prost(uint32, tag = "4")]
    pub load: u32,
    #[prost(uint64, tag = "5")]
    pub uptime_secs: u64,
    #[prost(uint64, tag = "6")]
    pub published_at_ms: u64,
    #[prost(bytes = "vec", tag = "15")]
    pub sig: Vec<u8>,
}

/// Нода представляется другой ноде: дескриптор + подпись хеша Noise-сессии ключом
/// идентичности (доказывает владение ключом именно в этом соединении).
#[derive(Clone, PartialEq, Message)]
pub struct PeerHello {
    #[prost(message, optional, tag = "1")]
    pub descriptor: Option<NodeDescriptor>,
    #[prost(bytes = "vec", tag = "2")]
    pub session_sig: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PeerWelcome {
    #[prost(message, optional, tag = "1")]
    pub descriptor: Option<NodeDescriptor>,
}

/// Сообщение gossip (из `идеи.md`): `msg_id` для дедупликации + TTL в хопах.
#[derive(Clone, PartialEq, Message)]
pub struct Gossip {
    #[prost(bytes = "vec", tag = "1")]
    pub msg_id: Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub ttl: u32,
    #[prost(oneof = "gossip::Payload", tags = "10, 11")]
    pub payload: Option<gossip::Payload>,
}

pub mod gossip {
    use super::*;

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Payload {
        #[prost(message, tag = "10")]
        Descriptor(NodeDescriptor),
        #[prost(message, tag = "11")]
        Stats(NodeStats),
    }
}

/// Снимок известной сети для клиента (карта сети, выбор нод). Постранично по `node_id`.
#[derive(Clone, PartialEq, Message)]
pub struct NetSnapshot {
    /// Пусто — с начала; иначе `next_cursor` из прошлого ответа.
    #[prost(bytes = "vec", tag = "1")]
    pub cursor: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
pub struct NetNode {
    #[prost(message, optional, tag = "1")]
    pub descriptor: Option<NodeDescriptor>,
    #[prost(message, optional, tag = "2")]
    pub stats: Option<NodeStats>,
}

#[derive(Clone, PartialEq, Message)]
pub struct NetSnapshotReply {
    #[prost(message, repeated, tag = "1")]
    pub nodes: Vec<NetNode>,
    /// Пусто — это последняя страница.
    #[prost(bytes = "vec", tag = "2")]
    pub next_cursor: Vec<u8>,
    /// node_id ноды, которая отвечает (клиент выделяет её на карте как «свою»).
    #[prost(bytes = "vec", tag = "3")]
    pub self_id: Vec<u8>,
}

/// Обновить свой статус (§15.2). Первый PUT закрепляет `presence_id` за `write_pk`.
/// Подпись: ключ `write_pk`.
#[derive(Clone, PartialEq, Message)]
pub struct PresencePut {
    #[prost(bytes = "vec", tag = "1")]
    pub presence_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub write_pk: Vec<u8>,
    /// Статус, зашифрованный ключом, который знают только допущенные (нода не читает).
    #[prost(bytes = "vec", tag = "3")]
    pub sealed: Vec<u8>,
    /// Через сколько секунд без нового PUT считать «не в сети». 0 — уйти офлайн сейчас.
    #[prost(uint32, tag = "4")]
    pub ttl_secs: u32,
}

/// Подписаться на статусы. Сразу приходит текущее состояние, затем изменения.
#[derive(Clone, PartialEq, Message)]
pub struct PresenceWatch {
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub presence_ids: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PresenceUpdate {
    #[prost(bytes = "vec", tag = "1")]
    pub presence_id: Vec<u8>,
    #[prost(bool, tag = "2")]
    pub online: bool,
    #[prost(bytes = "vec", tag = "3")]
    pub sealed: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub updated_at_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::MAX_BODY;

    #[test]
    fn signing_bytes_ignore_signature_and_bind_session() {
        let mut req = Request {
            corr_id: 7,
            auth_sig: vec![],
            body: Some(request::Body::QueueSub(QueueSub { recipient_id: vec![1; QUEUE_ID_LEN] })),
        };
        let unsigned = req.signing_bytes(b"session-a");
        req.auth_sig = vec![9; SIGNATURE_LEN];
        assert_eq!(unsigned, req.signing_bytes(b"session-a"));
        assert_ne!(unsigned, req.signing_bytes(b"session-b"));
    }

    #[test]
    fn largest_messages_fit_in_frame() {
        let u = u64::MAX;
        let entry = LogEntry {
            offset: u,
            kind: EntryKind::Commit as i32,
            epoch: u,
            received_at_ms: u,
            blob: vec![0; MAX_BLOB],
        };

        let resp = Response {
            corr_id: u,
            body: Some(response::Body::LogEntries(LogEntries { entries: vec![entry.clone()], next_offset: u })),
        };
        assert!(resp.encoded_len() <= MAX_BODY);

        let resp = Response {
            corr_id: u,
            body: Some(response::Body::CommitConflict(CommitConflict { winner: Some(entry.clone()) })),
        };
        assert!(resp.encoded_len() <= MAX_BODY);

        let ev =
            Event { body: Some(event::Body::LogEvent(LogEvent { log_id: vec![0; LOG_ID_LEN], entry: Some(entry) })) };
        assert!(ev.encoded_len() <= MAX_BODY);

        let ev = Event {
            body: Some(event::Body::QueueMessage(QueueMessage {
                recipient_id: vec![0; QUEUE_ID_LEN],
                msg_id: vec![0; MSG_ID_LEN],
                received_at_ms: u,
                body: vec![0; MAX_BLOB],
            })),
        };
        assert!(ev.encoded_len() <= MAX_BODY);

        let req = Request {
            corr_id: u,
            auth_sig: vec![0; SIGNATURE_LEN],
            body: Some(request::Body::LogCommit(LogCommit {
                log_id: vec![0; LOG_ID_LEN],
                epoch: u,
                blob: vec![0; MAX_BLOB],
            })),
        };
        assert!(req.encoded_len() <= MAX_BODY);
    }
}
