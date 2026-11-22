//! Звонки: личные и групповые, голос и видео.
//!
//! - **Сигналинг** — `Payload::Call` в журнале чата (MLS): вызов, ответ, отказ, выход. Подлинность и
//!   шифрование как у сообщений; история звонков одинакова на всех устройствах аккаунта.
//! - **Медиа** — комната на ноде чата (отдельное медиа-соединение с мелкими кадрами одного размера).
//!   Нода пересылает кадры остальным участникам и не видит содержимого: каждый кадр зашифрован
//!   ChaCha20-Poly1305 ключом звонка, который пришёл в вызове внутри MLS.
//! - **Кодеки** — в приложении (Opus / H.264 средствами системы); ядро режет видео на части,
//!   собирает обратно, шифрует, отбрасывает повторы и следит, кто в звонке.
//!
//! Кадр на проводе: `tag(4) || counter(8) || AEAD(plain)`, nonce = tag || counter, AAD = id комнаты.
//! `tag` — случайный номер участника на время звонка (у двух своих устройств — разные).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit, Payload as Aad};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use core_crypto::random_bytes;
use core_net::{Client as NetClient, NetError, NodeAddr};
use core_proto::msg::{event, request, RelayJoin, RelayLeave, RelaySend};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::payload::{CallOp, Payload};
use crate::store::{CallRow, ChatRow, ChatState};
use crate::{new_id, now_ms, Client, Error, Inner, Result, REQUEST_TIMEOUT};

/// Сколько звонит вызов без ответа.
pub const RING_TIMEOUT_MS: u64 = 60_000;
/// Групповой звонок без событий дольше этого считается завершённым (все ушли не попрощавшись).
const GROUP_STALE_MS: u64 = 6 * 3600 * 1000;
const HEARTBEAT: Duration = Duration::from_secs(1);
/// Участник молчит (ни одного кадра) дольше — считаем, что он отключился.
const PEER_GONE: Duration = Duration::from_secs(6);
/// Личный звонок: собеседник пропал дольше — звонок завершается.
const PEER_LOST: Duration = Duration::from_secs(40);
/// Полезная нагрузка одного кадра ноды (медиа-кадр минус обёртки запроса).
const MAX_DATA: usize = 1150;
const SEAL_OVERHEAD: usize = 4 + 8 + 16;
const MAX_PLAIN: usize = MAX_DATA - SEAL_OVERHEAD;
const VIDEO_HEADER: usize = 8;
const VIDEO_CHUNK: usize = MAX_PLAIN - VIDEO_HEADER;
/// Самый большой кадр видео (частей не больше 255).
pub const MAX_VIDEO_FRAME: usize = VIDEO_CHUNK * 255;
const OUT_QUEUE: usize = 128;

/// Что приходит в приложение и уходит из него (`kind` у `call_media` / `call_send`).
pub mod media {
    /// Пакет звука (Opus).
    pub const AUDIO: u8 = 1;
    /// Кадр видео (H.264, Annex B / AVCC — как отдало приложение).
    pub const VIDEO: u8 = 2;
    /// Ключевой кадр видео.
    pub const VIDEO_KEY: u8 = 3;
    /// Собеседнику нужен ключевой кадр (потерялась часть видео).
    pub const KEYFRAME_REQUEST: u8 = 4;
}

// Тип кадра внутри шифра.
const K_HELLO: u8 = 0;
const K_AUDIO: u8 = 1;
const K_VIDEO: u8 = 2;
const K_KEYREQ: u8 = 3;

/// Звонок для приложения.
#[derive(Clone, Debug)]
pub struct Call {
    pub id: String,
    pub chat_id: String,
    pub initiator: String,
    pub outgoing: bool,
    pub video: bool,
    pub group: bool,
    pub ts: u64,
    pub joined_ms: Option<u64>,
    pub ended_ms: Option<u64>,
    /// ringing | outgoing | active | ongoing (групповой идёт без нас) | ended
    pub state: String,
    /// Для завершённых: answered | missed | declined (пусто, пока идёт).
    pub result: String,
    /// Кто в звонке по сигналингу.
    pub members: Vec<String>,
}

/// Участник звонка, от которого идут кадры.
#[derive(Clone, Debug)]
pub struct CallPeer {
    /// Номер участника в звонке (hex) — у двух устройств одного аккаунта разные.
    pub peer: String,
    pub member_id: String,
    pub mic: bool,
    pub cam: bool,
}

// ───────────────────────────── Состояние ─────────────────────────────

#[derive(Default)]
pub(crate) struct Calls {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    /// Вызовы, отклонённые на этом аккаунте (групповой звонок продолжается, но звонить перестаёт).
    dismissed: Mutex<HashSet<String>>,
}

pub(crate) struct Session {
    id: String,
    chat_id: String,
    direct: bool,
    initiator: bool,
    room: Vec<u8>,
    cipher: ChaCha20Poly1305,
    tag: [u8; 4],
    ctr: AtomicU64,
    out: mpsc::Sender<Vec<u8>>,
    conn: Mutex<Option<Arc<NetClient>>>,
    closed: AtomicBool,
    state: Mutex<SessionState>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

struct SessionState {
    mic: bool,
    cam: bool,
    video_frame: u32,
    peers: HashMap<[u8; 4], Peer>,
    /// Последний раз, когда кто-то был в звонке (личный звонок без собеседника завершается).
    last_peer: Instant,
    last_keyreq: Option<Instant>,
}

struct Peer {
    member: String,
    mic: bool,
    cam: bool,
    seen: Instant,
    replay: Replay,
    video: Option<Assembly>,
    /// Номер последнего собранного кадра видео (пропуск → просим ключевой).
    last_video: Option<u32>,
}

#[derive(Default)]
struct Replay {
    top: u64,
    bits: u64,
}

impl Replay {
    /// Окно 64 кадра: повтор и слишком старое — отбрасываем.
    fn accept(&mut self, n: u64) -> bool {
        if n > self.top {
            let shift = n - self.top;
            self.bits = if shift >= 64 { 0 } else { self.bits << shift };
            self.bits |= 1;
            self.top = n;
            return true;
        }
        let d = self.top - n;
        if d >= 64 || self.bits & (1 << d) != 0 {
            return false;
        }
        self.bits |= 1 << d;
        true
    }
}

struct Assembly {
    frame: u32,
    key: bool,
    parts: Vec<Option<Vec<u8>>>,
    have: usize,
}

impl Session {
    fn seal(&self, plain: &[u8]) -> Vec<u8> {
        let n = self.ctr.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.tag);
        nonce[4..].copy_from_slice(&n.to_be_bytes());
        let ct = self.cipher.encrypt(Nonce::from_slice(&nonce), Aad { msg: plain, aad: &self.room }).expect("encrypt");
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    fn open(&self, data: &[u8]) -> Option<([u8; 4], u64, Vec<u8>)> {
        if data.len() < SEAL_OVERHEAD {
            return None;
        }
        let tag: [u8; 4] = data[..4].try_into().unwrap();
        if tag == self.tag {
            return None;
        }
        let n = u64::from_be_bytes(data[4..12].try_into().unwrap());
        let plain =
            self.cipher.decrypt(Nonce::from_slice(&data[..12]), Aad { msg: &data[12..], aad: &self.room }).ok()?;
        Some((tag, n, plain))
    }

    /// В очередь на отправку; очередь полна — кадр теряется (живой звук важнее полного).
    fn push(&self, plain: &[u8]) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        let _ = self.out.try_send(self.seal(plain));
    }

    fn hello(&self, me: &str, left: bool) -> Vec<u8> {
        let st = self.state.lock().unwrap();
        let mut plain = vec![K_HELLO, st.mic as u8, st.cam as u8, left as u8];
        plain.extend_from_slice(me.as_bytes());
        plain
    }

    fn send_video(&self, data: &[u8], key: bool) {
        let chunks: Vec<&[u8]> = data.chunks(VIDEO_CHUNK).collect();
        if chunks.is_empty() || chunks.len() > 255 {
            warn!("⚠️ call video frame too large: {} bytes", data.len());
            return;
        }
        let frame = {
            let mut st = self.state.lock().unwrap();
            st.video_frame = st.video_frame.wrapping_add(1);
            st.video_frame
        };
        for (i, chunk) in chunks.iter().enumerate() {
            let mut plain = Vec::with_capacity(VIDEO_HEADER + chunk.len());
            plain.push(K_VIDEO);
            plain.extend_from_slice(&frame.to_be_bytes());
            plain.push(i as u8);
            plain.push(chunks.len() as u8);
            plain.push(key as u8);
            plain.extend_from_slice(chunk);
            self.push(&plain);
        }
    }
}

// ───────────────────────────── API ─────────────────────────────

impl Client {
    /// Позвонить в чат (личный — собеседнику, групповой — всем). Возвращает id звонка.
    pub async fn start_call(&self, chat_id: &str, video: bool) -> Result<String> {
        let inner = &self.inner;
        let chat = inner.store.chat(chat_id)?.ok_or(Error::NoChat)?;
        if chat.state != ChatState::Active || inner.saved_id().as_deref() == Some(chat_id) {
            return Err(Error::NotReady);
        }
        let row = CallRow {
            id: new_id(),
            chat_id: chat.id.clone(),
            initiator: inner.me.clone(),
            video,
            ts: now_ms(),
            room: random_bytes::<16>().to_vec(),
            key: random_bytes::<32>().to_vec(),
            joined_ms: None,
            ended_ms: None,
            result: String::new(),
            members: vec![inner.me.clone()],
        };
        inner.store.insert_call(&row)?;
        inner.store.update_call(&row)?;
        info!("📞 calling chat={} video={video} group={}", chat.id, inner.is_group(&chat));
        inner.join_session(&chat, &row);
        let op = CallOp::Ring { ts: row.ts, video, room: row.room.clone(), key: row.key.clone() };
        if let Err(e) = inner.send_payload(&chat, &Payload::Call { id: row.id.clone(), op }).await {
            warn!("❌ call ring failed: {e}");
            inner.stop_session(&row.id, None);
            inner.finish_call(&row.id, "missed")?;
            return Err(e);
        }
        Ok(row.id)
    }

    /// Ответить на вызов или присоединиться к идущему групповому звонку.
    pub async fn accept_call(&self, call_id: &str) -> Result<()> {
        let inner = &self.inner;
        let mut row = inner.store.call(call_id)?.ok_or(Error::NoChat)?;
        if !row.result.is_empty() {
            return Err(Error::Other("call has ended".into()));
        }
        let chat = inner.store.chat(&row.chat_id)?.ok_or(Error::NoChat)?;
        if row.joined_ms.is_none() && now_ms().saturating_sub(row.ts) >= RING_TIMEOUT_MS {
            return Err(Error::Other("call has ended".into()));
        }
        if !row.members.contains(&inner.me) {
            row.members.push(inner.me.clone());
        }
        row.joined_ms.get_or_insert(now_ms());
        inner.store.update_call(&row)?;
        inner.calls.dismissed.lock().unwrap().remove(call_id);
        info!("📞 joining call {call_id}");
        inner.join_session(&chat, &row);
        inner.send_call_op(&chat, call_id, CallOp::Accept { ts: now_ms() }).await
    }

    /// Отклонить входящий вызов (личный завершается, групповой просто перестаёт звонить).
    pub async fn decline_call(&self, call_id: &str) -> Result<()> {
        let inner = &self.inner;
        let row = inner.store.call(call_id)?.ok_or(Error::NoChat)?;
        let chat = inner.store.chat(&row.chat_id)?.ok_or(Error::NoChat)?;
        if inner.is_group(&chat) {
            inner.calls.dismissed.lock().unwrap().insert(call_id.to_string());
        } else if row.result.is_empty() {
            inner.finish_call(call_id, "declined")?;
        }
        inner.notify_call(call_id, &chat.id);
        inner.send_call_op(&chat, call_id, CallOp::Decline { ts: now_ms() }).await
    }

    /// Положить трубку: личный звонок завершается у всех, из группового — выходим.
    pub async fn end_call(&self, call_id: &str) -> Result<()> {
        let inner = &self.inner;
        let row = inner.store.call(call_id)?.ok_or(Error::NoChat)?;
        let chat = inner.store.chat(&row.chat_id)?.ok_or(Error::NoChat)?;
        inner.stop_session(call_id, Some(&chat));
        if inner.is_group(&chat) {
            inner.member_left(call_id, &inner.me)?;
            inner.notify_call(call_id, &chat.id);
            inner.send_call_op(&chat, call_id, CallOp::Leave { ts: now_ms() }).await
        } else {
            if row.result.is_empty() {
                inner.finish_call(call_id, if row.joined_ms.is_some() { "answered" } else { "missed" })?;
            }
            inner.notify_call(call_id, &chat.id);
            inner.send_call_op(&chat, call_id, CallOp::End { ts: now_ms() }).await
        }
    }

    /// Отправить кадр (`kind`: `media::AUDIO`, `VIDEO`, `VIDEO_KEY`, `KEYFRAME_REQUEST`). Без ожидания:
    /// не успевает уйти — теряется.
    pub fn call_send(&self, call_id: &str, kind: u8, data: &[u8]) {
        let Some(s) = self.inner.calls.sessions.lock().unwrap().get(call_id).cloned() else { return };
        match kind {
            media::AUDIO if data.len() < MAX_PLAIN => {
                let mut plain = Vec::with_capacity(1 + data.len());
                plain.push(K_AUDIO);
                plain.extend_from_slice(data);
                s.push(&plain);
            }
            media::VIDEO | media::VIDEO_KEY => s.send_video(data, kind == media::VIDEO_KEY),
            media::KEYFRAME_REQUEST => s.push(&[K_KEYREQ]),
            _ => warn!("⚠️ call frame dropped: kind={kind} len={}", data.len()),
        }
    }

    /// Микрофон и камера: остальные видят значки «выключен».
    pub fn set_call_media(&self, call_id: &str, mic: bool, cam: bool) {
        let Some(s) = self.inner.calls.sessions.lock().unwrap().get(call_id).cloned() else { return };
        {
            let mut st = s.state.lock().unwrap();
            st.mic = mic;
            st.cam = cam;
        }
        s.push(&s.hello(&self.inner.me, false));
    }

    pub fn call(&self, call_id: &str) -> Result<Call> {
        let row = self.inner.store.call(call_id)?.ok_or(Error::NoChat)?;
        Ok(self.inner.call_info(row))
    }

    /// История звонков, новые сверху.
    pub fn calls(&self, limit: u32) -> Result<Vec<Call>> {
        Ok(self.inner.store.calls(limit)?.into_iter().map(|r| self.inner.call_info(r)).collect())
    }

    /// Кто сейчас в звонке (по кадрам медиа).
    pub fn call_peers(&self, call_id: &str) -> Vec<CallPeer> {
        let Some(s) = self.inner.calls.sessions.lock().unwrap().get(call_id).cloned() else { return vec![] };
        let st = s.state.lock().unwrap();
        let mut peers: Vec<CallPeer> = st
            .peers
            .iter()
            .map(|(tag, p)| CallPeer { peer: hex::encode(tag), member_id: p.member.clone(), mic: p.mic, cam: p.cam })
            .collect();
        peers.sort_by(|a, b| a.peer.cmp(&b.peer));
        peers
    }

    /// Убрать звонки из истории на этом устройстве.
    pub fn hide_calls(&self, ids: &[String]) -> Result<()> {
        Ok(self.inner.store.hide_calls(ids)?)
    }
}

// ───────────────────────────── Внутри ─────────────────────────────

impl Inner {
    pub(crate) fn is_group(&self, chat: &ChatRow) -> bool {
        self.store.members(&chat.id).map(|m| m.iter().filter(|m| m.member_id != self.me).count() > 1).unwrap_or(false)
    }

    fn call_info(&self, row: CallRow) -> Call {
        let group = self.store.chat(&row.chat_id).ok().flatten().is_some_and(|c| self.is_group(&c));
        let now = now_ms();
        let in_call = self.calls.sessions.lock().unwrap().contains_key(&row.id);
        let outgoing = row.initiator == self.me;
        let dismissed = self.calls.dismissed.lock().unwrap().contains(&row.id);
        let state = if !row.result.is_empty() {
            "ended"
        } else if in_call {
            if group || row.joined_ms.is_some() {
                "active"
            } else {
                "outgoing"
            }
        } else if !outgoing
            && !dismissed
            && !row.members.contains(&self.me)
            && now.saturating_sub(row.ts) < RING_TIMEOUT_MS
        {
            "ringing"
        } else if group && !row.members.is_empty() && now.saturating_sub(row.ts) < GROUP_STALE_MS {
            "ongoing"
        } else {
            "ended"
        };
        // Звонок оборвался без сигнала конца (приложение закрыли): ответили — разговор, нет — пропущен.
        let result = match (state, row.result.as_str()) {
            ("ended", "") if row.joined_ms.is_some() => "answered".to_string(),
            ("ended", "") => "missed".to_string(),
            (_, r) => r.to_string(),
        };
        Call {
            id: row.id,
            chat_id: row.chat_id,
            initiator: row.initiator,
            outgoing,
            video: row.video,
            group,
            ts: row.ts,
            joined_ms: row.joined_ms,
            ended_ms: row.ended_ms,
            state: state.into(),
            result,
            members: row.members,
        }
    }

    fn notify_call(&self, call_id: &str, chat_id: &str) {
        if let Some(l) = self.listener.read().unwrap().clone() {
            l.call_changed(call_id.to_string());
            l.changed(Some(chat_id.to_string()));
        }
    }

    async fn send_call_op(self: &Arc<Self>, chat: &ChatRow, call_id: &str, op: CallOp) -> Result<()> {
        self.send_payload(chat, &Payload::Call { id: call_id.to_string(), op }).await.map(drop)
    }

    fn finish_call(&self, call_id: &str, result: &str) -> Result<()> {
        if let Some(mut row) = self.store.call(call_id)? {
            if row.result.is_empty() {
                row.result = result.into();
                row.ended_ms = Some(now_ms());
                row.members.clear();
                self.store.update_call(&row)?;
                info!("📴 call {call_id} ended: {result}");
            }
        }
        Ok(())
    }

    fn member_left(&self, call_id: &str, member: &str) -> Result<()> {
        if let Some(mut row) = self.store.call(call_id)? {
            row.members.retain(|m| m != member);
            self.store.update_call(&row)?;
            if row.members.is_empty() && row.result.is_empty() {
                self.finish_call(call_id, if row.joined_ms.is_some() { "answered" } else { "missed" })?;
            }
        }
        Ok(())
    }

    /// Сигналинг из журнала чата.
    pub(crate) fn apply_call(self: &Arc<Self>, chat: &ChatRow, sender: &str, id: String, op: CallOp) -> Result<()> {
        let group = self.is_group(chat);
        match op {
            CallOp::Ring { ts, video, room, key } => {
                if room.len() != 16 || key.len() != 32 {
                    return Ok(());
                }
                let row = CallRow {
                    id: id.clone(),
                    chat_id: chat.id.clone(),
                    initiator: sender.into(),
                    video,
                    ts,
                    room,
                    key,
                    joined_ms: None,
                    ended_ms: None,
                    result: String::new(),
                    members: vec![sender.into()],
                };
                if self.store.insert_call(&row)? {
                    self.store.update_call(&row)?;
                    if sender != self.me {
                        let remaining = RING_TIMEOUT_MS.saturating_sub(now_ms().saturating_sub(ts));
                        if remaining > 0 {
                            let inner = Arc::downgrade(self);
                            let call_id = id.clone();
                            self.rt.spawn(async move {
                                tokio::time::sleep(Duration::from_millis(remaining)).await;
                                if let Some(inner) = inner.upgrade() {
                                    if let Some(listener) = inner.listener.read().unwrap().clone() {
                                        listener.call_changed(call_id);
                                    }
                                }
                            });
                        }
                    }
                }
            }
            CallOp::Accept { ts } => {
                let Some(mut row) = self.store.call(&id)? else { return Ok(()) };
                if !row.result.is_empty() {
                    return Ok(());
                }
                if !row.members.iter().any(|m| m == sender) {
                    row.members.push(sender.into());
                }
                row.joined_ms.get_or_insert(ts.min(now_ms()));
                self.store.update_call(&row)?;
                if sender == self.me && !self.calls.sessions.lock().unwrap().contains_key(&id) {
                    debug!("📞 call {id} answered on another device");
                }
            }
            CallOp::Decline { .. } => {
                if group {
                    if sender == self.me {
                        self.calls.dismissed.lock().unwrap().insert(id.clone());
                    }
                } else {
                    self.finish_call(&id, "declined")?;
                    self.stop_session(&id, None);
                }
            }
            CallOp::Leave { .. } | CallOp::End { .. } if group => {
                self.member_left(&id, sender)?;
            }
            CallOp::Leave { .. } | CallOp::End { .. } => {
                let Some(row) = self.store.call(&id)? else { return Ok(()) };
                self.finish_call(&id, if row.joined_ms.is_some() { "answered" } else { "missed" })?;
                self.stop_session(&id, None);
            }
        }
        if let Some(l) = self.listener.read().unwrap().clone() {
            l.call_changed(id);
        }
        Ok(())
    }

    /// Войти в комнату звонка: медиа-соединение к ноде чата, кадры — через приложение.
    fn join_session(self: &Arc<Self>, chat: &ChatRow, row: &CallRow) {
        if self.calls.sessions.lock().unwrap().contains_key(&row.id) {
            return;
        }
        let (tx, rx) = mpsc::channel(OUT_QUEUE);
        let session = Arc::new(Session {
            id: row.id.clone(),
            chat_id: chat.id.clone(),
            direct: !self.is_group(chat),
            initiator: row.initiator == self.me,
            room: row.room.clone(),
            cipher: ChaCha20Poly1305::new_from_slice(&row.key).expect("32-byte key"),
            tag: random_bytes::<4>(),
            ctr: AtomicU64::new(1),
            out: tx,
            conn: Mutex::new(None),
            closed: AtomicBool::new(false),
            state: Mutex::new(SessionState {
                mic: true,
                cam: row.video,
                video_frame: 0,
                peers: HashMap::new(),
                last_peer: Instant::now(),
                last_keyreq: None,
            }),
            tasks: Mutex::default(),
        });
        self.calls.sessions.lock().unwrap().insert(row.id.clone(), session.clone());
        let weak = Arc::downgrade(self);
        let tasks = vec![
            self.rt.spawn(media_loop(weak.clone(), session.clone(), chat.node.clone())),
            self.rt.spawn(send_loop(session.clone(), rx)),
            self.rt.spawn(heartbeat_loop(weak, session.clone())),
        ];
        *session.tasks.lock().unwrap() = tasks;
        self.notify_call(&row.id, &chat.id);
    }

    fn stop_session(self: &Arc<Self>, call_id: &str, _chat: Option<&ChatRow>) {
        let Some(s) = self.calls.sessions.lock().unwrap().remove(call_id) else { return };
        // Попрощаться: остальные сразу убирают нас из звонка, не дожидаясь тишины.
        let bye = s.seal(&s.hello(&self.me, true));
        s.closed.store(true, Ordering::Relaxed);
        let conn = s.conn.lock().unwrap().take();
        for t in s.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
        if let Some(conn) = conn {
            let room = s.room.clone();
            self.rt.spawn(async move {
                let _ =
                    conn.send_oneway(request::Body::RelaySend(RelaySend { room_id: room.clone(), data: bye })).await;
                let _ = conn.send_oneway(request::Body::RelayLeave(RelayLeave { room_id: room })).await;
            });
        }
        info!("📴 left call room {call_id}");
        self.notify_call(call_id, &s.chat_id);
    }

    fn on_frame(&self, s: &Session, data: &[u8]) {
        let Some((tag, n, plain)) = s.open(data) else { return };
        let Some((&kind, body)) = plain.split_first() else { return };
        let listener = self.listener.read().unwrap().clone();
        let peer_hex = hex::encode(tag);
        let mut changed = false;
        let mut deliver: Vec<(u8, Vec<u8>)> = vec![];
        let mut want_key = false;
        {
            let mut st = s.state.lock().unwrap();
            let fresh = !st.peers.contains_key(&tag);
            let peer = st.peers.entry(tag).or_insert_with(|| Peer {
                member: String::new(),
                mic: true,
                cam: false,
                seen: Instant::now(),
                replay: Replay::default(),
                video: None,
                last_video: None,
            });
            if !peer.replay.accept(n) {
                return;
            }
            peer.seen = Instant::now();
            match kind {
                K_HELLO if body.len() >= 3 => {
                    let (mic, cam, left) = (body[0] != 0, body[1] != 0, body[2] != 0);
                    let member = String::from_utf8_lossy(&body[3..]).into_owned();
                    if left {
                        st.peers.remove(&tag);
                        changed = true;
                    } else {
                        changed = fresh || peer.mic != mic || peer.cam != cam || peer.member != member;
                        peer.mic = mic;
                        peer.cam = cam;
                        peer.member = member;
                        if fresh {
                            info!("👥 call {} peer joined {peer_hex}", s.id);
                        }
                    }
                }
                K_AUDIO => deliver.push((media::AUDIO, body.to_vec())),
                K_VIDEO if body.len() > VIDEO_HEADER - 1 => {
                    let frame = u32::from_be_bytes(body[..4].try_into().unwrap());
                    let (idx, count, key) = (body[4] as usize, body[5] as usize, body[6] != 0);
                    let chunk = &body[7..];
                    if count == 0 || idx >= count {
                        return;
                    }
                    if peer.video.as_ref().is_none_or(|a| a.frame != frame) {
                        // Новый кадр, а прошлый не собрался — дальше декодер без ключевого не сможет.
                        if peer.video.as_ref().is_some_and(|a| a.have < a.parts.len() && frame > a.frame) {
                            want_key = true;
                        }
                        if peer.video.as_ref().is_some_and(|a| frame < a.frame) {
                            return;
                        }
                        peer.video = Some(Assembly { frame, key, parts: vec![None; count], have: 0 });
                    }
                    let a = peer.video.as_mut().unwrap();
                    if a.parts.len() == count && a.parts[idx].is_none() {
                        a.parts[idx] = Some(chunk.to_vec());
                        a.have += 1;
                    }
                    if a.have == a.parts.len() {
                        let a = peer.video.take().unwrap();
                        if peer.last_video.is_some_and(|l| a.frame > l.wrapping_add(1)) && !a.key {
                            want_key = true;
                        }
                        peer.last_video = Some(a.frame);
                        let data: Vec<u8> = a.parts.into_iter().flatten().flatten().collect();
                        deliver.push((if a.key { media::VIDEO_KEY } else { media::VIDEO }, data));
                    }
                }
                K_KEYREQ => deliver.push((media::KEYFRAME_REQUEST, vec![])),
                _ => {}
            }
            if !st.peers.is_empty() {
                st.last_peer = Instant::now();
            }
            if want_key {
                let now = Instant::now();
                if st.last_keyreq.is_some_and(|t| now.duration_since(t) < Duration::from_millis(500)) {
                    want_key = false;
                } else {
                    st.last_keyreq = Some(now);
                }
            }
        }
        if want_key {
            s.push(&[K_KEYREQ]);
        }
        if let Some(l) = listener {
            for (kind, data) in deliver {
                l.call_media(s.id.clone(), peer_hex.clone(), kind, data);
            }
            if changed {
                l.call_changed(s.id.clone());
            }
        }
    }
}

/// Медиа-соединение: вход в комнату, приём кадров; оборвалось — переподключаемся, пока звонок идёт.
async fn media_loop(inner: Weak<Inner>, s: Arc<Session>, node: String) {
    let Ok(addr) = node.parse::<NodeAddr>() else {
        warn!("❌ call: bad node address");
        return;
    };
    while !s.closed.load(Ordering::Relaxed) {
        let connected = tokio::time::timeout(REQUEST_TIMEOUT, NetClient::connect_media(&addr)).await;
        let (conn, mut events) = match connected {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                warn!("⚠️ call media connect failed: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            Err(_) => continue,
        };
        let conn = Arc::new(conn);
        let joined = conn.request(request::Body::RelayJoin(RelayJoin { room_id: s.room.clone() }), None).await;
        if let Err(e) = joined {
            warn!("⚠️ call room join failed: {e}");
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        info!("🎙️ call {} media connected", s.id);
        *s.conn.lock().unwrap() = Some(conn.clone());
        if let Some(inner) = inner.upgrade() {
            s.push(&s.hello(&inner.me, false));
        }
        while let Some(ev) = events.recv().await {
            let Some(event::Body::RelayFrame(f)) = ev.body else { continue };
            let Some(inner) = inner.upgrade() else { return };
            inner.on_frame(&s, &f.data);
        }
        *s.conn.lock().unwrap() = None;
        if !s.closed.load(Ordering::Relaxed) {
            warn!("⚠️ call {} media connection lost, reconnecting", s.id);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

async fn send_loop(s: Arc<Session>, mut rx: mpsc::Receiver<Vec<u8>>) {
    while let Some(data) = rx.recv().await {
        let conn = s.conn.lock().unwrap().clone();
        let Some(conn) = conn else { continue };
        let body = request::Body::RelaySend(RelaySend { room_id: s.room.clone(), data });
        if let Err(e) = conn.send_oneway(body).await {
            if !matches!(e, NetError::Closed) {
                debug!("call send failed: {e}");
            }
        }
    }
}

/// Раз в секунду: «я здесь» (+ микрофон/камера), уборка пропавших, тайм-ауты личного звонка.
async fn heartbeat_loop(inner: Weak<Inner>, s: Arc<Session>) {
    let mut tick = tokio::time::interval(HEARTBEAT);
    loop {
        tick.tick().await;
        let Some(inner) = inner.upgrade() else { return };
        s.push(&s.hello(&inner.me, false));
        let (gone, lost) = {
            let mut st = s.state.lock().unwrap();
            let before = st.peers.len();
            st.peers.retain(|_, p| p.seen.elapsed() < PEER_GONE);
            if !st.peers.is_empty() {
                st.last_peer = Instant::now();
            }
            (st.peers.len() != before, st.last_peer.elapsed() > PEER_LOST)
        };
        if gone {
            if let Some(l) = inner.listener.read().unwrap().clone() {
                l.call_changed(s.id.clone());
            }
        }
        let Ok(Some(row)) = inner.store.call(&s.id) else { continue };
        let unanswered = row.joined_ms.is_none() && now_ms().saturating_sub(row.ts) >= RING_TIMEOUT_MS;
        if (s.initiator && unanswered) || (s.direct && row.joined_ms.is_some() && lost) {
            info!("⏱️ call {} timed out (unanswered={unanswered})", s.id);
            let client = Client { inner: inner.clone() };
            let id = s.id.clone();
            inner.rt.spawn(async move {
                if let Err(e) = client.end_call(&id).await {
                    warn!("⚠️ call end failed: {e}");
                }
            });
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window() {
        let mut r = Replay::default();
        assert!(r.accept(1));
        assert!(!r.accept(1));
        assert!(r.accept(3));
        assert!(r.accept(2));
        assert!(!r.accept(2));
        assert!(r.accept(100));
        assert!(!r.accept(30));
        assert!(r.accept(99));
    }
}
