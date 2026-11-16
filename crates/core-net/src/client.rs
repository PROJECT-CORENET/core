//! Клиент ноды: запрос/ответ по `corr_id` + поток событий подписок.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use core_crypto::Ed25519Key;
use core_proto::frame::FrameType;
use core_proto::msg::{request, response, ErrorCode, Event, Request, Response};
use prost::Message;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::{session, NetError, NodeAddr};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const EVENT_QUEUE: usize = 1024;

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Response>>>>;

pub struct Client {
    writer: tokio::sync::Mutex<session::NoiseWriter>,
    pending: Pending,
    next_id: AtomicU64,
    session_hash: Vec<u8>,
    reader_task: JoinHandle<()>,
}

impl Client {
    /// Подключиться к ноде. Возвращает клиента и поток событий (сообщения очередей, записи журналов).
    pub async fn connect(addr: &NodeAddr) -> Result<(Self, mpsc::Receiver<Event>), NetError> {
        let session = session::connect(addr).await?;
        let pending: Pending = Arc::default();
        let (events_tx, events_rx) = mpsc::channel(EVENT_QUEUE);
        let reader_task = tokio::spawn(read_loop(session.reader, pending.clone(), events_tx));
        let client = Self {
            writer: tokio::sync::Mutex::new(session.writer),
            pending,
            next_id: AtomicU64::new(1),
            session_hash: session.handshake_hash,
            reader_task,
        };
        Ok((client, events_rx))
    }

    pub fn session_hash(&self) -> &[u8] {
        &self.session_hash
    }

    /// Отправить команду; если передан `auth` — подписать её этим ключом.
    pub async fn request(&self, body: request::Body, auth: Option<&Ed25519Key>) -> Result<response::Body, NetError> {
        let mut req = Request { corr_id: self.next_corr_id(), auth_sig: vec![], body: Some(body) };
        if let Some(key) = auth {
            req.auth_sig = key.sign(&req.signing_bytes(&self.session_hash)).to_vec();
        }
        self.send_request(req).await
    }

    /// Отправить уже собранный запрос как есть (для тестов и нестандартной подписи).
    pub async fn send_request(&self, mut req: Request) -> Result<response::Body, NetError> {
        if req.corr_id == 0 {
            req.corr_id = self.next_corr_id();
        }
        let corr_id = req.corr_id;
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(corr_id, tx);

        let sent = self.writer.lock().await.send(FrameType::Request, &req.encode_to_vec()).await;
        if let Err(e) = sent {
            self.pending.lock().unwrap().remove(&corr_id);
            return Err(e);
        }

        let resp = match timeout(REQUEST_TIMEOUT, rx).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(_)) => return Err(NetError::Closed),
            Err(_) => {
                self.pending.lock().unwrap().remove(&corr_id);
                return Err(NetError::Timeout);
            }
        };
        match resp.body {
            Some(response::Body::Error(e)) => Err(NetError::Node {
                code: ErrorCode::try_from(e.code).unwrap_or(ErrorCode::Unspecified),
                message: e.message,
            }),
            Some(body) => Ok(body),
            None => Err(NetError::Protocol("empty response".into())),
        }
    }

    fn next_corr_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

async fn read_loop(mut reader: session::NoiseReader, pending: Pending, events: mpsc::Sender<Event>) {
    while let Ok((ty, body)) = reader.recv().await {
        match ty {
            FrameType::Response => {
                let Ok(resp) = Response::decode(&*body) else { break };
                if let Some(tx) = pending.lock().unwrap().remove(&resp.corr_id) {
                    let _ = tx.send(resp);
                }
            }
            FrameType::Event => {
                let Ok(ev) = Event::decode(&*body) else { break };
                // Получатель событий мог быть закрыт — тогда просто не доставляем.
                let _ = events.send(ev).await;
            }
            FrameType::Request => break,
        }
    }
    // Ожидающие запросы получат NetError::Closed.
    pending.lock().unwrap().clear();
}
