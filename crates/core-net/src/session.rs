//! Noise-сессия поверх TCP.
//!
//! Шаблон `Noise_NK`: клиент знает статический ключ ноды (из адреса/каталога) и сам
//! остаётся анонимным — у него нет статического ключа. Одно RTT на рукопожатие.
//!
//! На проводе: `u16 length (BE) || noise-сообщение`. После рукопожатия каждое
//! noise-сообщение — зашифрованный кадр ровно `FRAME_SIZE` байт (в медиа-соединении
//! звонков — `MEDIA_FRAME_SIZE`). Режим клиент сообщает в первом сообщении рукопожатия
//! (оно зашифровано): пусто — обычный, `[1]` — медиа.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use core_proto::frame::{self, FrameType, FRAME_SIZE, MEDIA_FRAME_SIZE};
use snow::{Builder, HandshakeState, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::{NetError, NodeAddr};

pub const NOISE_PARAMS: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";
const NOISE_MAX_MSG: usize = 65535;
const NOISE_TAG: usize = 16;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Режим соединения: обычный (16 КБ кадры) или медиа (звонки, мелкие кадры).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Media,
}

impl Mode {
    pub fn frame_size(self) -> usize {
        match self {
            Mode::Normal => FRAME_SIZE,
            Mode::Media => MEDIA_FRAME_SIZE,
        }
    }

    fn payload(self) -> &'static [u8] {
        match self {
            Mode::Normal => &[],
            Mode::Media => &[1],
        }
    }

    fn from_payload(p: &[u8]) -> Result<Self, NetError> {
        match p {
            [] => Ok(Mode::Normal),
            [1] => Ok(Mode::Media),
            _ => Err(NetError::Protocol("unknown session mode".into())),
        }
    }
}

pub struct Session {
    pub reader: NoiseReader,
    pub writer: NoiseWriter,
    /// Хеш рукопожатия — уникален для сессии, к нему привязываются подписи команд.
    pub handshake_hash: Vec<u8>,
    pub mode: Mode,
}

pub struct NoiseReader {
    inner: OwnedReadHalf,
    transport: Arc<Mutex<TransportState>>,
    frame_size: usize,
}

pub struct NoiseWriter {
    inner: OwnedWriteHalf,
    transport: Arc<Mutex<TransportState>>,
    frame_size: usize,
}

impl NoiseReader {
    pub async fn recv(&mut self) -> Result<(FrameType, Vec<u8>), NetError> {
        let ciphertext = read_raw(&mut self.inner).await?;
        if ciphertext.len() != self.frame_size + NOISE_TAG {
            return Err(NetError::Protocol(format!("invalid ciphertext length: {}", ciphertext.len())));
        }
        let mut plain = vec![0u8; ciphertext.len()];
        let n = self.transport.lock().unwrap().read_message(&ciphertext, &mut plain)?;
        let (ty, body) = frame::decode_sized(&plain[..n], self.frame_size)?;
        Ok((ty, body.to_vec()))
    }
}

impl NoiseWriter {
    pub async fn send(&mut self, ty: FrameType, body: &[u8]) -> Result<(), NetError> {
        let plain = frame::encode_sized(ty, body, self.frame_size)?;
        let mut ciphertext = vec![0u8; self.frame_size + NOISE_TAG];
        let n = self.transport.lock().unwrap().write_message(&plain, &mut ciphertext)?;
        write_raw(&mut self.inner, &ciphertext[..n]).await
    }
}

/// Подключиться к ноде как клиент.
pub async fn connect(addr: &NodeAddr) -> Result<Session, NetError> {
    connect_mode(addr, Mode::Normal).await
}

/// Подключиться в заданном режиме (медиа — для звонков).
pub async fn connect_mode(addr: &NodeAddr, mode: Mode) -> Result<Session, NetError> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr.host)).await.map_err(|_| NetError::Timeout)??;
    stream.set_nodelay(true)?;
    timeout(HANDSHAKE_TIMEOUT, initiator(stream, &addr.public_key, mode)).await.map_err(|_| NetError::Timeout)?
}

/// Принять входящее соединение на стороне ноды.
pub async fn accept(stream: TcpStream, static_private: &[u8; 32]) -> Result<Session, NetError> {
    stream.set_nodelay(true)?;
    timeout(HANDSHAKE_TIMEOUT, responder(stream, static_private)).await.map_err(|_| NetError::Timeout)?
}

async fn initiator(mut stream: TcpStream, server_public: &[u8; 32], mode: Mode) -> Result<Session, NetError> {
    let mut hs = Builder::new(NOISE_PARAMS.parse()?).remote_public_key(server_public).build_initiator()?;
    let mut buf = vec![0u8; NOISE_MAX_MSG];
    let n = hs.write_message(mode.payload(), &mut buf)?; // -> e, es (+ режим, зашифрован)
    write_raw(&mut stream, &buf[..n]).await?;
    let msg = read_raw(&mut stream).await?; // <- e, ee
    hs.read_message(&msg, &mut buf)?;
    finish(stream, hs, mode)
}

async fn responder(mut stream: TcpStream, static_private: &[u8; 32]) -> Result<Session, NetError> {
    let mut hs = Builder::new(NOISE_PARAMS.parse()?).local_private_key(static_private).build_responder()?;
    let mut buf = vec![0u8; NOISE_MAX_MSG];
    let msg = read_raw(&mut stream).await?;
    let len = hs.read_message(&msg, &mut buf)?;
    let mode = Mode::from_payload(&buf[..len])?;
    let n = hs.write_message(&[], &mut buf)?;
    write_raw(&mut stream, &buf[..n]).await?;
    finish(stream, hs, mode)
}

fn finish(stream: TcpStream, hs: HandshakeState, mode: Mode) -> Result<Session, NetError> {
    let handshake_hash = hs.get_handshake_hash().to_vec();
    let transport = Arc::new(Mutex::new(hs.into_transport_mode()?));
    let (r, w) = stream.into_split();
    let frame_size = mode.frame_size();
    Ok(Session {
        reader: NoiseReader { inner: r, transport: transport.clone(), frame_size },
        writer: NoiseWriter { inner: w, transport, frame_size },
        handshake_hash,
        mode,
    })
}

async fn write_raw(w: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<(), NetError> {
    let mut out = Vec::with_capacity(2 + data.len());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    w.write_all(&out).await?;
    Ok(())
}

async fn read_raw(r: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, NetError> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(NetError::Closed),
        Err(e) => return Err(e.into()),
    }
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    match r.read_exact(&mut buf).await {
        Ok(_) => Ok(buf),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Err(NetError::Closed),
        Err(e) => Err(e.into()),
    }
}
