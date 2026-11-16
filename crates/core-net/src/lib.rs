//! Сетевой слой CORE.
//!
//! - [`addr`] — адрес ноды `core://<x25519_pk>@host:port`.
//! - [`session`] — Noise_NK поверх TCP + кадры фиксированного размера.
//! - [`client`] — клиент: запрос/ответ по `corr_id` + поток событий.

pub mod addr;
pub mod client;
pub mod session;

pub use addr::NodeAddr;
pub use client::Client;
pub use session::{accept, connect, NoiseReader, NoiseWriter, Session};

use core_proto::frame::FrameError;
use core_proto::msg::ErrorCode;

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("frame: {0}")]
    Frame(#[from] FrameError),
    #[error("protobuf: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("timeout")]
    Timeout,
    #[error("connection closed")]
    Closed,
    #[error("invalid node address: {0}")]
    BadAddress(String),
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error("node error {code:?}: {message}")]
    Node { code: ErrorCode, message: String },
}

impl NetError {
    /// Код ошибки ноды, если это ответ ноды.
    pub fn node_code(&self) -> Option<ErrorCode> {
        match self {
            NetError::Node { code, .. } => Some(*code),
            _ => None,
        }
    }
}
