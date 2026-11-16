//! Wire protocol CORE (АРХИТЕКТУРА.md §23).
//!
//! - [`frame`] — кадры фиксированного размера 16 KiB (наблюдатель не видит длину сообщений).
//! - [`msg`] — команды клиент ↔ нода, ответы и события (protobuf через prost-derive).

pub mod frame;
pub mod msg;

/// Текущая версия протокола, пишется в каждый кадр.
pub const PROTOCOL_VERSION: u8 = 1;
