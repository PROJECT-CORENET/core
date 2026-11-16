//! Вложения: файл шифруется ChaCha20-Poly1305 кусками и кладётся в отдельный журнал на ноде.
//! Ключи журнала и расшифровки уходят получателям только внутри MLS-сообщения.

use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use core_crypto::{random_bytes, Ed25519Key};
use core_net::Client as NetClient;
use core_proto::msg::{request, response, LogAppend, LogNew, LogRead};
use tokio::task::JoinSet;

use crate::{expect_done, refused, AttachmentRef, Error, Result};

/// Открытый текст куска: блоб журнала = 4 байта номера + шифротекст (+16 байт тега) — с запасом до MAX_BLOB.
const CHUNK: usize = 14 * 1024;
const IN_FLIGHT: usize = 24;
pub const MAX_FILE: u64 = 100 * 1024 * 1024;
/// Файлы до этого размера скачиваются сами, как в Telegram.
pub const AUTO_DOWNLOAD: u64 = 25 * 1024 * 1024;

fn nonce(index: u32) -> Nonce {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&index.to_le_bytes());
    *Nonce::from_slice(&n)
}

fn io(e: std::io::Error) -> Error {
    Error::Other(format!("file: {e}"))
}

pub async fn upload(conn: &Arc<NetClient>, node: &str, path: &Path, att: &mut AttachmentRef) -> Result<()> {
    let key: [u8; 32] = random_bytes();
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

    let cipher = ChaCha20Poly1305::new((&key).into());
    let write = Arc::new(write);
    let mut file = std::fs::File::open(path).map_err(io)?;
    let mut tasks = JoinSet::new();
    let mut index = 0u32;
    loop {
        let mut buf = vec![0u8; CHUNK];
        let mut filled = 0;
        while filled < CHUNK {
            let n = file.read(&mut buf[filled..]).map_err(io)?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 && index > 0 {
            break;
        }
        buf.truncate(filled);
        let mut blob = index.to_le_bytes().to_vec();
        blob.extend(cipher.encrypt(&nonce(index), buf.as_slice()).expect("encrypt"));

        if tasks.len() >= IN_FLIGHT {
            tasks.join_next().await.unwrap().map_err(|e| Error::Other(e.to_string()))??;
        }
        let (conn, write, log_id) = (conn.clone(), write.clone(), log_id.clone());
        tasks.spawn(async move {
            match conn.request(request::Body::LogAppend(LogAppend { log_id, blob }), Some(&write)).await? {
                response::Body::LogAppended(_) => Ok(()),
                other => Err(refused(other)),
            }
        });
        index += 1;
        if filled < CHUNK {
            break;
        }
    }
    while let Some(r) = tasks.join_next().await {
        r.map_err(|e| Error::Other(e.to_string()))??;
    }

    att.node = node.to_string();
    att.log = log_id;
    att.rk = read.to_bytes().to_vec();
    att.key = key.to_vec();
    att.chunks = index;
    Ok(())
}

pub async fn download(conn: &Arc<NetClient>, att: &AttachmentRef, dest: &Path) -> Result<()> {
    let key: [u8; 32] = att.key.as_slice().try_into().map_err(|_| Error::Other("bad attachment key".into()))?;
    let read = Arc::new(Ed25519Key::from_bytes(
        att.rk.as_slice().try_into().map_err(|_| Error::Other("bad attachment key".into()))?,
    ));
    let cipher = ChaCha20Poly1305::new((&key).into());
    let mut parts: Vec<Option<Vec<u8>>> = vec![None; att.chunks as usize];

    // Куски могли лечь в журнал не по порядку (выгрузка параллельная) — номер берём из заголовка.
    let mut tasks = JoinSet::new();
    let mut offset = 0u64;
    let mut got = 0usize;
    while got < parts.len() {
        while tasks.len() < IN_FLIGHT && (offset as usize) < parts.len() {
            let (conn, read, log_id) = (conn.clone(), read.clone(), att.log.clone());
            let from = offset;
            tasks.spawn(async move {
                match conn
                    .request(request::Body::LogRead(LogRead { log_id, from_offset: from, limit: 1 }), Some(&read))
                    .await?
                {
                    response::Body::LogEntries(e) => Ok(e.entries),
                    other => Err(refused(other)),
                }
            });
            offset += 1;
        }
        let Some(r) = tasks.join_next().await else { break };
        for entry in r.map_err(|e| Error::Other(e.to_string()))?? {
            if entry.blob.len() < 4 {
                continue;
            }
            let index = u32::from_le_bytes(entry.blob[..4].try_into().unwrap());
            let plain = cipher
                .decrypt(&nonce(index), &entry.blob[4..])
                .map_err(|_| Error::Other("attachment chunk is corrupted".into()))?;
            if let Some(slot) = parts.get_mut(index as usize) {
                if slot.is_none() {
                    *slot = Some(plain);
                    got += 1;
                }
            }
        }
        if tasks.is_empty() && (offset as usize) >= parts.len() && got < parts.len() {
            return Err(Error::Other("attachment is incomplete on the node".into()));
        }
    }

    let tmp = dest.with_extension("part");
    let mut f = std::fs::File::create(&tmp).map_err(io)?;
    for part in parts.into_iter().flatten() {
        f.write_all(&part).map_err(io)?;
    }
    f.sync_all().map_err(io)?;
    std::fs::rename(&tmp, dest).map_err(io)?;
    Ok(())
}
