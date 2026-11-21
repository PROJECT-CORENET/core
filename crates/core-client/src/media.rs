//! Вложения: файл шифруется ChaCha20-Poly1305 кусками и кладётся в отдельный журнал на ноде.
//! Ключи журнала и расшифровки уходят получателям только внутри MLS-сообщения.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};

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

/// Ход передач по id сообщения (доля 0…1); запись живёт, пока передача идёт.
static TRANSFERS: LazyLock<Mutex<HashMap<String, f32>>> = LazyLock::new(Default::default);

/// Доля переданного для сообщения или `None`, если сейчас ничего не передаётся.
pub fn progress(message_id: &str) -> Option<f32> {
    TRANSFERS.lock().unwrap().get(message_id).copied()
}

/// Отмечает ход одной передачи; по завершении (в том числе с ошибкой) запись убирается.
struct Tracker(Option<String>);

impl Tracker {
    fn new(id: Option<&str>) -> Self {
        if let Some(id) = id {
            TRANSFERS.lock().unwrap().insert(id.to_string(), 0.0);
        }
        Self(id.map(str::to_string))
    }

    fn set(&self, done: u64, total: u64) {
        if let Some(id) = &self.0 {
            let share = (done as f32 / total.max(1) as f32).min(1.0);
            TRANSFERS.lock().unwrap().insert(id.clone(), share);
        }
    }
}

impl Drop for Tracker {
    fn drop(&mut self) {
        if let Some(id) = &self.0 {
            TRANSFERS.lock().unwrap().remove(id);
        }
    }
}

fn nonce(index: u32) -> Nonce {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&index.to_le_bytes());
    *Nonce::from_slice(&n)
}

fn io(e: std::io::Error) -> Error {
    Error::Other(format!("file: {e}"))
}

#[cfg(all(target_os = "ios", not(target_abi = "sim")))]
fn protect_cache_file(file: &std::fs::File) -> std::io::Result<()> {
    use std::ffi::c_int;
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    }
    // Darwin sys/fcntl.h, APFS Protection Class A (NSFileProtectionComplete).
    const SET_PROTECTION_CLASS: c_int = 64;
    const COMPLETE: c_int = 1;
    // SAFETY: descriptor belongs to the open File and the command expects an int.
    if unsafe { fcntl(file.as_raw_fd(), SET_PROTECTION_CLASS, COMPLETE) } == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(all(target_os = "ios", not(target_abi = "sim"))))]
fn protect_cache_file(_: &std::fs::File) -> std::io::Result<()> {
    Ok(())
}

/// `track` — id сообщения, под которым виден ход выгрузки (`progress`).
pub async fn upload(
    conn: &Arc<NetClient>,
    node: &str,
    path: &Path,
    att: &mut AttachmentRef,
    track: Option<&str>,
) -> Result<()> {
    let tracker = Tracker::new(track);
    let total = std::fs::metadata(path).map(|m| m.len().div_ceil(CHUNK as u64).max(1)).unwrap_or(1);
    let mut done = 0u64;
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
            done += 1;
            tracker.set(done, total);
        }
        let (conn, write, log_id) = (conn.clone(), write.clone(), log_id.clone());
        tasks.spawn(async move {
            match conn
                .request(request::Body::LogAppend(LogAppend { log_id, blob, ..Default::default() }), Some(&write))
                .await?
            {
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
        done += 1;
        tracker.set(done, total);
    }

    att.node = node.to_string();
    att.log = log_id;
    att.rk = read.to_bytes().to_vec();
    att.key = key.to_vec();
    att.chunks = index;
    Ok(())
}

/// Зафиксированный шифротекст хранится по смещению в журнале. Номер самого куска может отличаться.
fn checkpoint_path(dest: &Path, log: &[u8]) -> std::path::PathBuf {
    dest.with_extension(format!("download-{}", hex::encode(log)))
}

fn open_chunk(cipher: &ChaCha20Poly1305, att: &AttachmentRef, blob: &[u8]) -> Result<(usize, Vec<u8>)> {
    if !(20..=CHUNK + 20).contains(&blob.len()) {
        return Err(Error::Other("bad attachment chunk size".into()));
    }
    let index = u32::from_le_bytes(blob[..4].try_into().unwrap());
    if index >= att.chunks {
        return Err(Error::Other("bad attachment chunk number".into()));
    }
    let expected = (att.size - u64::from(index) * CHUNK as u64).min(CHUNK as u64);
    let plain =
        cipher.decrypt(&nonce(index), &blob[4..]).map_err(|_| Error::Other("attachment chunk is corrupted".into()))?;
    if plain.len() as u64 != expected {
        return Err(Error::Other("bad attachment chunk length".into()));
    }
    Ok((index as usize, plain))
}

fn restore_checkpoint(cipher: &ChaCha20Poly1305, att: &AttachmentRef, dir: &Path) -> (Vec<Option<u64>>, Vec<u64>) {
    let mut parts = vec![None; att.chunks as usize];
    let mut missing = Vec::new();
    for offset in 0..u64::from(att.chunks) {
        let path = dir.join(offset.to_string());
        let saved = std::fs::File::open(&path).and_then(|file| {
            let mut blob = Vec::new();
            file.take((CHUNK + 21) as u64).read_to_end(&mut blob)?;
            Ok(blob)
        });
        if let Ok(blob) = saved {
            if let Ok((index, _)) = open_chunk(cipher, att, &blob) {
                if parts[index].is_none() {
                    parts[index] = Some(offset);
                    continue;
                }
            }
            let _ = std::fs::remove_file(path);
        }
        missing.push(offset);
    }
    (parts, missing)
}

/// Докачивает только отсутствующие смещения журнала. Части на диске остаются в исходном шифротексте.
pub async fn download(conn: &Arc<NetClient>, att: &AttachmentRef, dest: &Path, track: Option<&str>) -> Result<()> {
    if att.log.len() != 32 || att.size > MAX_FILE || u64::from(att.chunks) != att.size.div_ceil(CHUNK as u64).max(1) {
        return Err(Error::Other("bad attachment metadata".into()));
    }
    let tracker = Tracker::new(track);
    let key: [u8; 32] = att.key.as_slice().try_into().map_err(|_| Error::Other("bad attachment key".into()))?;
    let read = Arc::new(Ed25519Key::from_bytes(
        att.rk.as_slice().try_into().map_err(|_| Error::Other("bad attachment key".into()))?,
    ));
    let cipher = ChaCha20Poly1305::new((&key).into());
    let checkpoint = checkpoint_path(dest, &att.log);
    std::fs::create_dir_all(&checkpoint).map_err(io)?;
    let (mut parts, missing) = restore_checkpoint(&cipher, att, &checkpoint);
    let mut got = parts.len() - missing.len();
    tracker.set(got as u64, parts.len() as u64);

    let mut offsets = missing.into_iter();
    let mut tasks = JoinSet::new();
    let mut failure = None;
    loop {
        while failure.is_none() && tasks.len() < IN_FLIGHT {
            let Some(from) = offsets.next() else { break };
            let (conn, read, log_id) = (conn.clone(), read.clone(), att.log.clone());
            tasks.spawn(async move {
                match conn
                    .request(request::Body::LogRead(LogRead { log_id, from_offset: from, limit: 1 }), Some(&read))
                    .await?
                {
                    response::Body::LogEntries(e) => e
                        .entries
                        .into_iter()
                        .find(|entry| entry.offset == from)
                        .ok_or_else(|| Error::Other("attachment is incomplete on the node".into())),
                    other => Err(refused(other)),
                }
            });
        }
        let Some(result) = tasks.join_next().await else { break };
        let entry = match result.map_err(|e| Error::Other(e.to_string())).and_then(|result| result) {
            Ok(entry) => entry,
            Err(error) => {
                failure.get_or_insert(error);
                // Сохраняем успешные ответы, которые уже были запрошены.
                continue;
            }
        };
        let (index, _) = open_chunk(&cipher, att, &entry.blob)?;
        if parts[index].is_some() {
            return Err(Error::Other("duplicate attachment chunk".into()));
        }
        let tmp = checkpoint.join("write.tmp");
        std::fs::write(&tmp, &entry.blob).map_err(io)?;
        std::fs::rename(&tmp, checkpoint.join(entry.offset.to_string())).map_err(io)?;
        parts[index] = Some(entry.offset);
        got += 1;
        tracker.set(got as u64, parts.len() as u64);
    }
    if let Some(error) = failure {
        return Err(error);
    }

    let tmp = dest.with_extension("part");
    let result = (|| {
        let mut file = std::fs::File::create(&tmp).map_err(io)?;
        protect_cache_file(&file).map_err(io)?;
        for offset in parts {
            let offset = offset.ok_or_else(|| Error::Other("attachment is incomplete on the node".into()))?;
            let blob = std::fs::read(checkpoint.join(offset.to_string())).map_err(io)?;
            let (_, plain) = open_chunk(&cipher, att, &blob)?;
            file.write_all(&plain).map_err(io)?;
        }
        file.sync_all().map_err(io)?;
        std::fs::rename(&tmp, dest).map_err(io)
    })();
    if result.is_ok() {
        let _ = std::fs::remove_dir_all(checkpoint);
    } else {
        let _ = std::fs::remove_file(tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_resumes_out_of_order_and_refetches_corrupt_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let cipher = ChaCha20Poly1305::new((&[5; 32]).into());
        let att = AttachmentRef { size: 2 * CHUNK as u64 + 3, chunks: 3, ..Default::default() };
        let pack = |index: u32, data: &[u8]| {
            let mut blob = index.to_le_bytes().to_vec();
            blob.extend(cipher.encrypt(&nonce(index), data).unwrap());
            blob
        };
        std::fs::write(dir.path().join("0"), pack(2, b"end")).unwrap();
        std::fs::write(dir.path().join("1"), b"broken").unwrap();
        let (parts, missing) = restore_checkpoint(&cipher, &att, dir.path());
        assert_eq!(parts, vec![None, None, Some(0)]);
        assert_eq!(missing, vec![1, 2]);
        std::fs::write(dir.path().join("1"), pack(0, &vec![1; CHUNK])).unwrap();
        std::fs::write(dir.path().join("2"), pack(1, &vec![2; CHUNK])).unwrap();
        let (parts, missing) = restore_checkpoint(&cipher, &att, dir.path());
        assert_eq!(parts, vec![Some(1), Some(2), Some(0)]);
        assert!(missing.is_empty());
    }
}
