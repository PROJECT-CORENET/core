//! Хранилище mailbox-ноды (SQLite).
//!
//! Нода хранит только шифротексты и ключи авторизации. Никаких IP, никаких связей
//! «кто кому пишет»: у очереди два несвязанных снаружи ID (получателя и отправителя).

use std::path::Path;
use std::sync::Mutex;

use core_crypto::random_bytes;
use core_proto::msg::{EntryKind, LogEntry, QueueMessage, MSG_ID_LEN, QUEUE_ID_LEN};
use rusqlite::{params, Connection, OptionalExtension, Transaction};

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS queues (
    recipient_id      BLOB PRIMARY KEY,
    sender_id         BLOB NOT NULL UNIQUE,
    recipient_auth_pk BLOB NOT NULL,
    sender_auth_pk    BLOB,
    created_ms        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS queue_messages (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id BLOB NOT NULL REFERENCES queues(recipient_id) ON DELETE CASCADE,
    msg_id       BLOB NOT NULL,
    received_ms  INTEGER NOT NULL,
    body         BLOB NOT NULL,
    UNIQUE (recipient_id, msg_id)
);
CREATE INDEX IF NOT EXISTS queue_messages_received ON queue_messages(received_ms);

CREATE TABLE IF NOT EXISTS logs (
    log_id         BLOB PRIMARY KEY,
    write_pk       BLOB NOT NULL,
    read_pk        BLOB NOT NULL,
    created_ms     INTEGER NOT NULL,
    last_append_ms INTEGER,
    next_pos       INTEGER NOT NULL DEFAULT 0,
    max_epoch      INTEGER
);

CREATE TABLE IF NOT EXISTS log_notifications (
    log_id BLOB NOT NULL REFERENCES logs(log_id) ON DELETE CASCADE,
    slot BLOB NOT NULL,
    alert BLOB NOT NULL,
    voip BLOB NOT NULL,
    expires INTEGER NOT NULL,
    PRIMARY KEY (log_id, slot)
);

CREATE TABLE IF NOT EXISTS log_entries (
    log_id      BLOB NOT NULL REFERENCES logs(log_id) ON DELETE CASCADE,
    pos         INTEGER NOT NULL,
    kind        INTEGER NOT NULL,
    epoch       INTEGER NOT NULL,
    received_ms INTEGER NOT NULL,
    blob        BLOB NOT NULL,
    PRIMARY KEY (log_id, pos)
);
CREATE INDEX IF NOT EXISTS log_entries_received ON log_entries(received_ms);

CREATE TABLE IF NOT EXISTS log_commits (
    log_id BLOB NOT NULL REFERENCES logs(log_id) ON DELETE CASCADE,
    epoch  INTEGER NOT NULL,
    pos    INTEGER NOT NULL,
    PRIMARY KEY (log_id, epoch)
);
"#;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    #[error("quota exceeded")]
    Quota,
    /// Коммит для этой эпохи уже принят — внутри победитель.
    #[error("commit conflict")]
    Conflict(Box<LogEntry>),
    #[error("stale epoch")]
    StaleEpoch,
}

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone)]
pub struct QueueAuth {
    pub recipient_auth_pk: Vec<u8>,
    pub sender_auth_pk: Option<Vec<u8>>,
}

/// `(recipient_id, sender_auth_pk)` — результат поиска очереди по `sender_id`.
pub type SenderLookup = (Vec<u8>, Option<Vec<u8>>);

#[derive(Debug, Clone)]
pub struct LogKeys {
    pub write_pk: Vec<u8>,
    pub read_pk: Vec<u8>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CleanupStats {
    pub queue_messages: usize,
    pub log_entries: usize,
    pub logs: usize,
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    // ───────────── Очереди ─────────────

    /// Создать очередь. Возвращает `(recipient_id, sender_id)`.
    pub fn queue_new(&self, recipient_auth_pk: &[u8], now: u64) -> Result<(Vec<u8>, Vec<u8>)> {
        let rid = random_bytes::<QUEUE_ID_LEN>().to_vec();
        let sid = random_bytes::<QUEUE_ID_LEN>().to_vec();
        self.conn.lock().unwrap().execute(
            "INSERT INTO queues (recipient_id, sender_id, recipient_auth_pk, created_ms) VALUES (?1, ?2, ?3, ?4)",
            params![rid, sid, recipient_auth_pk, now as i64],
        )?;
        Ok((rid, sid))
    }

    pub fn queue_auth(&self, recipient_id: &[u8]) -> Result<Option<QueueAuth>> {
        Ok(self
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT recipient_auth_pk, sender_auth_pk FROM queues WHERE recipient_id = ?1",
                [recipient_id],
                |r| Ok(QueueAuth { recipient_auth_pk: r.get(0)?, sender_auth_pk: r.get(1)? }),
            )
            .optional()?)
    }

    /// По `sender_id` → `(recipient_id, sender_auth_pk)`.
    pub fn queue_by_sender(&self, sender_id: &[u8]) -> Result<Option<SenderLookup>> {
        Ok(self
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT recipient_id, sender_auth_pk FROM queues WHERE sender_id = ?1", [sender_id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?)
    }

    /// Закрепить ключ отправителя — один раз.
    pub fn queue_secure(&self, recipient_id: &[u8], sender_auth_pk: &[u8]) -> Result<()> {
        let n = self.conn.lock().unwrap().execute(
            "UPDATE queues SET sender_auth_pk = ?2 WHERE recipient_id = ?1 AND sender_auth_pk IS NULL",
            params![recipient_id, sender_auth_pk],
        )?;
        match n {
            1 => Ok(()),
            _ if self.queue_auth(recipient_id)?.is_some() => Err(StoreError::AlreadyExists),
            _ => Err(StoreError::NotFound),
        }
    }

    /// Положить сообщение. Возвращает `(seq, сообщение)`.
    pub fn queue_push(
        &self,
        recipient_id: &[u8],
        body: &[u8],
        now: u64,
        max_messages: u32,
    ) -> Result<(i64, QueueMessage)> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let count: i64 =
            tx.query_row("SELECT COUNT(*) FROM queue_messages WHERE recipient_id = ?1", [recipient_id], |r| r.get(0))?;
        if count >= max_messages as i64 {
            return Err(StoreError::Quota);
        }
        let msg_id = random_bytes::<MSG_ID_LEN>().to_vec();
        tx.execute(
            "INSERT INTO queue_messages (recipient_id, msg_id, received_ms, body) VALUES (?1, ?2, ?3, ?4)",
            params![recipient_id, msg_id, now as i64, body],
        )?;
        let seq = tx.last_insert_rowid();
        tx.commit()?;
        Ok((
            seq,
            QueueMessage { recipient_id: recipient_id.to_vec(), msg_id, received_at_ms: now, body: body.to_vec() },
        ))
    }

    /// Недоставленные сообщения с `seq > after_seq`, по порядку.
    pub fn queue_pending(&self, recipient_id: &[u8], after_seq: i64, limit: u32) -> Result<Vec<(i64, QueueMessage)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT seq, msg_id, received_ms, body FROM queue_messages
             WHERE recipient_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![recipient_id, after_seq, limit], |r| {
            Ok((
                r.get(0)?,
                QueueMessage {
                    recipient_id: recipient_id.to_vec(),
                    msg_id: r.get(1)?,
                    received_at_ms: r.get::<_, i64>(2)? as u64,
                    body: r.get(3)?,
                },
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Удалить доставленное сообщение. `false` — такого не было.
    pub fn queue_ack(&self, recipient_id: &[u8], msg_id: &[u8]) -> Result<bool> {
        let n = self.conn.lock().unwrap().execute(
            "DELETE FROM queue_messages WHERE recipient_id = ?1 AND msg_id = ?2",
            params![recipient_id, msg_id],
        )?;
        Ok(n == 1)
    }

    pub fn queue_delete(&self, recipient_id: &[u8]) -> Result<()> {
        self.conn.lock().unwrap().execute("DELETE FROM queues WHERE recipient_id = ?1", [recipient_id])?;
        Ok(())
    }

    // ───────────── Журналы ─────────────

    pub fn log_new(&self, log_id: &[u8], write_pk: &[u8], read_pk: &[u8], now: u64) -> Result<()> {
        let n = self.conn.lock().unwrap().execute(
            "INSERT OR IGNORE INTO logs (log_id, write_pk, read_pk, created_ms) VALUES (?1, ?2, ?3, ?4)",
            params![log_id, write_pk, read_pk, now as i64],
        )?;
        if n == 0 {
            return Err(StoreError::AlreadyExists);
        }
        Ok(())
    }

    pub fn log_keys(&self, log_id: &[u8]) -> Result<Option<LogKeys>> {
        Ok(self
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT write_pk, read_pk FROM logs WHERE log_id = ?1", [log_id], |r| {
                Ok(LogKeys { write_pk: r.get(0)?, read_pk: r.get(1)? })
            })
            .optional()?)
    }

    pub fn notify_set(&self, route: &core_proto::msg::NotifySet, now: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM log_notifications WHERE log_id = ? AND expires <= ?",
            params![route.log_id, now as i64],
        )?;
        if route.alert.is_empty() && route.voip.is_empty() {
            conn.execute(
                "DELETE FROM log_notifications WHERE log_id = ? AND slot = ?",
                params![route.log_id, route.slot],
            )?;
            return Ok(());
        }
        let updated = conn.execute(
            "INSERT INTO log_notifications (log_id, slot, alert, voip, expires)
             SELECT ?1, ?2, ?3, ?4, ?5
             WHERE EXISTS (SELECT 1 FROM log_notifications WHERE log_id = ?1 AND slot = ?2)
                OR (SELECT COUNT(*) FROM log_notifications WHERE log_id = ?1) < 128
             ON CONFLICT(log_id, slot) DO UPDATE SET alert=excluded.alert, voip=excluded.voip, expires=excluded.expires",
             params![route.log_id, route.slot, route.alert, route.voip, now as i64 + 30 * 24 * 60 * 60 * 1000],
        )?;
        if updated == 0 {
            return Err(StoreError::Quota);
        }
        Ok(())
    }

    pub fn notify_targets(
        &self,
        log: &[u8],
        sender: &[u8],
        linked: &[Vec<u8>],
        voip: bool,
        now: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT CASE WHEN ?1 THEN voip ELSE alert END, slot FROM log_notifications WHERE log_id = ?2 AND slot != ?3 AND expires > ?4",
        )?;
        let targets = stmt
            .query_map(params![voip, log, sender, now as i64], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut seen = std::collections::HashSet::new();
        Ok(targets
            .into_iter()
            .filter_map(|(entry, slot)| {
                (!entry.is_empty() && !linked.contains(&slot) && seen.insert(entry.clone())).then_some(entry)
            })
            .collect())
    }

    pub fn log_append(&self, log_id: &[u8], blob: &[u8], now: u64) -> Result<LogEntry> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let entry = append_tx(&tx, log_id, EntryKind::Message, 0, blob, now)?;
        tx.commit()?;
        Ok(entry)
    }

    /// Compare-and-swap коммита MLS (§11.4): на эпоху принимается ровно один коммит,
    /// эпохи только растут.
    pub fn log_commit(&self, log_id: &[u8], epoch: u64, blob: &[u8], now: u64) -> Result<LogEntry> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let max_epoch: Option<i64> = tx
            .query_row("SELECT max_epoch FROM logs WHERE log_id = ?1", [log_id], |r| r.get(0))
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let existing: Option<i64> = tx
            .query_row(
                "SELECT pos FROM log_commits WHERE log_id = ?1 AND epoch = ?2",
                params![log_id, epoch as i64],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(pos) = existing {
            // Победитель мог быть удалён по TTL — тогда клиенту остаётся только «эпоха устарела».
            return match entry_at(&tx, log_id, pos)? {
                Some(winner) => Err(StoreError::Conflict(Box::new(winner))),
                None => Err(StoreError::StaleEpoch),
            };
        }
        if max_epoch.is_some_and(|m| epoch as i64 <= m) {
            return Err(StoreError::StaleEpoch);
        }
        let entry = append_tx(&tx, log_id, EntryKind::Commit, epoch, blob, now)?;
        tx.execute(
            "INSERT INTO log_commits (log_id, epoch, pos) VALUES (?1, ?2, ?3)",
            params![log_id, epoch as i64, entry.offset as i64],
        )?;
        tx.execute("UPDATE logs SET max_epoch = ?2 WHERE log_id = ?1", params![log_id, epoch as i64])?;
        tx.commit()?;
        Ok(entry)
    }

    /// Записи с `offset >= from` (часть могла быть удалена по TTL — тогда начинаем с самой ранней).
    pub fn log_read(&self, log_id: &[u8], from: u64, limit: u32) -> Result<Vec<LogEntry>> {
        let conn = self.conn.lock().unwrap();
        let exists: Option<i64> =
            conn.query_row("SELECT 1 FROM logs WHERE log_id = ?1", [log_id], |r| r.get(0)).optional()?;
        if exists.is_none() {
            return Err(StoreError::NotFound);
        }
        let mut stmt = conn.prepare_cached(
            "SELECT pos, kind, epoch, received_ms, blob FROM log_entries
             WHERE log_id = ?1 AND pos >= ?2 ORDER BY pos LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![log_id, from as i64, limit], row_to_entry)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    // ───────────── Обслуживание ─────────────

    /// Удалить всё, что старше TTL, и брошенные пустые журналы.
    pub fn cleanup(&self, now: u64, queue_ttl_ms: u64, log_ttl_ms: u64) -> Result<CleanupStats> {
        let queue_cutoff = now.saturating_sub(queue_ttl_ms) as i64;
        let log_cutoff = now.saturating_sub(log_ttl_ms) as i64;
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let stats = CleanupStats {
            queue_messages: tx.execute("DELETE FROM queue_messages WHERE received_ms < ?1", [queue_cutoff])?,
            log_entries: tx.execute("DELETE FROM log_entries WHERE received_ms < ?1", [log_cutoff])?,
            logs: tx.execute("DELETE FROM logs WHERE COALESCE(last_append_ms, created_ms) < ?1", [log_cutoff])?,
        };
        tx.commit()?;
        Ok(stats)
    }
}

fn append_tx(tx: &Transaction, log_id: &[u8], kind: EntryKind, epoch: u64, blob: &[u8], now: u64) -> Result<LogEntry> {
    let pos: i64 = tx
        .query_row("SELECT next_pos FROM logs WHERE log_id = ?1", [log_id], |r| r.get(0))
        .optional()?
        .ok_or(StoreError::NotFound)?;
    tx.execute(
        "INSERT INTO log_entries (log_id, pos, kind, epoch, received_ms, blob) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![log_id, pos, kind as i32, epoch as i64, now as i64, blob],
    )?;
    tx.execute(
        "UPDATE logs SET next_pos = next_pos + 1, last_append_ms = ?2 WHERE log_id = ?1",
        params![log_id, now as i64],
    )?;
    Ok(LogEntry { offset: pos as u64, kind: kind as i32, epoch, received_at_ms: now, blob: blob.to_vec() })
}

fn entry_at(conn: &Connection, log_id: &[u8], pos: i64) -> Result<Option<LogEntry>> {
    Ok(conn
        .query_row(
            "SELECT pos, kind, epoch, received_ms, blob FROM log_entries WHERE log_id = ?1 AND pos = ?2",
            params![log_id, pos],
            row_to_entry,
        )
        .optional()?)
}

fn row_to_entry(r: &rusqlite::Row) -> rusqlite::Result<LogEntry> {
    Ok(LogEntry {
        offset: r.get::<_, i64>(0)? as u64,
        kind: r.get(1)?,
        epoch: r.get::<_, i64>(2)? as u64,
        received_at_ms: r.get::<_, i64>(3)? as u64,
        blob: r.get(4)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PK: &[u8] = &[1; 32];

    #[test]
    fn log_push_routes_skip_sender_and_clear_independently() {
        use core_proto::msg::NotifySet;
        let s = Store::open_in_memory().unwrap();
        let log_id = vec![5; 32];
        s.log_new(&log_id, PK, PK, 1).unwrap();
        let mut sender =
            NotifySet { log_id: log_id.clone(), slot: vec![1; 16], alert: vec![11; 32], voip: vec![12; 32] };
        let mut receiver =
            NotifySet { log_id: log_id.clone(), slot: vec![2; 16], alert: vec![21; 32], voip: vec![22; 32] };
        s.notify_set(&sender, 1).unwrap();
        s.notify_set(&receiver, 1).unwrap();
        assert!(s
            .notify_targets(&log_id, &sender.slot, std::slice::from_ref(&receiver.slot), false, 2)
            .unwrap()
            .is_empty());
        assert_eq!(s.notify_targets(&log_id, &sender.slot, &[], false, 2).unwrap(), [receiver.alert.clone()]);
        assert_eq!(s.notify_targets(&log_id, &sender.slot, &[], true, 2).unwrap(), [receiver.voip.clone()]);
        receiver.alert.clear();
        receiver.voip.clear();
        s.notify_set(&receiver, 2).unwrap();
        assert!(s.notify_targets(&log_id, &sender.slot, &[], false, 3).unwrap().is_empty());
        assert_eq!(s.notify_targets(&log_id, &receiver.slot, &[], false, 3).unwrap(), [sender.alert.clone()]);
        sender.alert.clear();
        sender.voip.clear();
        s.notify_set(&sender, 3).unwrap();
        assert!(s.notify_targets(&log_id, &receiver.slot, &[], true, 4).unwrap().is_empty());
    }

    #[test]
    fn queue_lifecycle() {
        let s = Store::open_in_memory().unwrap();
        let (rid, sid) = s.queue_new(PK, 100).unwrap();
        assert_ne!(rid, sid);
        assert_eq!(s.queue_by_sender(&sid).unwrap().unwrap().0, rid);

        let (seq1, m1) = s.queue_push(&rid, b"a", 100, 10).unwrap();
        let (seq2, _) = s.queue_push(&rid, b"b", 101, 10).unwrap();
        assert!(seq2 > seq1);
        assert_eq!(s.queue_pending(&rid, 0, 10).unwrap().len(), 2);
        assert_eq!(s.queue_pending(&rid, seq1, 10).unwrap().len(), 1);

        assert!(s.queue_ack(&rid, &m1.msg_id).unwrap());
        assert!(!s.queue_ack(&rid, &m1.msg_id).unwrap());
        assert_eq!(s.queue_pending(&rid, 0, 10).unwrap().len(), 1);

        s.queue_secure(&rid, &[2; 32]).unwrap();
        assert!(matches!(s.queue_secure(&rid, &[3; 32]), Err(StoreError::AlreadyExists)));
        assert!(matches!(s.queue_secure(&[9; 24], &[3; 32]), Err(StoreError::NotFound)));

        s.queue_delete(&rid).unwrap();
        assert!(s.queue_auth(&rid).unwrap().is_none());
        assert!(s.queue_pending(&rid, 0, 10).unwrap().is_empty());
    }

    #[test]
    fn queue_quota() {
        let s = Store::open_in_memory().unwrap();
        let (rid, _) = s.queue_new(PK, 0).unwrap();
        s.queue_push(&rid, b"1", 0, 2).unwrap();
        s.queue_push(&rid, b"2", 0, 2).unwrap();
        assert!(matches!(s.queue_push(&rid, b"3", 0, 2), Err(StoreError::Quota)));
    }

    #[test]
    fn log_append_and_read() {
        let s = Store::open_in_memory().unwrap();
        let id = [7u8; 32];
        s.log_new(&id, PK, PK, 0).unwrap();
        assert!(matches!(s.log_new(&id, PK, PK, 0), Err(StoreError::AlreadyExists)));
        for i in 0..5u8 {
            assert_eq!(s.log_append(&id, &[i], 10).unwrap().offset, i as u64);
        }
        let entries = s.log_read(&id, 2, 2).unwrap();
        assert_eq!(entries.iter().map(|e| e.offset).collect::<Vec<_>>(), vec![2, 3]);
        assert!(matches!(s.log_read(&[0; 32], 0, 1), Err(StoreError::NotFound)));
        assert!(matches!(s.log_append(&[0; 32], b"x", 0), Err(StoreError::NotFound)));
    }

    #[test]
    fn log_commit_cas() {
        let s = Store::open_in_memory().unwrap();
        let id = [7u8; 32];
        s.log_new(&id, PK, PK, 0).unwrap();
        let first = s.log_commit(&id, 1, b"alice", 0).unwrap();
        assert_eq!(first.kind, EntryKind::Commit as i32);
        match s.log_commit(&id, 1, b"bob", 0) {
            Err(StoreError::Conflict(winner)) => assert_eq!(winner.blob, b"alice"),
            other => panic!("ожидался конфликт, получено {other:?}"),
        }
        s.log_commit(&id, 2, b"bob", 0).unwrap();
        // Пропущенная эпоха в прошлом — устарела.
        s.log_commit(&id, 5, b"x", 0).unwrap();
        assert!(matches!(s.log_commit(&id, 4, b"late", 0), Err(StoreError::StaleEpoch)));
    }

    #[test]
    fn cleanup_by_ttl() {
        let s = Store::open_in_memory().unwrap();
        let (rid, _) = s.queue_new(PK, 0).unwrap();
        s.queue_push(&rid, b"old", 100, 10).unwrap();
        s.queue_push(&rid, b"new", 1_000, 10).unwrap();

        let stale = [1u8; 32];
        let fresh = [2u8; 32];
        s.log_new(&stale, PK, PK, 100).unwrap();
        s.log_append(&stale, b"old", 100).unwrap();
        s.log_new(&fresh, PK, PK, 100).unwrap();
        s.log_append(&fresh, b"old", 100).unwrap();
        s.log_append(&fresh, b"new", 1_000).unwrap();

        let stats = s.cleanup(1_100, 500, 500).unwrap();
        assert_eq!(stats, CleanupStats { queue_messages: 1, log_entries: 2, logs: 1 });
        assert_eq!(s.queue_pending(&rid, 0, 10).unwrap().len(), 1);
        assert!(s.log_keys(&stale).unwrap().is_none());
        let left = s.log_read(&fresh, 0, 10).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].offset, 1);
    }
}
