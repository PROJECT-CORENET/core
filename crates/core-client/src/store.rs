//! Локальная база клиента (SQLite): аккаунт, чаты, участники, сообщения, состояние MLS.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::payload::{AttachmentRef, LinkPreview};

pub type Result<T> = std::result::Result<T, rusqlite::Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatState {
    /// Ждём Welcome от пригласившего.
    Joining = 0,
    Active = 1,
    /// Нас удалили из группы.
    Left = 2,
}

impl ChatState {
    fn from_i64(v: i64) -> Self {
        match v {
            0 => Self::Joining,
            2 => Self::Left,
            _ => Self::Active,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageStatus {
    Sending = 0,
    Sent = 1,
    Read = 2,
    Failed = 3,
    Received = 4,
    /// Дошло до устройства собеседника (отчёт о доставке), но ещё не прочитано.
    Delivered = 5,
}

impl MessageStatus {
    pub(crate) fn from_i64(v: i64) -> Self {
        match v {
            0 => Self::Sending,
            2 => Self::Read,
            3 => Self::Failed,
            4 => Self::Received,
            5 => Self::Delivered,
            _ => Self::Sent,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChatRow {
    pub id: String,
    pub group_id: Option<Vec<u8>>,
    pub title: String,
    pub custom_title: bool,
    pub node: String,
    pub log_id: Vec<u8>,
    pub write_sk: Vec<u8>,
    pub read_sk: Vec<u8>,
    pub read_offset: u64,
    pub state: ChatState,
    pub created_ms: u64,
    pub last_ms: u64,
    pub unread: u32,
    pub muted: bool,
    pub pinned: bool,
}

#[derive(Clone, Debug)]
pub struct MemberRow {
    pub member_id: String,
    pub name: String,
    pub avatar: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct MessageRow {
    pub id: String,
    pub chat_id: String,
    pub sender_id: String,
    pub outgoing: bool,
    pub ts: u64,
    pub text: String,
    pub attachment: Option<AttachmentRef>,
    pub status: MessageStatus,
    pub file_path: Option<String>,
    pub reply_to: Option<String>,
    pub link: Option<LinkPreview>,
    /// Пересланное: от кого.
    pub fwd: Option<String>,
    /// Ключ автора пересланного.
    pub fwd_id: Option<String>,
}

/// Резервный журнал чата на другой ноде: если нода чата пропадёт, переписка переезжает сюда.
#[derive(Clone, Debug, PartialEq)]
pub struct MirrorRow {
    pub node: String,
    pub log_id: Vec<u8>,
    pub write_sk: Vec<u8>,
    pub read_sk: Vec<u8>,
    pub read_offset: u64,
}

#[derive(Clone, Debug)]
pub struct QueueRow {
    pub chat_id: String,
    pub node: String,
    pub recipient_id: Vec<u8>,
    pub recipient_sk: Vec<u8>,
    pub sender_id: Vec<u8>,
}

pub struct Store {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = "
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS mls (k BLOB PRIMARY KEY, v BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS chats (
    id TEXT PRIMARY KEY, group_id BLOB, title TEXT NOT NULL, custom_title INTEGER NOT NULL DEFAULT 0,
    node TEXT NOT NULL, log_id BLOB NOT NULL, write_sk BLOB NOT NULL, read_sk BLOB NOT NULL,
    read_offset INTEGER NOT NULL DEFAULT 0, state INTEGER NOT NULL, created_ms INTEGER NOT NULL,
    last_ms INTEGER NOT NULL, unread INTEGER NOT NULL DEFAULT 0, muted INTEGER NOT NULL DEFAULT 0,
    pinned INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS members (
    chat_id TEXT NOT NULL, member_id TEXT NOT NULL, name TEXT NOT NULL, avatar BLOB,
    PRIMARY KEY (chat_id, member_id));
-- Очереди-приглашения (мы приглашаем) и очереди ответа (мы вступаем).
CREATE TABLE IF NOT EXISTS invites (
    chat_id TEXT PRIMARY KEY, node TEXT NOT NULL, recipient_id BLOB NOT NULL, recipient_sk BLOB NOT NULL,
    sender_id BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS joins (
    chat_id TEXT PRIMARY KEY, node TEXT NOT NULL, recipient_id BLOB NOT NULL, recipient_sk BLOB NOT NULL,
    sender_id BLOB NOT NULL);
-- Свои записи в журнале: MLS не расшифровывает собственные сообщения, их пропускаем.
CREATE TABLE IF NOT EXISTS own_offsets (chat_id TEXT NOT NULL, off INTEGER NOT NULL, PRIMARY KEY (chat_id, off));
CREATE TABLE IF NOT EXISTS messages (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE, chat_id TEXT NOT NULL,
    sender_id TEXT NOT NULL, outgoing INTEGER NOT NULL, ts INTEGER NOT NULL, text TEXT NOT NULL,
    attachment TEXT, status INTEGER NOT NULL, file_path TEXT, reply_to TEXT);
CREATE INDEX IF NOT EXISTS messages_chat ON messages (chat_id, seq);
-- Реакции: одна на участника, порядок эмодзи — по первой поставленной.
CREATE TABLE IF NOT EXISTS reactions (
    msg_id TEXT NOT NULL, sender_id TEXT NOT NULL, emoji TEXT NOT NULL, ts INTEGER NOT NULL,
    PRIMARY KEY (msg_id, sender_id));
-- Звонки (история): одинакова на всех устройствах — строится из сигналинга в журнале чата.
-- result: '' — идёт / звонит, answered, missed, declined, cancelled. members — кто сейчас в звонке (JSON).
CREATE TABLE IF NOT EXISTS calls (
    id TEXT PRIMARY KEY, chat_id TEXT NOT NULL, initiator TEXT NOT NULL, video INTEGER NOT NULL,
    ts INTEGER NOT NULL, room BLOB NOT NULL, key BLOB NOT NULL, joined_ms INTEGER, ended_ms INTEGER,
    result TEXT NOT NULL DEFAULT '', members TEXT NOT NULL DEFAULT '[]', hidden INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS calls_ts ON calls (ts);
CREATE TABLE IF NOT EXISTS mirrors (
    chat_id TEXT PRIMARY KEY, node TEXT NOT NULL, log_id BLOB NOT NULL, write_sk BLOB NOT NULL,
    read_sk BLOB NOT NULL, read_offset INTEGER NOT NULL DEFAULT 0);
";

const CALL_COLS: &str = "id, chat_id, initiator, video, ts, room, key, joined_ms, ended_ms, result, members";

#[derive(Clone, Debug)]
pub struct CallRow {
    pub id: String,
    pub chat_id: String,
    pub initiator: String,
    pub video: bool,
    pub ts: u64,
    pub room: Vec<u8>,
    pub key: Vec<u8>,
    /// Когда разговор начался (кто-то ответил).
    pub joined_ms: Option<u64>,
    pub ended_ms: Option<u64>,
    pub result: String,
    /// Кто сейчас в звонке (по сигналингу).
    pub members: Vec<String>,
}

fn call_row(r: &Row) -> Result<CallRow> {
    Ok(CallRow {
        id: r.get(0)?,
        chat_id: r.get(1)?,
        initiator: r.get(2)?,
        video: r.get(3)?,
        ts: r.get::<_, i64>(4)? as u64,
        room: r.get(5)?,
        key: r.get(6)?,
        joined_ms: r.get::<_, Option<i64>>(7)?.map(|v| v as u64),
        ended_ms: r.get::<_, Option<i64>>(8)?.map(|v| v as u64),
        result: r.get(9)?,
        members: serde_json::from_str(&r.get::<_, String>(10)?).unwrap_or_default(),
    })
}

const CHAT_COLS: &str = "id, group_id, title, custom_title, node, log_id, write_sk, read_sk, read_offset, state, \
                         created_ms, last_ms, unread, muted, pinned";
const MSG_COLS: &str =
    "id, chat_id, sender_id, outgoing, ts, text, attachment, status, file_path, reply_to, link, fwd, fwd_id";

fn chat_row(r: &Row) -> Result<ChatRow> {
    Ok(ChatRow {
        id: r.get(0)?,
        group_id: r.get(1)?,
        title: r.get(2)?,
        custom_title: r.get(3)?,
        node: r.get(4)?,
        log_id: r.get(5)?,
        write_sk: r.get(6)?,
        read_sk: r.get(7)?,
        read_offset: r.get::<_, i64>(8)? as u64,
        state: ChatState::from_i64(r.get(9)?),
        created_ms: r.get::<_, i64>(10)? as u64,
        last_ms: r.get::<_, i64>(11)? as u64,
        unread: r.get(12)?,
        muted: r.get(13)?,
        pinned: r.get(14)?,
    })
}

fn message_row(r: &Row) -> Result<MessageRow> {
    let attachment: Option<String> = r.get(6)?;
    Ok(MessageRow {
        id: r.get(0)?,
        chat_id: r.get(1)?,
        sender_id: r.get(2)?,
        outgoing: r.get(3)?,
        ts: r.get::<_, i64>(4)? as u64,
        text: r.get(5)?,
        attachment: attachment.and_then(|a| serde_json::from_str(&a).ok()),
        status: MessageStatus::from_i64(r.get(7)?),
        file_path: r.get(8)?,
        reply_to: r.get(9)?,
        link: r.get::<_, Option<String>>(10)?.and_then(|l| serde_json::from_str(&l).ok()),
        fwd: r.get(11)?,
        fwd_id: r.get(12)?,
    })
}

fn queue_row(r: &Row) -> Result<QueueRow> {
    Ok(QueueRow {
        chat_id: r.get(0)?,
        node: r.get(1)?,
        recipient_id: r.get(2)?,
        recipient_sk: r.get(3)?,
        sender_id: r.get(4)?,
    })
}

impl Store {
    /// `key` — ключ SQLCipher (32 байта). Старая незашифрованная база шифруется на месте.
    pub fn open(path: &Path, key: Option<&[u8]>) -> Result<Self> {
        // Сбой при открытии бывает временным (прошлый процесс ещё закрывает базу) — пробуем ещё.
        // Неверный ключ (своя формулировка) повторять незачем: его проверка уже с повторами.
        let mut attempt = 0;
        loop {
            match Self::open_once(path, key) {
                Err(rusqlite::Error::SqliteFailure(e, msg))
                    if attempt < 4
                        && msg.as_deref() != Some("wrong database key")
                        && matches!(
                            e.code,
                            rusqlite::ErrorCode::NotADatabase
                                | rusqlite::ErrorCode::DatabaseBusy
                                | rusqlite::ErrorCode::DatabaseLocked
                        ) =>
                {
                    attempt += 1;
                    tracing::warn!("⚠️ database open failed ({e}), retry {attempt}");
                    std::thread::sleep(std::time::Duration::from_millis(400));
                }
                other => return other,
            }
        }
    }

    fn open_once(path: &Path, key: Option<&[u8]>) -> Result<Self> {
        let conn = match key {
            Some(key) => Self::open_encrypted(path, key)?,
            None => Connection::open(path)?,
        };
        conn.execute_batch(SCHEMA)?;
        // Миграция: превью ссылок появилось позже первых баз.
        let has_link: bool =
            conn.prepare("SELECT 1 FROM pragma_table_info('messages') WHERE name = 'link'")?.exists([])?;
        if !has_link {
            conn.execute_batch("ALTER TABLE messages ADD COLUMN link TEXT")?;
        }
        // Миграция: подпись «Переслано от …».
        let has_fwd: bool =
            conn.prepare("SELECT 1 FROM pragma_table_info('messages') WHERE name = 'fwd'")?.exists([])?;
        if !has_fwd {
            conn.execute_batch("ALTER TABLE messages ADD COLUMN fwd TEXT")?;
        }
        let has_fwd_id: bool =
            conn.prepare("SELECT 1 FROM pragma_table_info('messages') WHERE name = 'fwd_id'")?.exists([])?;
        if !has_fwd_id {
            conn.execute_batch("ALTER TABLE messages ADD COLUMN fwd_id TEXT")?;
        }
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn open_encrypted(path: &Path, key: &[u8]) -> Result<Connection> {
        let pragma = format!("PRAGMA key = \"x'{}'\";", hex::encode(key));
        // Несколько попыток: пока прошлый процесс приложения дописывает журнал (WAL) при закрытии,
        // SQLCipher отвечает «file is not a database» — как при неверном ключе, хотя база цела.
        for attempt in 0..6 {
            let conn = Connection::open(path)?;
            conn.execute_batch(&pragma)?;
            if conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).is_ok() {
                if attempt > 0 {
                    tracing::info!("🔐 database opened on attempt {}", attempt + 1);
                }
                return Ok(conn);
            }
            drop(conn);
            if attempt < 5 {
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        }
        // Не открылась с ключом: либо это старая открытая база, либо ключ неверный.
        let plain = Connection::open(path)?;
        if plain.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).is_err() {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_NOTADB),
                Some("wrong database key".into()),
            ));
        }
        let tmp = path.with_extension("enc");
        let _ = std::fs::remove_file(&tmp);
        plain.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode = DELETE;")?;
        plain
            .execute(&format!("ATTACH DATABASE ?1 AS enc KEY \"x'{}'\"", hex::encode(key)), [tmp.to_string_lossy()])?;
        plain.query_row("SELECT sqlcipher_export('enc')", [], |_| Ok(()))?;
        plain.execute_batch("DETACH DATABASE enc;")?;
        drop(plain);
        for ext in ["db-wal", "db-shm"] {
            let _ = std::fs::remove_file(path.with_extension(ext));
        }
        std::fs::rename(&tmp, path).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        tracing::info!("🔐 database encrypted in place");
        let conn = Connection::open(path)?;
        conn.execute_batch(&pragma)?;
        Ok(conn)
    }

    // ── звонки ──

    /// Новый вызов; повтор (догон истории, второе устройство) ничего не меняет. `true` — вставлен.
    pub fn insert_call(&self, call: &CallRow) -> Result<bool> {
        self.with(|c| {
            c.execute(
                "INSERT OR IGNORE INTO calls (id, chat_id, initiator, video, ts, room, key) VALUES (?,?,?,?,?,?,?)",
                params![call.id, call.chat_id, call.initiator, call.video, call.ts as i64, call.room, call.key],
            )
            .map(|n| n > 0)
        })
    }

    pub fn call(&self, id: &str) -> Result<Option<CallRow>> {
        self.with(|c| c.query_row(&format!("SELECT {CALL_COLS} FROM calls WHERE id = ?"), [id], call_row).optional())
    }

    /// История: новые сверху, скрытые пользователем — нет.
    pub fn calls(&self, limit: u32) -> Result<Vec<CallRow>> {
        self.with(|c| {
            let mut stmt =
                c.prepare(&format!("SELECT {CALL_COLS} FROM calls WHERE hidden = 0 ORDER BY ts DESC LIMIT ?"))?;
            let rows = stmt.query_map([limit], call_row)?;
            rows.collect()
        })
    }

    pub fn update_call(&self, call: &CallRow) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE calls SET joined_ms = ?, ended_ms = ?, result = ?, members = ? WHERE id = ?",
                params![
                    call.joined_ms.map(|v| v as i64),
                    call.ended_ms.map(|v| v as i64),
                    call.result,
                    serde_json::to_string(&call.members).unwrap(),
                    call.id
                ],
            )
            .map(drop)
        })
    }

    /// Убрать из истории (только на этом устройстве; звонок в журнале остаётся).
    pub fn hide_calls(&self, ids: &[String]) -> Result<()> {
        self.with(|c| {
            for id in ids {
                c.execute("UPDATE calls SET hidden = 1 WHERE id = ?", [id])?;
            }
            Ok(())
        })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        f(&self.conn.lock().unwrap())
    }

    // ── kv ──

    pub fn get(&self, k: &str) -> Result<Option<Vec<u8>>> {
        self.with(|c| c.query_row("SELECT v FROM kv WHERE k = ?", [k], |r| r.get(0)).optional())
    }

    /// Все ключи с префиксом (для настроек приложения и реестра устройств).
    pub fn get_prefix(&self, prefix: &str) -> Result<Vec<(String, Vec<u8>)>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT k, v FROM kv WHERE substr(k, 1, length(?1)) = ?1")?;
            let rows = stmt.query_map([prefix], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect()
        })
    }

    pub fn set(&self, k: &str, v: &[u8]) -> Result<()> {
        self.with(|c| c.execute("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", params![k, v]).map(drop))
    }

    pub fn delete(&self, k: &str) -> Result<()> {
        self.with(|c| c.execute("DELETE FROM kv WHERE k = ?", [k]).map(drop))
    }

    // ── MLS ──

    pub fn load_mls(&self) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT k, v FROM mls")?;
            let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect()
        })
    }

    /// Состояние MLS небольшое — перезаписываем целиком одной транзакцией.
    pub fn save_mls(&self, values: &HashMap<Vec<u8>, Vec<u8>>) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM mls", [])?;
        {
            let mut stmt = tx.prepare("INSERT INTO mls (k, v) VALUES (?, ?)")?;
            for (k, v) in values {
                stmt.execute(params![k, v])?;
            }
        }
        tx.commit()
    }

    // ── чаты ──

    pub fn insert_chat(&self, c: &ChatRow) -> Result<()> {
        self.with(|conn| {
            conn.execute(
                &format!("INSERT INTO chats ({CHAT_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"),
                params![
                    c.id,
                    c.group_id,
                    c.title,
                    c.custom_title,
                    c.node,
                    c.log_id,
                    c.write_sk,
                    c.read_sk,
                    c.read_offset as i64,
                    c.state as i64,
                    c.created_ms as i64,
                    c.last_ms as i64,
                    c.unread,
                    c.muted,
                    c.pinned
                ],
            )
            .map(drop)
        })
    }

    pub fn chats(&self) -> Result<Vec<ChatRow>> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!("SELECT {CHAT_COLS} FROM chats"))?;
            let rows = stmt.query_map([], chat_row)?;
            rows.collect()
        })
    }

    pub fn chat(&self, id: &str) -> Result<Option<ChatRow>> {
        self.with(|c| c.query_row(&format!("SELECT {CHAT_COLS} FROM chats WHERE id = ?"), [id], chat_row).optional())
    }

    pub fn chat_by_log(&self, log_id: &[u8]) -> Result<Option<ChatRow>> {
        self.with(|c| {
            c.query_row(&format!("SELECT {CHAT_COLS} FROM chats WHERE log_id = ? AND state = 1"), [log_id], chat_row)
                .optional()
        })
    }

    /// Чат по MLS group id — один и тот же на всех устройствах аккаунта (локальные id разные).
    pub fn chat_by_group(&self, group_id: &[u8]) -> Result<Option<ChatRow>> {
        self.with(|c| {
            c.query_row(&format!("SELECT {CHAT_COLS} FROM chats WHERE group_id = ?"), [group_id], chat_row).optional()
        })
    }

    pub fn activate_chat(
        &self,
        id: &str,
        group_id: &[u8],
        log_id: &[u8],
        write_sk: &[u8],
        read_sk: &[u8],
        from: u64,
    ) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE chats SET group_id = ?, log_id = ?, write_sk = ?, read_sk = ?, read_offset = ?, state = 1 \
                 WHERE id = ?",
                params![group_id, log_id, write_sk, read_sk, from as i64, id],
            )
            .map(drop)
        })
    }

    pub fn set_chat_state(&self, id: &str, state: ChatState) -> Result<()> {
        self.with(|c| c.execute("UPDATE chats SET state = ? WHERE id = ?", params![state as i64, id]).map(drop))
    }

    pub fn set_read_offset(&self, id: &str, offset: u64) -> Result<()> {
        self.with(|c| {
            c.execute("UPDATE chats SET read_offset = MAX(read_offset, ?) WHERE id = ?", params![offset as i64, id])
                .map(drop)
        })
    }

    pub fn set_title(&self, id: &str, title: &str, custom: bool) -> Result<()> {
        self.with(|c| {
            c.execute("UPDATE chats SET title = ?, custom_title = ? WHERE id = ?", params![title, custom, id]).map(drop)
        })
    }

    pub fn set_flag(&self, id: &str, column: &str, value: bool) -> Result<()> {
        debug_assert!(matches!(column, "muted" | "pinned"));
        self.with(|c| c.execute(&format!("UPDATE chats SET {column} = ? WHERE id = ?"), params![value, id]).map(drop))
    }

    pub fn touch_chat(&self, id: &str, ts: u64, unread_delta: u32) -> Result<()> {
        self.with(|c| {
            c.execute(
                "UPDATE chats SET last_ms = MAX(last_ms, ?), unread = unread + ? WHERE id = ?",
                params![ts as i64, unread_delta, id],
            )
            .map(drop)
        })
    }

    pub fn clear_unread(&self, id: &str) -> Result<u32> {
        self.with(|c| {
            let n: u32 = c.query_row("SELECT unread FROM chats WHERE id = ?", [id], |r| r.get(0)).unwrap_or(0);
            c.execute("UPDATE chats SET unread = 0 WHERE id = ?", [id])?;
            Ok(n)
        })
    }

    /// Прочитано на другом устройстве до `up_to`: непрочитанными остаются только входящие новее.
    pub fn set_read_up_to(&self, id: &str, up_to: u64) -> Result<u32> {
        self.with(|c| {
            let left: u32 = c.query_row(
                "SELECT COUNT(*) FROM messages WHERE chat_id = ? AND outgoing = 0 AND ts > ?",
                params![id, up_to as i64],
                |r| r.get(0),
            )?;
            c.execute("UPDATE chats SET unread = MIN(unread, ?) WHERE id = ?", params![left, id])?;
            Ok(left)
        })
    }

    pub fn set_unread(&self, id: &str, unread: u32) -> Result<()> {
        self.with(|c| c.execute("UPDATE chats SET unread = ? WHERE id = ?", params![unread, id]).map(drop))
    }

    pub fn delete_chat(&self, id: &str) -> Result<()> {
        self.with(|c| {
            for table in ["chats WHERE id", "members WHERE chat_id", "invites WHERE chat_id", "joins WHERE chat_id"] {
                c.execute(&format!("DELETE FROM {table} = ?"), [id])?;
            }
            c.execute("DELETE FROM own_offsets WHERE chat_id = ?", [id])?;
            c.execute("DELETE FROM messages WHERE chat_id = ?", [id])?;
            c.execute("DELETE FROM mirrors WHERE chat_id = ?", [id])?;
            Ok(())
        })
    }

    // ── участники ──

    pub fn upsert_member(&self, chat_id: &str, member_id: &str, name: &str, avatar: Option<&[u8]>) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT OR REPLACE INTO members (chat_id, member_id, name, avatar) VALUES (?, ?, ?, ?)",
                params![chat_id, member_id, name, avatar],
            )
            .map(drop)
        })
    }

    pub fn delete_member(&self, chat_id: &str, member_id: &str) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM members WHERE chat_id = ? AND member_id = ?", [chat_id, member_id]).map(drop)
        })
    }

    // ── резервные журналы ──

    pub fn mirror(&self, chat_id: &str) -> Result<Option<MirrorRow>> {
        self.with(|c| {
            c.query_row(
                "SELECT node, log_id, write_sk, read_sk, read_offset FROM mirrors WHERE chat_id = ?",
                [chat_id],
                |r| {
                    Ok(MirrorRow {
                        node: r.get(0)?,
                        log_id: r.get(1)?,
                        write_sk: r.get(2)?,
                        read_sk: r.get(3)?,
                        read_offset: r.get::<_, i64>(4)? as u64,
                    })
                },
            )
            .optional()
        })
    }

    pub fn set_mirror(&self, chat_id: &str, m: &MirrorRow) -> Result<()> {
        self.with(|c| {
            c.execute(
                "INSERT OR REPLACE INTO mirrors (chat_id, node, log_id, write_sk, read_sk, read_offset) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![chat_id, m.node, m.log_id, m.write_sk, m.read_sk, m.read_offset as i64],
            )
            .map(drop)
        })
    }

    /// Переезд на резервный журнал: он становится основным, старый — резервом.
    /// Свои смещения относились к старому журналу — сбрасываем, иначе пропустим чужие записи.
    pub fn swap_to_mirror(&self, chat_id: &str) -> Result<Option<MirrorRow>> {
        let (Some(chat), Some(m)) = (self.chat(chat_id)?, self.mirror(chat_id)?) else { return Ok(None) };
        let old = MirrorRow {
            node: chat.node.clone(),
            log_id: chat.log_id.clone(),
            write_sk: chat.write_sk.clone(),
            read_sk: chat.read_sk.clone(),
            read_offset: chat.read_offset,
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE chats SET node = ?, log_id = ?, write_sk = ?, read_sk = ?, read_offset = ? WHERE id = ?",
            params![m.node, m.log_id, m.write_sk, m.read_sk, m.read_offset as i64, chat_id],
        )?;
        tx.execute(
            "UPDATE mirrors SET node = ?, log_id = ?, write_sk = ?, read_sk = ?, read_offset = ? WHERE chat_id = ?",
            params![old.node, old.log_id, old.write_sk, old.read_sk, old.read_offset as i64, chat_id],
        )?;
        tx.execute("DELETE FROM own_offsets WHERE chat_id = ?", [chat_id])?;
        tx.execute("DELETE FROM invites WHERE chat_id = ?", [chat_id])?;
        tx.commit()?;
        Ok(Some(m))
    }

    pub fn members(&self, chat_id: &str) -> Result<Vec<MemberRow>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT member_id, name, avatar FROM members WHERE chat_id = ?")?;
            let rows = stmt
                .query_map([chat_id], |r| Ok(MemberRow { member_id: r.get(0)?, name: r.get(1)?, avatar: r.get(2)? }))?;
            rows.collect()
        })
    }

    // ── очереди ──

    pub fn insert_queue(&self, table: &str, q: &QueueRow) -> Result<()> {
        debug_assert!(matches!(table, "invites" | "joins"));
        self.with(|c| {
            c.execute(
                &format!(
                    "INSERT OR REPLACE INTO {table} (chat_id, node, recipient_id, recipient_sk, sender_id) \
                     VALUES (?, ?, ?, ?, ?)"
                ),
                params![q.chat_id, q.node, q.recipient_id, q.recipient_sk, q.sender_id],
            )
            .map(drop)
        })
    }

    pub fn queues(&self, table: &str) -> Result<Vec<QueueRow>> {
        self.with(|c| {
            let mut stmt =
                c.prepare(&format!("SELECT chat_id, node, recipient_id, recipient_sk, sender_id FROM {table}"))?;
            let rows = stmt.query_map([], queue_row)?;
            rows.collect()
        })
    }

    pub fn queue_for_chat(&self, table: &str, chat_id: &str) -> Result<Option<QueueRow>> {
        self.with(|c| {
            c.query_row(
                &format!("SELECT chat_id, node, recipient_id, recipient_sk, sender_id FROM {table} WHERE chat_id = ?"),
                [chat_id],
                queue_row,
            )
            .optional()
        })
    }

    pub fn delete_queue(&self, table: &str, chat_id: &str) -> Result<()> {
        self.with(|c| c.execute(&format!("DELETE FROM {table} WHERE chat_id = ?"), [chat_id]).map(drop))
    }

    // ── свои записи в журнале ──

    pub fn add_own_offset(&self, chat_id: &str, offset: u64) -> Result<()> {
        self.with(|c| {
            c.execute("INSERT OR IGNORE INTO own_offsets (chat_id, off) VALUES (?, ?)", params![chat_id, offset as i64])
                .map(drop)
        })
    }

    pub fn is_own_offset(&self, chat_id: &str, offset: u64) -> Result<bool> {
        self.with(|c| {
            c.query_row(
                "SELECT 1 FROM own_offsets WHERE chat_id = ? AND off = ?",
                params![chat_id, offset as i64],
                |_| Ok(()),
            )
            .optional()
            .map(|r| r.is_some())
        })
    }

    // ── сообщения ──

    pub fn insert_message(&self, m: &MessageRow) -> Result<bool> {
        self.with(|c| Self::insert_message_in(c, m))
    }

    /// Новое сообщение и время/непрочитанные чата — одной операцией под замком базы:
    /// иначе между записями читатель видел сообщение без счётчика непрочитанных.
    /// Чат трогается, только если сообщение действительно новое.
    pub fn insert_message_touch(&self, m: &MessageRow, ts: u64, unread_delta: u32) -> Result<bool> {
        self.with(|c| {
            let tx = c.unchecked_transaction()?;
            let inserted = Self::insert_message_in(&tx, m)?;
            if inserted {
                tx.execute(
                    "UPDATE chats SET last_ms = MAX(last_ms, ?), unread = unread + ? WHERE id = ?",
                    params![ts as i64, unread_delta, m.chat_id],
                )?;
            }
            tx.commit()?;
            Ok(inserted)
        })
    }

    fn insert_message_in(c: &Connection, m: &MessageRow) -> Result<bool> {
        {
            let attachment = m.attachment.as_ref().map(|a| serde_json::to_string(a).unwrap());
            let link = m.link.as_ref().map(|l| serde_json::to_string(l).unwrap());
            let n = c.execute(
                &format!("INSERT OR IGNORE INTO messages ({MSG_COLS}) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"),
                params![
                    m.id,
                    m.chat_id,
                    m.sender_id,
                    m.outgoing,
                    m.ts as i64,
                    m.text,
                    attachment,
                    m.status as i64,
                    m.file_path,
                    m.reply_to,
                    link,
                    m.fwd,
                    m.fwd_id
                ],
            )?;
            Ok(n > 0)
        }
    }

    pub fn message(&self, id: &str) -> Result<Option<MessageRow>> {
        self.with(|c| {
            c.query_row(&format!("SELECT {MSG_COLS} FROM messages WHERE id = ?"), [id], message_row).optional()
        })
    }

    /// Последние `limit` сообщений (по порядку), опционально — до сообщения `before`.
    pub fn messages(&self, chat_id: &str, limit: u32, before: Option<&str>) -> Result<Vec<MessageRow>> {
        self.with(|c| {
            let before_seq: i64 = match before {
                Some(id) => c
                    .query_row("SELECT seq FROM messages WHERE id = ?", [id], |r| r.get(0))
                    .optional()?
                    .unwrap_or(i64::MAX),
                None => i64::MAX,
            };
            let mut stmt = c.prepare(&format!(
                "SELECT {MSG_COLS} FROM messages WHERE chat_id = ? AND seq < ? ORDER BY seq DESC LIMIT ?"
            ))?;
            let mut rows: Vec<MessageRow> =
                stmt.query_map(params![chat_id, before_seq, limit], message_row)?.collect::<Result<_>>()?;
            rows.reverse();
            Ok(rows)
        })
    }

    pub fn last_message(&self, chat_id: &str) -> Result<Option<MessageRow>> {
        Ok(self.messages(chat_id, 1, None)?.pop())
    }

    pub fn set_status(&self, id: &str, status: MessageStatus) -> Result<()> {
        self.with(|c| c.execute("UPDATE messages SET status = ? WHERE id = ?", params![status as i64, id]).map(drop))
    }

    pub fn set_attachment(&self, id: &str, a: &AttachmentRef) -> Result<()> {
        self.with(|c| {
            c.execute("UPDATE messages SET attachment = ? WHERE id = ?", params![serde_json::to_string(a).unwrap(), id])
                .map(drop)
        })
    }

    pub fn set_file_path(&self, id: &str, path: Option<&str>) -> Result<()> {
        self.with(|c| c.execute("UPDATE messages SET file_path = ? WHERE id = ?", params![path, id]).map(drop))
    }

    /// Отметить свои сообщения прочитанными собеседником (до `up_to` включительно).
    pub fn mark_outgoing_read(&self, chat_id: &str, up_to: u64) -> Result<usize> {
        self.with(|c| {
            c.execute(
                "UPDATE messages SET status = 2 WHERE chat_id = ? AND outgoing = 1 AND status IN (1, 5) AND ts <= ?",
                params![chat_id, up_to as i64],
            )
        })
    }

    /// Свои сообщения дошли до устройства собеседника (до `up_to` включительно).
    pub fn mark_outgoing_delivered(&self, chat_id: &str, up_to: u64) -> Result<usize> {
        self.with(|c| {
            c.execute(
                "UPDATE messages SET status = 5 WHERE chat_id = ? AND outgoing = 1 AND status = 1 AND ts <= ?",
                params![chat_id, up_to as i64],
            )
        })
    }

    pub fn max_incoming_ts(&self, chat_id: &str) -> Result<u64> {
        self.with(|c| {
            c.query_row(
                "SELECT COALESCE(MAX(ts), 0) FROM messages WHERE chat_id = ? AND outgoing = 0",
                [chat_id],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u64)
        })
    }

    pub fn delete_message(&self, id: &str) -> Result<()> {
        self.with(|c| {
            c.execute("DELETE FROM reactions WHERE msg_id = ?", [id])?;
            c.execute("DELETE FROM messages WHERE id = ?", [id]).map(drop)
        })
    }

    /// Поставить (или снять — `None`) реакцию участника.
    pub fn set_reaction(&self, msg_id: &str, sender_id: &str, emoji: Option<&str>, ts: u64) -> Result<()> {
        self.with(|c| match emoji {
            Some(e) => c
                .execute(
                    "INSERT INTO reactions (msg_id, sender_id, emoji, ts) VALUES (?,?,?,?)
                     ON CONFLICT (msg_id, sender_id) DO UPDATE SET emoji = excluded.emoji, ts = excluded.ts",
                    params![msg_id, sender_id, e, ts as i64],
                )
                .map(drop),
            None => {
                c.execute("DELETE FROM reactions WHERE msg_id = ? AND sender_id = ?", [msg_id, sender_id]).map(drop)
            }
        })
    }

    /// Реакции сообщения: (эмодзи, кто поставил) в порядке появления.
    pub fn reactions(&self, msg_id: &str) -> Result<Vec<(String, String)>> {
        self.with(|c| {
            let mut stmt = c.prepare("SELECT emoji, sender_id FROM reactions WHERE msg_id = ? ORDER BY ts ASC")?;
            let rows = stmt.query_map([msg_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect()
        })
    }

    pub fn clear_history(&self, chat_id: &str) -> Result<()> {
        self.with(|c| c.execute("DELETE FROM messages WHERE chat_id = ?", [chat_id]).map(drop))
    }

    /// Готовые локальные файлы от старых к новым (без тех, что ещё выгружаются) — для лимита кэша.
    pub fn media_files_by_age(&self) -> Result<Vec<String>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT file_path FROM messages WHERE file_path IS NOT NULL AND status != 0 ORDER BY ts ASC, seq ASC",
            )?;
            let rows = stmt.query_map([], |r| r.get(0))?;
            rows.collect()
        })
    }

    /// Все локальные файлы вложений — для экрана «Хранилище».
    pub fn media_files(&self) -> Result<Vec<(String, String, String)>> {
        self.with(|c| {
            let mut stmt =
                c.prepare("SELECT chat_id, attachment, file_path FROM messages WHERE file_path IS NOT NULL")?;
            let rows = stmt.query_map([], |r| {
                let att: Option<String> = r.get(1)?;
                let kind = att
                    .and_then(|a| serde_json::from_str::<AttachmentRef>(&a).ok())
                    .map(|a| a.kind)
                    .unwrap_or_else(|| "file".into());
                Ok((r.get(0)?, kind, r.get(2)?))
            })?;
            rows.collect()
        })
    }

    /// Каталог данных мог переехать (на iOS путь к песочнице меняется при каждой переустановке):
    /// пути к файлам вложений переносятся в текущий `media` — по имени файла, если он там есть.
    pub fn rebase_media(&self, media: &Path) -> Result<usize> {
        self.with(|c| {
            let rows: Vec<(String, String)> = {
                let mut stmt = c.prepare("SELECT id, file_path FROM messages WHERE file_path IS NOT NULL")?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                rows.collect::<Result<_>>()?
            };
            let mut moved = 0;
            for (id, old) in rows {
                let Some(name) = Path::new(&old).file_name() else { continue };
                let new = media.join(name);
                if new != Path::new(&old) && new.exists() {
                    c.execute("UPDATE messages SET file_path = ? WHERE id = ?", params![new.to_string_lossy(), id])?;
                    moved += 1;
                }
            }
            Ok(moved)
        })
    }

    /// Свои неотправленные сообщения за последние сутки (ошибка или «отправляется» после перезапуска), старые первыми.
    pub fn unsent_outgoing(&self) -> Result<Vec<String>> {
        let since = crate::now_ms().saturating_sub(24 * 60 * 60 * 1000) as i64;
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id FROM messages WHERE outgoing = 1 AND status IN (0, 3) AND ts >= ? ORDER BY ts ASC, seq ASC",
            )?;
            let rows = stmt.query_map([since], |r| r.get(0))?;
            rows.collect()
        })
    }

    /// Сообщения с вложением, которого нет на устройстве (новые сначала), — для догрузки.
    pub fn missing_media(&self, limit: u32) -> Result<Vec<MessageRow>> {
        self.with(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {MSG_COLS} FROM messages WHERE attachment IS NOT NULL AND file_path IS NULL AND status != 0 \
                 ORDER BY ts DESC LIMIT ?"
            ))?;
            let rows = stmt.query_map([limit], message_row)?;
            rows.collect()
        })
    }

    pub fn clear_file_paths_for(&self, path: &str) -> Result<()> {
        self.with(|c| c.execute("UPDATE messages SET file_path = NULL WHERE file_path = ?", [path]).map(drop))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(id: &str, path: Option<&str>) -> MessageRow {
        MessageRow {
            id: id.into(),
            chat_id: "c".into(),
            sender_id: "me".into(),
            outgoing: true,
            ts: 1,
            text: String::new(),
            attachment: Some(AttachmentRef { kind: "photo".into(), name: "a.jpg".into(), ..Default::default() }),
            status: MessageStatus::Sent,
            file_path: path.map(Into::into),
            reply_to: None,
            link: None,
            fwd: None,
            fwd_id: None,
        }
    }

    #[test]
    fn media_paths_follow_moved_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let media = dir.path().join("media");
        std::fs::create_dir_all(&media).unwrap();
        std::fs::write(media.join("m1.jpg"), b"x").unwrap();
        let store = Store::open(&dir.path().join("client.db"), None).unwrap();
        // Старый путь песочницы (до переустановки) — файл на месте, но под другим каталогом.
        store.insert_message(&message("m1", Some("/old/sandbox/media/m1.jpg"))).unwrap();
        store.insert_message(&message("m2", Some("/old/sandbox/media/m2.jpg"))).unwrap();
        store.insert_message(&message("m3", None)).unwrap();

        assert_eq!(store.rebase_media(&media).unwrap(), 1);
        let m1 = store.message("m1").unwrap().unwrap();
        assert_eq!(m1.file_path.as_deref(), Some(media.join("m1.jpg").to_str().unwrap()));
        // Файла нет — путь не трогаем; повтор ничего не меняет.
        assert_eq!(store.message("m2").unwrap().unwrap().file_path.as_deref(), Some("/old/sandbox/media/m2.jpg"));
        assert_eq!(store.rebase_media(&media).unwrap(), 0);

        let missing: Vec<String> = store.missing_media(10).unwrap().into_iter().map(|m| m.id).collect();
        assert_eq!(missing, vec!["m3".to_string()]);
    }
}
