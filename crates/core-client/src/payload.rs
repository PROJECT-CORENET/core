//! Что лежит внутри MLS-сообщений и служебных очередей. Нода видит только шифротекст MLS,
//! а в очередях — KeyPackage (публичный) и Welcome (зашифрован для получателя).

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Содержимое прикладного MLS-сообщения.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Payload {
    Message {
        id: String,
        ts: u64,
        #[serde(default)]
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        att: Option<Box<AttachmentRef>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reply_to: Option<String>,
        /// Превью ссылки готовит отправитель: получатель не ходит на чужой сайт и не светит свой IP.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        link: Option<Box<LinkPreview>>,
        /// Пересланное: имя автора оригинала (как его видел пересылающий).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fwd: Option<String>,
        /// Ключ автора оригинала — чтобы открыть его профиль. Нет — автор пожелал остаться только именем.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fwd_id: Option<String>,
    },
    /// Правка текста/подписи; автор определяется MLS, а не полем в теле сообщения.
    Edit {
        id: String,
        text: String,
        ts: u64,
        edit_id: String,
    },
    /// Имя и аватар — только внутри группы, нода их не видит.
    Profile {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
        avatar: Option<Vec<u8>>,
    },
    Title {
        title: String,
    },
    /// Отчёт о прочтении: прочитаны сообщения с `ts <= up_to`.
    Read {
        up_to: u64,
    },
    /// «Печатает…» / «записывает голосовое…» — живёт несколько секунд, в истории не хранится.
    Typing {
        kind: String,
        ts: u64,
    },
    /// Отчёт о доставке: сообщения с `ts <= up_to` дошли до устройства (ещё не прочитаны).
    Delivered {
        up_to: u64,
    },
    Delete {
        id: String,
    },
    /// Реакция на сообщение: одна на участника, пустая строка — снять.
    React {
        id: String,
        emoji: String,
    },
    /// Резервный журнал чата на другой ноде (ключи — только внутри MLS).
    Mirror(MirrorCreds),
    /// Участник выходит из группы: кто-то из оставшихся удаляет его коммитом.
    Leave,
    /// Только в «Избранном», между своими устройствами: появился чат (создан или принято приглашение) —
    /// остальные устройства вступают по ссылке. `gid` — MLS group id (hex), чтобы не вступать дважды.
    SyncChat {
        link: String,
        gid: String,
    },
    /// Только в «Избранном», между своими устройствами: изменение состояния аккаунта.
    Sync(SyncOp),
    /// Звонок: сигналинг идёт через MLS (подлинность и шифрование), звук и видео — через комнату на ноде.
    Call {
        id: String,
        op: CallOp,
    },
}

/// Шаг звонка. `ts` — время отправителя: при догоне истории старый вызов уже не звонит.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum CallOp {
    /// Вызов: комната на ноде чата и ключ шифрования кадров (знают только участники чата).
    Ring {
        ts: u64,
        video: bool,
        #[serde(with = "b64")]
        room: Vec<u8>,
        #[serde(with = "b64")]
        key: Vec<u8>,
    },
    /// Ответил (остальные устройства этого аккаунта перестают звонить).
    Accept { ts: u64 },
    /// Отклонил.
    Decline { ts: u64 },
    /// Вышел из группового звонка.
    Leave { ts: u64 },
    /// Положил трубку (личный звонок завершается у всех).
    End { ts: u64 },
}

/// Что синхронизируется между устройствами одного аккаунта. Чаты — по MLS group id (hex):
/// локальные id чатов на устройствах разные.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SyncOp {
    /// Закреп, звук, архив.
    ChatFlags {
        gid: String,
        pinned: bool,
        muted: bool,
        archived: bool,
    },
    /// Прочитано до `up_to` (ts входящих).
    ReadUpTo {
        gid: String,
        up_to: u64,
    },
    MarkUnread {
        gid: String,
    },
    /// Чат удалён с устройства (без выхода из группы).
    DeleteChat {
        gid: String,
    },
    ClearHistory {
        gid: String,
    },
    /// Сообщение удалено «у себя».
    DeleteLocal {
        gid: String,
        id: String,
    },
    /// Настройки автозагрузки и кэша.
    Media {
        json: String,
    },
    /// Настройка приложения (папки, оформление…): ключ и значение-JSON, последнее по времени побеждает.
    App {
        key: String,
        value: String,
        ts: u64,
    },
    /// Устройство аккаунта: имя, платформа, нода подключения и ключ подписи MLS (по нему отключают).
    Device(DeviceRecord),
    /// Отключить устройство: все удаляют его из своих групп, само устройство стирает аккаунт.
    RemoveDevice {
        id: String,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: String,
    pub name: String,
    /// ios | macos | …
    pub platform: String,
    /// Нода, к которой устройство подключено (для карты сети).
    pub node: String,
    /// Открытый ключ подписи MLS этого устройства (hex).
    pub sig: String,
    pub ts: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MirrorCreds {
    pub node: String,
    #[serde(with = "hex_bytes")]
    pub log_id: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub write_sk: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub read_sk: Vec<u8>,
}

/// Ссылка на зашифрованный файл: куски лежат в отдельном журнале на ноде,
/// ключ расшифровки передаётся только внутри MLS.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AttachmentRef {
    /// photo | video | voice | file
    pub kind: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    #[serde(default)]
    pub node: String,
    #[serde(default, with = "hex_bytes")]
    pub log: Vec<u8>,
    #[serde(default, with = "hex_bytes")]
    pub rk: Vec<u8>,
    #[serde(default, with = "hex_bytes")]
    pub key: Vec<u8>,
    #[serde(default)]
    pub chunks: u32,
    /// Маленькое превью (JPEG) — показывается сразу, до скачивания.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub thumb: Option<Vec<u8>>,
    #[serde(default)]
    pub w: u32,
    #[serde(default)]
    pub h: u32,
    #[serde(default)]
    pub duration_ms: u64,
    /// Форма волны голосового (0–255 на столбик).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub wave: Option<Vec<u8>>,
    /// Фото/видео под спойлером: размыто, пока получатель не нажмёт.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub spoiler: bool,
}

/// Карточка ссылки: заголовок, описание и крошечная картинка.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct LinkPreview {
    pub url: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub desc: String,
    #[serde(default)]
    pub site: String,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub image: Option<Vec<u8>>,
}

impl LinkPreview {
    /// Сообщение целиком должно влезть в одну запись журнала — урезаем превью.
    pub const MAX_IMAGE: usize = 6_000;

    pub fn sanitized(mut self) -> Option<Self> {
        let lower = self.url.to_ascii_lowercase();
        if !(lower.starts_with("https://") || lower.starts_with("http://")) || self.url.len() > 2_000 {
            return None;
        }
        self.title = self.title.chars().take(200).collect();
        self.desc = self.desc.chars().take(300).collect();
        self.site = self.site.chars().take(80).collect();
        if self.image.as_ref().is_some_and(|i| i.len() > Self::MAX_IMAGE) {
            self.image = None;
        }
        Some(self)
    }
}

/// Запрос на вступление — в очередь приглашения.
#[derive(Serialize, Deserialize)]
pub struct JoinRequest {
    #[serde(with = "b64")]
    pub key_package: Vec<u8>,
    /// Куда прислать Welcome (очередь на той же ноде).
    #[serde(with = "hex_bytes")]
    pub reply: Vec<u8>,
}

/// Ответ на вступление — в очередь вступающего.
#[derive(Serialize, Deserialize)]
pub struct JoinReply {
    #[serde(with = "b64")]
    pub welcome: Vec<u8>,
    /// `LogCreds`, зашифрованные ключом из MLS-экспортёра новой эпохи: нода их не прочтёт.
    #[serde(with = "b64")]
    pub creds: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct LogCreds {
    #[serde(with = "hex_bytes")]
    pub log_id: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub write_sk: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub read_sk: Vec<u8>,
    pub from_offset: u64,
}

/// Приглашение: `core-invite:<base64url(JSON)>`. Ссылку передают вне сети (QR, мессенджер).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Invite {
    pub v: u8,
    /// Адрес ноды `core://…`, где живёт чат.
    pub node: String,
    #[serde(with = "hex_bytes")]
    pub queue: Vec<u8>,
    /// Подсказка для интерфейса до вступления; настоящее имя придёт уже внутри MLS.
    #[serde(default)]
    pub hint: String,
    /// Название группы (пусто для личного чата) — для карточки приглашения в переписке.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub title: String,
}

pub const INVITE_PREFIX: &str = "core-invite:";

impl Invite {
    pub fn encode(&self) -> String {
        format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).unwrap()))
    }

    pub fn decode(link: &str) -> Option<Self> {
        let body = link.trim().strip_prefix(INVITE_PREFIX)?;
        let invite: Self = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).ok()?).ok()?;
        (invite.v == 1 && !invite.queue.is_empty()).then_some(invite)
    }
}

pub(crate) mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

pub(crate) mod b64 {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        STANDARD.decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

pub(crate) mod b64_opt {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_str(&STANDARD.encode(v)),
            None => s.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?.map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom)).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_roundtrip() {
        let invite = Invite {
            v: 1,
            node: "core://ab@host:1".into(),
            queue: vec![1, 2, 3],
            hint: "Алиса".into(),
            title: String::new(),
        };
        let link = invite.encode();
        assert!(link.starts_with(INVITE_PREFIX));
        assert_eq!(Invite::decode(&link), Some(invite));
        assert_eq!(Invite::decode("core-invite:@@@"), None);
    }

    #[test]
    fn payload_json_is_tagged() {
        let p = Payload::Read { up_to: 5 };
        assert_eq!(serde_json::to_string(&p).unwrap(), r#"{"t":"read","up_to":5}"#);
    }
}
