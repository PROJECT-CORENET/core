//! Клиентское ядро (аккаунт, MLS-чаты, вложения) для Swift.

use std::path::Path;
use std::sync::Arc;

use core_client as cc;

use crate::CoreError;

impl From<cc::Error> for CoreError {
    fn from(e: cc::Error) -> Self {
        match e {
            cc::Error::Net(n) => n.into(),
            cc::Error::Node(m) => CoreError::Node { message: m },
            cc::Error::BadInvite => {
                CoreError::Client { message: "Неверная ссылка-приглашение".into() }
            }
            cc::Error::NotReady => CoreError::Client { message: "Чат ещё подключается".into() },
            other => CoreError::Client { message: other.to_string() },
        }
    }
}

/// Колбэк из Rust: изменился чат `chat_id` (или список чатов, если `None`). Вызывается не на главном потоке.
#[uniffi::export(with_foreign)]
pub trait CoreListener: Send + Sync {
    fn changed(&self, chat_id: Option<String>);
    /// Участник печатает или готовит вложение (`kind`: text, voice, photo, file).
    fn typing(&self, chat_id: String, member_id: String, kind: String);
    /// Другое устройство аккаунта изменило настройку приложения `key` (`devices` — список устройств,
    /// `removed` — это устройство отключили, `*` — всё сразу после связывания).
    fn synced(&self, key: String);
    /// Звонок изменился (вызов, ответ, конец, участники, микрофон/камера).
    fn call_changed(&self, call_id: String);
    /// Кадр звонка: `kind` 1 — звук (Opus), 2 — видео, 3 — ключевой кадр видео, 4 — просьба о ключевом кадре.
    fn call_media(&self, call_id: String, peer: String, kind: u8, data: Vec<u8>);
}

struct ListenerBridge(Arc<dyn CoreListener>);

impl cc::Listener for ListenerBridge {
    fn changed(&self, chat_id: Option<String>) {
        self.0.changed(chat_id);
    }

    fn typing(&self, chat_id: String, member_id: String, kind: String) {
        self.0.typing(chat_id, member_id, kind);
    }

    fn synced(&self, key: String) {
        self.0.synced(key);
    }

    fn call_changed(&self, call_id: String) {
        self.0.call_changed(call_id);
    }

    fn call_media(&self, call_id: String, peer: String, kind: u8, data: Vec<u8>) {
        self.0.call_media(call_id, peer, kind, data);
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CallInfo {
    pub id: String,
    pub chat_id: String,
    pub initiator: String,
    pub outgoing: bool,
    pub video: bool,
    pub group: bool,
    pub ts_ms: u64,
    pub joined_ms: Option<u64>,
    pub ended_ms: Option<u64>,
    /// ringing | outgoing | active | ongoing | ended
    pub state: String,
    /// answered | missed | declined (пусто, пока идёт)
    pub result: String,
    pub members: Vec<String>,
}

impl From<cc::Call> for CallInfo {
    fn from(c: cc::Call) -> Self {
        Self {
            id: c.id,
            chat_id: c.chat_id,
            initiator: c.initiator,
            outgoing: c.outgoing,
            video: c.video,
            group: c.group,
            ts_ms: c.ts,
            joined_ms: c.joined_ms,
            ended_ms: c.ended_ms,
            state: c.state,
            result: c.result,
            members: c.members,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct CallPeerInfo {
    pub peer: String,
    pub member_id: String,
    pub mic: bool,
    pub cam: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ProfileInfo {
    pub id: String,
    pub name: String,
    pub avatar: Option<Vec<u8>>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MemberInfo {
    pub id: String,
    pub name: String,
    pub avatar: Option<Vec<u8>>,
    pub is_me: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct AttachmentInfo {
    /// photo | video | voice | file
    pub kind: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub thumb: Option<Vec<u8>>,
    pub width: u32,
    pub height: u32,
    pub duration_ms: u64,
    pub waveform: Option<Vec<u8>>,
    pub spoiler: bool,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct MessageInfo {
    pub id: String,
    pub chat_id: String,
    pub sender_id: String,
    pub sender_name: String,
    pub outgoing: bool,
    pub ts_ms: u64,
    pub text: String,
    /// sending | sent | read | failed | received
    pub status: String,
    pub attachment: Option<AttachmentInfo>,
    /// Файл вложения на диске (если скачан).
    pub local_path: Option<String>,
    pub reply_to: Option<String>,
    pub link: Option<LinkPreviewInfo>,
    /// Пересланное: имя автора оригинала.
    pub forwarded_from: Option<String>,
    /// Пересланное: ключ автора — открыть его профиль.
    pub forwarded_from_id: Option<String>,
    /// Реакции в порядке появления.
    pub reactions: Vec<ReactionInfo>,
    /// Время последней правки (0 — не редактировалось).
    pub edited_ms: u64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ReactionInfo {
    pub emoji: String,
    pub count: u32,
    /// Среди поставивших есть я.
    pub mine: bool,
    /// Ключи поставивших.
    pub senders: Vec<String>,
}

/// Автозагрузка по типам и лимит кэша (0 — без ограничений).
#[derive(Debug, Clone, uniffi::Record)]
pub struct MediaSettings {
    pub auto_photos: bool,
    pub auto_videos: bool,
    pub auto_voice: bool,
    pub auto_files: bool,
    pub auto_max_bytes: u64,
    pub cache_limit_bytes: u64,
}

/// Превью ссылки. Готовится на устройстве отправителя и едет внутри MLS.
#[derive(Debug, Clone, uniffi::Record)]
pub struct LinkPreviewInfo {
    pub url: String,
    pub title: String,
    pub desc: String,
    pub site: String,
    pub image: Option<Vec<u8>>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct ChatInfo {
    pub id: String,
    pub title: String,
    pub is_group: bool,
    /// joining | active | left
    pub state: String,
    pub node: String,
    pub unread: u32,
    pub muted: bool,
    pub pinned: bool,
    pub last_ms: u64,
    pub last_message: Option<MessageInfo>,
    pub avatar: Option<Vec<u8>>,
    pub members: Vec<MemberInfo>,
    /// Чат «Избранное» (только вы).
    pub is_saved: bool,
    /// Группу создали вы — можно удалять участников.
    pub is_owner: bool,
    /// Нода резервного журнала (чат переедет туда, если его нода пропадёт).
    pub backup_node: Option<String>,
    pub archived: bool,
    /// MLS group id (hex): одинаковый на всех устройствах аккаунта — им называют чаты в общих настройках.
    pub gid: Option<String>,
}

/// Устройство аккаунта.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    /// ios | macos
    pub platform: String,
    /// Нода, к которой подключено устройство (для карты сети).
    pub node: String,
    pub is_this: bool,
    pub seen_ms: u64,
}

/// Одноразовый канал связывания устройств (QR).
#[derive(uniffi::Object)]
pub struct CoreLinkChannel {
    inner: cc::LinkChannel,
}

fn link_role(existing: bool) -> cc::LinkRole {
    if existing {
        cc::LinkRole::Existing
    } else {
        cc::LinkRole::New
    }
}

/// Показать QR для связывания. `existing` — на этом устройстве аккаунт уже есть.
#[uniffi::export(async_runtime = "tokio")]
pub async fn link_offer(node: String, existing: bool, device_name: String) -> Result<Arc<CoreLinkChannel>, CoreError> {
    let inner = cc::LinkChannel::offer(&node, link_role(existing), &device_name).await?;
    Ok(Arc::new(CoreLinkChannel { inner }))
}

/// Отсканировали QR другого устройства.
#[uniffi::export(async_runtime = "tokio")]
pub async fn link_scan(qr: String, existing: bool, device_name: String) -> Result<Arc<CoreLinkChannel>, CoreError> {
    let inner = cc::LinkChannel::scan(&qr, link_role(existing), &device_name).await?;
    Ok(Arc::new(CoreLinkChannel { inner }))
}

/// Похоже ли на QR связывания устройств.
#[uniffi::export]
pub fn is_link_qr(text: String) -> bool {
    cc::LinkOffer::decode(&text).is_some()
}

/// Новое устройство: принять аккаунт и подготовить базу в `dir` (потом — обычный `open_client`).
/// Возвращает имя аккаунта.
#[uniffi::export(async_runtime = "tokio")]
pub async fn link_receive_account(
    channel: Arc<CoreLinkChannel>,
    dir: String,
    db_key: Option<Vec<u8>>,
) -> Result<String, CoreError> {
    Ok(cc::link_receive_account(&channel.inner, Path::new(&dir), db_key.as_deref()).await?)
}

#[uniffi::export(async_runtime = "tokio")]
impl CoreLinkChannel {
    /// Строка для QR (у показывающей стороны).
    pub fn qr(&self) -> Option<String> {
        self.inner.qr()
    }

    /// Имя устройства на той стороне, если уже известно.
    pub fn peer_name(&self) -> Option<String> {
        self.inner.peer_name()
    }

    /// Дождаться, пока QR отсканируют; возвращает имя того устройства.
    pub async fn wait_peer(&self, timeout_secs: u64) -> Result<String, CoreError> {
        Ok(self.inner.wait_peer(std::time::Duration::from_secs(timeout_secs)).await?)
    }

    /// Отказать той стороне.
    pub async fn decline(&self) -> Result<(), CoreError> {
        self.inner.decline().await?;
        self.inner.close().await;
        Ok(())
    }

    pub async fn close(&self) {
        self.inner.close().await;
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct NewAttachment {
    pub path: String,
    pub kind: String,
    pub name: String,
    pub mime: String,
    pub thumb: Option<Vec<u8>>,
    pub width: u32,
    pub height: u32,
    pub duration_ms: u64,
    pub waveform: Option<Vec<u8>>,
    pub spoiler: bool,
    /// Пересылка: имя автора оригинала.
    pub forwarded_from: Option<String>,
    /// Пересылка: ключ автора оригинала.
    pub forwarded_from_id: Option<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct StorageUsage {
    pub photos: u64,
    pub videos: u64,
    pub voice: u64,
    pub files: u64,
    pub database: u64,
}

fn status(s: cc::MessageStatus) -> String {
    match s {
        cc::MessageStatus::Sending => "sending",
        cc::MessageStatus::Sent => "sent",
        cc::MessageStatus::Read => "read",
        cc::MessageStatus::Failed => "failed",
        cc::MessageStatus::Received => "received",
        cc::MessageStatus::Delivered => "delivered",
    }
    .into()
}

fn message(m: cc::Message) -> MessageInfo {
    MessageInfo {
        id: m.id,
        chat_id: m.chat_id,
        sender_id: m.sender_id,
        sender_name: m.sender_name,
        outgoing: m.outgoing,
        ts_ms: m.ts,
        text: m.text,
        status: status(m.status),
        attachment: m.attachment.map(|a| AttachmentInfo {
            kind: a.kind,
            name: a.name,
            mime: a.mime,
            size: a.size,
            thumb: a.thumb,
            width: a.w,
            height: a.h,
            duration_ms: a.duration_ms,
            waveform: a.wave,
            spoiler: a.spoiler,
        }),
        local_path: m.local_path,
        reply_to: m.reply_to,
        link: m.link.map(|l| LinkPreviewInfo {
            url: l.url,
            title: l.title,
            desc: l.desc,
            site: l.site,
            image: l.image,
        }),
        forwarded_from: m.forwarded_from,
        forwarded_from_id: m.forwarded_from_id,
        reactions: m
            .reactions
            .into_iter()
            .map(|r| ReactionInfo { emoji: r.emoji, count: r.count, mine: r.mine, senders: r.senders })
            .collect(),
        edited_ms: m.edited_ms,
    }
}

fn chat(c: cc::Chat) -> ChatInfo {
    ChatInfo {
        id: c.id,
        title: c.title,
        is_group: c.is_group,
        state: match c.state {
            cc::ChatState::Joining => "joining",
            cc::ChatState::Active => "active",
            cc::ChatState::Left => "left",
        }
        .into(),
        node: c.node,
        unread: c.unread,
        muted: c.muted,
        pinned: c.pinned,
        last_ms: c.last_ms,
        last_message: c.last_message.map(message),
        is_saved: c.is_saved,
        is_owner: c.is_owner,
        backup_node: c.backup_node,
        archived: c.archived,
        gid: c.gid,
        avatar: c.avatar,
        members: c
            .members
            .into_iter()
            .map(|m| MemberInfo { id: m.id, name: m.name, avatar: m.avatar, is_me: m.is_me })
            .collect(),
    }
}

/// Аккаунт на устройстве. Все сетевые вызовы — async, данные — из локальной базы.
#[derive(uniffi::Object)]
pub struct CoreClient {
    inner: cc::Client,
}

/// Открыть (или создать) аккаунт в каталоге `dir`; новые чаты создаются на ноде `node`.
#[uniffi::export(async_runtime = "tokio")]
/// `db_key` — 32-байтный ключ SQLCipher (приложение держит его в Secure Enclave / файле).
pub async fn open_client(dir: String, node: String, db_key: Option<Vec<u8>>) -> Result<Arc<CoreClient>, CoreError> {
    let inner = cc::Client::open_with_key(Path::new(&dir), &node, db_key.as_deref()).await?;
    Ok(Arc::new(CoreClient { inner }))
}

/// Писать журнал ядра в файл (`RUST_LOG`-фильтр, по умолчанию info). Повторный вызов ничего не делает.
/// Файл больше 4 МБ при старте начинается заново.
#[uniffi::export]
pub fn init_logging(path: String) {
    use std::sync::Mutex;
    use tracing_subscriber::EnvFilter;
    if std::fs::metadata(&path).map(|m| m.len() > 4 << 20).unwrap_or(false) {
        let _ = std::fs::remove_file(&path);
    }
    let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) else { return };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let ok = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_writer(Mutex::new(file))
        .try_init()
        .is_ok();
    if ok {
        tracing::info!("📝 core log started");
    }
}

/// Похоже ли на ссылку-приглашение (для вставки из буфера).
#[uniffi::export]
pub fn is_invite_link(text: String) -> bool {
    cc::Invite::decode(&text).is_some()
}

/// Что видно в приглашении до вступления: кто пригласил и (для группы) её название.
#[derive(Debug, Clone, uniffi::Record)]
pub struct InviteInfo {
    pub inviter: String,
    pub title: String,
    pub node: String,
}

#[uniffi::export]
pub fn parse_invite(link: String) -> Option<InviteInfo> {
    let invite = cc::Invite::decode(&link)?;
    Some(InviteInfo { inviter: invite.hint, title: invite.title, node: invite.node })
}

#[uniffi::export(async_runtime = "tokio")]
impl CoreClient {
    pub fn set_listener(&self, listener: Arc<dyn CoreListener>) {
        self.inner.set_listener(Arc::new(ListenerBridge(listener)));
    }

    pub fn set_default_node(&self, node: String) {
        self.inner.set_default_node(&node);
    }

    pub fn profile(&self) -> Result<ProfileInfo, CoreError> {
        let p = self.inner.profile()?;
        Ok(ProfileInfo { id: p.id, name: p.name, avatar: p.avatar })
    }

    pub async fn set_profile(&self, name: String, avatar: Option<Vec<u8>>) -> Result<(), CoreError> {
        Ok(self.inner.set_profile(&name, avatar).await?)
    }

    pub fn chats(&self) -> Result<Vec<ChatInfo>, CoreError> {
        Ok(self.inner.chats()?.into_iter().map(chat).collect())
    }

    pub fn chat(&self, chat_id: String) -> Result<ChatInfo, CoreError> {
        Ok(chat(self.inner.chat(&chat_id)?))
    }

    pub fn messages(&self, chat_id: String, limit: u32, before: Option<String>) -> Result<Vec<MessageInfo>, CoreError> {
        Ok(self.inner.messages(&chat_id, limit, before.as_deref())?.into_iter().map(message).collect())
    }

    /// Новый чат: возвращает [id чата, ссылка-приглашение].
    pub async fn create_chat(&self, title: Option<String>) -> Result<Vec<String>, CoreError> {
        let (id, link) = self.inner.create_chat(title.as_deref()).await?;
        Ok(vec![id, link])
    }

    /// Id чата «Избранное»; создаётся при первом вызове (нужна связь с нодой).
    pub async fn saved_chat(&self) -> Result<String, CoreError> {
        Ok(self.inner.saved_chat().await?)
    }

    pub async fn invite_link(&self, chat_id: String) -> Result<String, CoreError> {
        Ok(self.inner.invite_link(&chat_id).await?)
    }

    pub async fn accept_invite(&self, link: String) -> Result<String, CoreError> {
        Ok(self.inner.accept_invite(&link).await?)
    }

    pub async fn rename_chat(&self, chat_id: String, title: String) -> Result<(), CoreError> {
        Ok(self.inner.rename_chat(&chat_id, &title).await?)
    }

    pub fn set_muted(&self, chat_id: String, muted: bool) -> Result<(), CoreError> {
        Ok(self.inner.set_muted(&chat_id, muted)?)
    }

    pub async fn send_typing(&self, chat_id: String, kind: String) -> Result<(), CoreError> {
        Ok(self.inner.send_typing(&chat_id, &kind).await?)
    }

    pub fn set_archived(&self, chat_id: String, archived: bool) -> Result<(), CoreError> {
        Ok(self.inner.set_archived(&chat_id, archived)?)
    }

    pub fn set_pinned(&self, chat_id: String, pinned: bool) -> Result<(), CoreError> {
        Ok(self.inner.set_pinned(&chat_id, pinned)?)
    }

    pub async fn mark_read(&self, chat_id: String) -> Result<(), CoreError> {
        Ok(self.inner.mark_read(&chat_id).await?)
    }

    pub fn mark_unread(&self, chat_id: String) -> Result<(), CoreError> {
        Ok(self.inner.mark_unread(&chat_id)?)
    }

    pub async fn remove_member(&self, chat_id: String, member_id: String) -> Result<(), CoreError> {
        Ok(self.inner.remove_member(&chat_id, &member_id).await?)
    }

    pub async fn leave_chat(&self, chat_id: String) -> Result<(), CoreError> {
        Ok(self.inner.leave_chat(&chat_id).await?)
    }

    /// Ноды основной сети — для резервных журналов чатов.
    pub async fn set_backup_nodes(&self, nodes: Vec<String>) {
        // async — чтобы ядро запустило фоновую задачу внутри своего рантайма tokio.
        self.inner.set_backup_nodes(nodes);
    }

    pub fn delete_chat(&self, chat_id: String) -> Result<(), CoreError> {
        Ok(self.inner.delete_chat(&chat_id)?)
    }

    pub fn clear_history(&self, chat_id: String) -> Result<(), CoreError> {
        Ok(self.inner.clear_history(&chat_id)?)
    }

    pub async fn send_text(
        &self,
        chat_id: String,
        text: String,
        reply_to: Option<String>,
        link: Option<LinkPreviewInfo>,
    ) -> Result<String, CoreError> {
        let link =
            link.map(|l| cc::LinkPreview { url: l.url, title: l.title, desc: l.desc, site: l.site, image: l.image });
        Ok(self.inner.send_text(&chat_id, &text, reply_to, link).await?)
    }

    /// Переслать текст с подписью «Переслано от `from`».
    pub async fn forward_text(
        &self,
        chat_id: String,
        text: String,
        link: Option<LinkPreviewInfo>,
        from: String,
        from_id: Option<String>,
    ) -> Result<String, CoreError> {
        let link =
            link.map(|l| cc::LinkPreview { url: l.url, title: l.title, desc: l.desc, site: l.site, image: l.image });
        Ok(self.inner.forward_text(&chat_id, &text, link, &from, from_id).await?)
    }

    pub async fn send_attachment(
        &self,
        chat_id: String,
        attachment: NewAttachment,
        caption: String,
    ) -> Result<String, CoreError> {
        let a = cc::OutgoingAttachment {
            path: attachment.path,
            kind: attachment.kind,
            name: attachment.name,
            mime: attachment.mime,
            thumb: attachment.thumb,
            width: attachment.width,
            height: attachment.height,
            duration_ms: attachment.duration_ms,
            waveform: attachment.waveform,
            spoiler: attachment.spoiler,
            forwarded_from: attachment.forwarded_from,
            forwarded_from_id: attachment.forwarded_from_id,
        };
        Ok(self.inner.send_attachment(&chat_id, a, &caption).await?)
    }

    pub async fn download(&self, message_id: String) -> Result<String, CoreError> {
        Ok(self.inner.download(&message_id).await?)
    }

    pub fn delete_message(&self, message_id: String) -> Result<(), CoreError> {
        Ok(self.inner.delete_message_locally(&message_id)?)
    }

    /// Поставить реакцию; `None` — снять свою.
    pub async fn react(&self, message_id: String, emoji: Option<String>) -> Result<(), CoreError> {
        Ok(self.inner.react(&message_id, emoji.as_deref()).await?)
    }

    /// Повторить отправку сообщения с ошибкой (выгрузит вложение, если оно не ушло).
    pub async fn retry_message(&self, message_id: String) -> Result<(), CoreError> {
        Ok(self.inner.retry_message(&message_id).await?)
    }

    pub async fn edit_message(&self, message_id: String, text: String) -> Result<(), CoreError> {
        Ok(self.inner.edit_message(&message_id, &text).await?)
    }

    pub async fn delete_message_for_all(&self, message_id: String) -> Result<(), CoreError> {
        Ok(self.inner.delete_message_for_all(&message_id).await?)
    }

    pub fn media_settings(&self) -> MediaSettings {
        let m = self.inner.media_settings();
        MediaSettings {
            auto_photos: m.auto_photos,
            auto_videos: m.auto_videos,
            auto_voice: m.auto_voice,
            auto_files: m.auto_files,
            auto_max_bytes: m.auto_max_bytes,
            cache_limit_bytes: m.cache_limit_bytes,
        }
    }

    /// Сохранить настройки автозагрузки и лимит кэша (лишнее удаляется сразу).
    pub fn set_media_settings(&self, settings: MediaSettings) -> Result<(), CoreError> {
        Ok(self.inner.set_media_settings(&cc::MediaSettings {
            auto_photos: settings.auto_photos,
            auto_videos: settings.auto_videos,
            auto_voice: settings.auto_voice,
            auto_files: settings.auto_files,
            auto_max_bytes: settings.auto_max_bytes,
            cache_limit_bytes: settings.cache_limit_bytes,
        })?)
    }

    pub fn storage_usage(&self) -> Result<StorageUsage, CoreError> {
        let u = self.inner.storage_usage()?;
        Ok(StorageUsage { photos: u.photos, videos: u.videos, voice: u.voice, files: u.files, database: u.database })
    }

    // ── несколько устройств ──

    /// Старое устройство: отдать аккаунт новому (после подтверждения пользователем).
    pub async fn link_send_account(&self, channel: Arc<CoreLinkChannel>) -> Result<(), CoreError> {
        Ok(self.inner.link_send_account(&channel.inner).await?)
    }

    // ── звонки ──

    pub async fn start_call(&self, chat_id: String, video: bool) -> Result<String, CoreError> {
        Ok(self.inner.start_call(&chat_id, video).await?)
    }

    pub async fn accept_call(&self, call_id: String) -> Result<(), CoreError> {
        Ok(self.inner.accept_call(&call_id).await?)
    }

    pub async fn decline_call(&self, call_id: String) -> Result<(), CoreError> {
        Ok(self.inner.decline_call(&call_id).await?)
    }

    pub async fn end_call(&self, call_id: String) -> Result<(), CoreError> {
        Ok(self.inner.end_call(&call_id).await?)
    }

    /// Кадр звонка (без ожидания): `kind` как у `CoreListener::call_media`.
    pub fn call_send(&self, call_id: String, kind: u8, data: Vec<u8>) {
        self.inner.call_send(&call_id, kind, &data)
    }

    pub fn set_call_media(&self, call_id: String, mic: bool, cam: bool) {
        self.inner.set_call_media(&call_id, mic, cam)
    }

    pub fn call(&self, call_id: String) -> Result<CallInfo, CoreError> {
        Ok(self.inner.call(&call_id)?.into())
    }

    pub fn calls(&self, limit: u32) -> Result<Vec<CallInfo>, CoreError> {
        Ok(self.inner.calls(limit)?.into_iter().map(Into::into).collect())
    }

    pub fn call_peers(&self, call_id: String) -> Vec<CallPeerInfo> {
        self.inner
            .call_peers(&call_id)
            .into_iter()
            .map(|p| CallPeerInfo { peer: p.peer, member_id: p.member_id, mic: p.mic, cam: p.cam })
            .collect()
    }

    pub fn hide_calls(&self, ids: Vec<String>) -> Result<(), CoreError> {
        Ok(self.inner.hide_calls(&ids)?)
    }

    /// Общая для всех устройств настройка приложения (JSON).
    pub fn set_app_setting(&self, key: String, value: String) -> Result<(), CoreError> {
        Ok(self.inner.set_app_setting(&key, &value)?)
    }

    pub fn app_setting(&self, key: String) -> Result<Option<String>, CoreError> {
        Ok(self.inner.app_setting(&key)?)
    }

    /// Сообщить о себе: имя устройства, платформа, нода подключения.
    pub fn set_device(&self, name: String, platform: String, node: String) -> Result<(), CoreError> {
        Ok(self.inner.set_device(&name, &platform, &node)?)
    }

    pub fn devices(&self) -> Result<Vec<DeviceInfo>, CoreError> {
        Ok(self
            .inner
            .devices()?
            .into_iter()
            .map(|d| DeviceInfo {
                id: d.id,
                name: d.name,
                platform: d.platform,
                node: d.node,
                is_this: d.is_this,
                seen_ms: d.seen_ms,
            })
            .collect())
    }

    pub async fn remove_device(&self, device_id: String) -> Result<(), CoreError> {
        Ok(self.inner.remove_device(&device_id).await?)
    }

    /// Доля переданного вложения сообщения (0…1) или `None`, если передачи сейчас нет.
    pub fn transfer_progress(&self, message_id: String) -> Option<f32> {
        self.inner.transfer_progress(&message_id)
    }

    /// Это устройство отключили с другого — нужно стереть данные.
    pub fn is_removed(&self) -> bool {
        self.inner.is_removed()
    }

    /// Удалить скачанные файлы указанных видов (`photo`, `video`, `voice`, `file`; пусто — все). Возвращает байты.
    pub fn clear_media(&self, kinds: Vec<String>) -> Result<u64, CoreError> {
        Ok(self.inner.clear_media(&kinds)?)
    }
}
