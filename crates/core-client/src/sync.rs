//! Несколько устройств одного аккаунта.
//!
//! Каждое устройство — отдельный участник (лист) в каждой MLS-группе: тот же id аккаунта в учётных данных,
//! своя подпись. Поэтому новые сообщения, реакции, удаления и отчёты о прочтении сами приходят на все
//! устройства. Всё остальное (закреп, архив, звук, удаление «у себя», настройки, новые чаты, список
//! устройств) идёт служебными сообщениями `Sync` в «Избранном» — группе только из своих устройств.
//! Чаты в них называются по MLS group id: локальные id чатов на устройствах разные.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use tracing::{info, warn};

use crate::link::{LinkMsg, SnapChat, SnapMember, SnapMessage, Snapshot};
use crate::payload::{DeviceRecord, Payload, SyncOp};
use crate::store::{ChatRow, ChatState, MessageRow, MessageStatus, Store};
use crate::{
    archive_key, device_key, key, media, mls, new_queue, now_ms, owner_key, quiet_key, refused, subscribe_queue,
    AttachmentRef, Client, Device, Error, Inner, Invite, LinkChannel, LinkRole, Result, DEVICE_ID_KEY, LINK_HISTORY,
    LINK_PENDING_KEY, MEDIA_SETTINGS_KEY, SAVED_CHAT_KEY,
};
use core_proto::msg::{request, response, LogCommit};

const DEVICE_SIG_KEY: &str = "device.sig";
const SNAPSHOT_FILE: &str = "link-snapshot.json";
/// Это устройство отключили с другого — приложение должно стереть данные.
const DEVICE_REMOVED_KEY: &str = "device.removed";
const APP_PREFIX: &str = "app.";
const DEVICE_PREFIX: &str = "device.rec.";
/// Чат, в который уже вступаем по команде своего устройства (gid → локальный id).
fn synced_key(gid: &str) -> String {
    format!("sync.gid.{gid}")
}

impl Inner {
    pub(crate) fn gid(&self, chat_id: &str) -> Option<String> {
        self.store.chat(chat_id).ok().flatten()?.group_id.map(hex::encode)
    }

    fn chat_by_gid(&self, gid: &str) -> Result<Option<ChatRow>> {
        let Ok(bytes) = hex::decode(gid) else { return Ok(None) };
        Ok(self.store.chat_by_group(&bytes)?)
    }

    /// Ссылка-приглашение (в том числе в «Избранное» — её получают только свои устройства).
    pub(crate) async fn invite_link(self: &Arc<Self>, chat_id: &str) -> Result<String> {
        let chat = self.store.chat(chat_id)?.ok_or(Error::NoChat)?;
        if chat.state != ChatState::Active {
            return Err(Error::NotReady);
        }
        let q = match self.store.queue_for_chat("invites", chat_id)? {
            Some(q) => q,
            None => {
                let conn = self.conn(&chat.node).await?;
                let q = new_queue(&conn, chat_id, &chat.node).await?;
                self.store.insert_queue("invites", &q)?;
                subscribe_queue(&conn, &q).await?;
                q
            }
        };
        let hint = match self.profile_payload()? {
            Payload::Profile { name, .. } => name,
            _ => String::new(),
        };
        let node = chat.node.clone();
        let model = self.chat_model(chat)?;
        let title = if model.is_group { model.title } else { String::new() };
        Ok(Invite { v: 1, node, queue: q.sender_id, hint, title }.encode())
    }

    /// Вступить по ссылке. `sync_gid` — вступаем по команде своего устройства (объявлять чат не нужно).
    pub(crate) async fn accept_invite(self: &Arc<Self>, link: &str, sync_gid: Option<&str>) -> Result<String> {
        let invite = Invite::decode(link).ok_or(Error::BadInvite)?;
        let conn = self.conn(&invite.node).await?;
        let chat_id = crate::new_id();
        let reply = new_queue(&conn, &chat_id, &invite.node).await?;

        let engine = self.engine.lock().await;
        let bundle = KeyPackage::builder()
            .build(crate::CIPHERSUITE, &engine.provider, &engine.signer, engine.credential.clone())
            .map_err(mls)?;
        let key_package = bundle.key_package().tls_serialize_detached().map_err(mls)?;
        engine.save(&self.store)?;
        drop(engine);

        let title = [&invite.title, &invite.hint]
            .into_iter()
            .find(|t| !t.is_empty())
            .cloned()
            .unwrap_or_else(|| "Подключение…".to_string());
        self.store.insert_chat(&ChatRow {
            id: chat_id.clone(),
            group_id: None,
            title,
            custom_title: false,
            node: invite.node.clone(),
            log_id: vec![],
            write_sk: vec![],
            read_sk: vec![],
            read_offset: 0,
            state: ChatState::Joining,
            created_ms: now_ms(),
            last_ms: now_ms(),
            unread: 0,
            muted: false,
            pinned: false,
        })?;
        if let Some(gid) = sync_gid {
            self.store.set(&synced_key(gid), chat_id.as_bytes())?;
            self.store.set(&quiet_key(&chat_id), b"1")?;
        }
        self.store.insert_queue("joins", &reply)?;
        subscribe_queue(&conn, &reply).await?;

        let body = serde_json::to_vec(&crate::JoinRequest { key_package, reply: reply.sender_id.clone() }).unwrap();
        crate::expect_done(
            conn.request(request::Body::QueueSend(core_proto::msg::QueueSend { sender_id: invite.queue, body }), None)
                .await?,
        )?;
        info!("🤝 join request sent for chat {chat_id}");
        self.notify(None);
        Ok(chat_id)
    }

    pub(crate) fn delete_chat(&self, chat_id: &str) -> Result<()> {
        for m in self.store.messages(chat_id, u32::MAX, None)? {
            if let Some(p) = m.file_path {
                let _ = std::fs::remove_file(p);
            }
        }
        self.store.delete_chat(chat_id)?;
        self.notify(None);
        Ok(())
    }

    pub(crate) fn delete_message_locally(&self, m: &MessageRow) {
        if let Some(p) = &m.file_path {
            let _ = std::fs::remove_file(p);
        }
        let _ = self.store.delete_message(&m.id);
        self.notify(Some(m.chat_id.clone()));
    }

    // ── рассылка своим устройствам ──

    /// «Избранное», если оно уже работает.
    fn saved_row(&self) -> Option<ChatRow> {
        let id = self.saved_id()?;
        self.store.chat(&id).ok().flatten().filter(|c| c.state == ChatState::Active)
    }

    /// Есть ли у аккаунта другие устройства (кроме этого в «Избранном» кто-то есть).
    async fn has_other_devices(&self, saved: &ChatRow) -> bool {
        let engine = self.engine.lock().await;
        engine.group(saved).map(|g| g.members().count() > 1).unwrap_or(false)
    }

    /// Отправить операцию остальным устройствам (в фоне; без других устройств — ничего).
    pub(crate) fn sync(self: &Arc<Self>, op: SyncOp) {
        let inner = self.clone();
        tokio::spawn(async move {
            let Some(saved) = inner.saved_row() else { return };
            if !inner.has_other_devices(&saved).await {
                return;
            }
            if let Err(e) = inner.send_payload(&saved, &Payload::Sync(op)).await {
                warn!("⚠️ sync to other devices failed: {e}");
            }
        });
    }

    pub(crate) fn sync_flags(self: &Arc<Self>, chat_id: &str) {
        let Ok(Some(chat)) = self.store.chat(chat_id) else { return };
        let Some(gid) = chat.group_id.as_deref().map(hex::encode) else { return };
        let archived = self.store.get(&archive_key(chat_id)).ok().flatten().is_some();
        self.sync(SyncOp::ChatFlags { gid, pinned: chat.pinned, muted: chat.muted, archived });
    }

    /// Новый чат на этом устройстве — остальные устройства вступают по ссылке.
    pub(crate) fn announce_chat(self: &Arc<Self>, chat_id: &str) {
        let (inner, chat_id) = (self.clone(), chat_id.to_string());
        tokio::spawn(async move {
            let Some(saved) = inner.saved_row() else { return };
            if saved.id == chat_id || !inner.has_other_devices(&saved).await {
                return;
            }
            let Some(gid) = inner.gid(&chat_id) else { return };
            let result = async {
                let link = inner.invite_link(&chat_id).await?;
                inner.send_payload(&saved, &Payload::SyncChat { link, gid }).await
            }
            .await;
            match result {
                Ok(_) => info!("📣 chat {chat_id} announced to own devices"),
                Err(e) => warn!("⚠️ announcing chat to own devices failed: {e}"),
            }
        });
    }

    /// Другое своё устройство завело чат — вступаем, если ещё не там.
    pub(crate) fn join_synced_chat(self: &Arc<Self>, link: String, gid: String) {
        let inner = self.clone();
        tokio::spawn(async move {
            let known = inner.chat_by_gid(&gid).ok().flatten().is_some()
                || inner.store.get(&synced_key(&gid)).ok().flatten().is_some();
            if known {
                return;
            }
            match inner.accept_invite(&link, Some(&gid)).await {
                Ok(id) => info!("🔁 joining chat {id} created on another device"),
                Err(e) => warn!("⚠️ joining synced chat failed: {e}"),
            }
        });
    }

    pub(crate) fn apply_sync(self: &Arc<Self>, op: SyncOp) -> Result<()> {
        match op {
            SyncOp::ChatFlags { gid, pinned, muted, archived } => {
                if let Some(chat) = self.chat_by_gid(&gid)? {
                    self.store.set_flag(&chat.id, "pinned", pinned)?;
                    self.store.set_flag(&chat.id, "muted", muted)?;
                    if archived {
                        self.store.set(&archive_key(&chat.id), b"1")?;
                    } else {
                        self.store.delete(&archive_key(&chat.id))?;
                    }
                    self.notify(None);
                }
            }
            SyncOp::ReadUpTo { gid, up_to } => {
                if let Some(chat) = self.chat_by_gid(&gid)? {
                    self.store.set_read_up_to(&chat.id, up_to)?;
                    self.notify(None);
                }
            }
            SyncOp::MarkUnread { gid } => {
                if let Some(chat) = self.chat_by_gid(&gid)? {
                    if chat.unread == 0 {
                        self.store.set_unread(&chat.id, 1)?;
                    }
                    self.notify(None);
                }
            }
            SyncOp::DeleteChat { gid } => {
                if let Some(chat) = self.chat_by_gid(&gid)? {
                    if self.saved_id().as_deref() != Some(chat.id.as_str()) {
                        self.delete_chat(&chat.id)?;
                    }
                }
            }
            SyncOp::ClearHistory { gid } => {
                if let Some(chat) = self.chat_by_gid(&gid)? {
                    self.store.clear_history(&chat.id)?;
                    self.notify(Some(chat.id));
                }
            }
            SyncOp::DeleteLocal { gid, id } => {
                if let Some(chat) = self.chat_by_gid(&gid)? {
                    if let Some(m) = self.store.message(&id)?.filter(|m| m.chat_id == chat.id) {
                        self.delete_message_locally(&m);
                    }
                }
            }
            SyncOp::Media { json } => {
                if serde_json::from_str::<crate::MediaSettings>(&json).is_ok() {
                    self.store.set(MEDIA_SETTINGS_KEY, json.as_bytes())?;
                    self.notify(None);
                    self.synced("media");
                }
            }
            SyncOp::App { key, value, ts } => {
                let newer = self.app_setting(&key)?.is_none_or(|(_, old)| ts > old);
                if newer {
                    self.store_app_setting(&key, &value, ts)?;
                    self.synced(&key);
                }
            }
            SyncOp::Device(record) => {
                let known = self.store.get(&device_key(&record.id))?.is_some();
                if record.id != self.device_id() {
                    self.store.set(&device_key(&record.id), &serde_json::to_vec(&record).unwrap())?;
                    self.synced("devices");
                    // Новое для нас устройство ещё не знает о нас — представимся.
                    if !known {
                        self.announce_device();
                    }
                }
            }
            SyncOp::RemoveDevice { id } => {
                if id == self.device_id() {
                    warn!("🚫 this device was removed from the account");
                    self.store.set(DEVICE_REMOVED_KEY, b"1")?;
                    self.synced("removed");
                } else {
                    self.store.delete(&device_key(&id))?;
                    self.synced("devices");
                }
            }
        }
        Ok(())
    }

    fn synced(&self, key: &str) {
        if let Some(l) = self.listener.read().unwrap().clone() {
            l.synced(key.to_string());
        }
    }

    // ── настройки приложения ──

    pub(crate) fn store_app_setting(&self, key: &str, value: &str, ts: u64) -> Result<()> {
        let v = serde_json::to_vec(&(value, ts)).unwrap();
        Ok(self.store.set(&format!("{APP_PREFIX}{key}"), &v)?)
    }

    pub(crate) fn app_setting(&self, key: &str) -> Result<Option<(String, u64)>> {
        Ok(self.store.get(&format!("{APP_PREFIX}{key}"))?.and_then(|v| serde_json::from_slice(&v).ok()))
    }

    // ── устройства ──

    pub(crate) fn device_id(&self) -> String {
        self.store
            .get(DEVICE_ID_KEY)
            .ok()
            .flatten()
            .map(|v| String::from_utf8_lossy(&v).into_owned())
            .unwrap_or_default()
    }

    /// Запись этого устройства (имя и нода — последние, что сообщило приложение).
    pub(crate) fn this_device(&self) -> Result<DeviceRecord> {
        let id = self.device_id();
        let mut record: DeviceRecord =
            self.store.get(&device_key(&id))?.and_then(|v| serde_json::from_slice(&v).ok()).unwrap_or_default();
        record.id = id;
        record.sig =
            self.store.get(DEVICE_SIG_KEY)?.map(|v| String::from_utf8_lossy(&v).into_owned()).unwrap_or_default();
        Ok(record)
    }

    /// Сообщить остальным устройствам о себе (после вступления в «Избранное» и в ответ новичку).
    pub(crate) fn announce_device(self: &Arc<Self>) {
        if let Ok(mut record) = self.this_device() {
            record.ts = now_ms();
            self.sync(SyncOp::Device(record));
        }
    }

    pub(crate) fn devices(&self) -> Result<Vec<Device>> {
        let this = self.device_id();
        let mut out: Vec<Device> = self
            .store
            .get_prefix(DEVICE_PREFIX)?
            .into_iter()
            .filter_map(|(_, v)| serde_json::from_slice::<DeviceRecord>(&v).ok())
            .map(|r| Device {
                is_this: r.id == this,
                id: r.id,
                name: r.name,
                platform: r.platform,
                node: r.node,
                seen_ms: r.ts,
            })
            .collect();
        out.sort_by(|a, b| b.is_this.cmp(&a.is_this).then(b.seen_ms.cmp(&a.seen_ms)));
        Ok(out)
    }

    pub(crate) async fn remove_device(self: &Arc<Self>, device_id: &str) -> Result<()> {
        if device_id == self.device_id() {
            return Err(Error::Other("this device can't remove itself".into()));
        }
        let record: DeviceRecord = self
            .store
            .get(&device_key(device_id))?
            .and_then(|v| serde_json::from_slice(&v).ok())
            .ok_or_else(|| Error::Other("unknown device".into()))?;
        // Сначала команда (пока устройство ещё в «Избранном»), потом — удаление из всех групп.
        if let Some(saved) = self.saved_row() {
            let op = Payload::Sync(SyncOp::RemoveDevice { id: device_id.to_string() });
            if let Err(e) = self.send_payload(&saved, &op).await {
                warn!("⚠️ remove-device notice failed: {e}");
            }
        }
        let sig = hex::decode(&record.sig).unwrap_or_default();
        if !sig.is_empty() {
            for chat in self.store.chats()?.into_iter().filter(|c| c.state == ChatState::Active) {
                if let Err(e) = self.remove_leaves(&chat.id, |m| m.signature_key == sig).await {
                    warn!("⚠️ removing device from chat {} failed: {e}", chat.id);
                }
            }
        }
        self.store.delete(&device_key(device_id))?;
        info!("🗑️ device {device_id} removed");
        self.synced("devices");
        Ok(())
    }

    /// Удалить из группы листья, подходящие под `select` (коммит через compare-and-swap по эпохе).
    pub(crate) async fn remove_leaves(
        self: &Arc<Self>,
        chat_id: &str,
        select: impl Fn(&Member) -> bool,
    ) -> Result<usize> {
        let mut engine = self.engine.lock().await;
        for _attempt in 0..3 {
            let chat = self.store.chat(chat_id)?.ok_or(Error::NoChat)?;
            let mut group = engine.group(&chat)?;
            let own = group.own_leaf_index();
            let indices: Vec<LeafNodeIndex> =
                group.members().filter(|m| m.index != own && select(m)).map(|m| m.index).collect();
            if indices.is_empty() {
                return Ok(0);
            }
            let (commit, _, _) = group.remove_members(&engine.provider, &engine.signer, &indices).map_err(mls)?;
            let conn = self.conn(&chat.node).await?;
            let body = request::Body::LogCommit(LogCommit {
                log_id: chat.log_id.clone(),
                epoch: group.epoch().as_u64(),
                blob: commit.tls_serialize_detached().map_err(mls)?,
            });
            match conn.request(body, Some(&key(&chat.write_sk))).await? {
                response::Body::LogAppended(a) => {
                    self.store.add_own_offset(&chat.id, a.offset)?;
                    group.merge_pending_commit(&engine.provider).map_err(mls)?;
                    engine.save(&self.store)?;
                    self.notify(Some(chat_id.into()));
                    return Ok(indices.len());
                }
                response::Body::CommitConflict(c) => {
                    group.clear_pending_commit(engine.provider.storage()).map_err(mls)?;
                    engine.save(&self.store)?;
                    if let Some(winner) = c.winner {
                        self.process_entry(&mut engine, &chat, winner).await?;
                    }
                }
                other => {
                    group.clear_pending_commit(engine.provider.storage()).map_err(mls)?;
                    engine.save(&self.store)?;
                    return Err(refused(other));
                }
            }
        }
        Err(Error::Other("commit conflicts, giving up".into()))
    }

    // ── связывание: снимок аккаунта ──

    fn snap_chat(&self, row: &ChatRow, link: String) -> Result<SnapChat> {
        let members = self
            .store
            .members(&row.id)?
            .into_iter()
            .filter(|m| m.member_id != self.me)
            .map(|m| SnapMember { id: m.member_id, name: m.name, avatar: m.avatar })
            .collect();
        let messages = self
            .store
            .messages(&row.id, LINK_HISTORY, None)?
            .into_iter()
            .filter(|m| m.status != MessageStatus::Sending && m.status != MessageStatus::Failed)
            .map(|m| SnapMessage {
                reactions: self.store.reactions(&m.id).unwrap_or_default(),
                id: m.id,
                sender: m.sender_id,
                ts: m.ts,
                status: m.status as i64,
                text: m.text,
                att: m.attachment,
                reply_to: m.reply_to,
                link: m.link,
                fwd: m.fwd,
                fwd_id: m.fwd_id,
            })
            .collect();
        Ok(SnapChat {
            link,
            gid: row.group_id.as_deref().map(hex::encode).unwrap_or_default(),
            title: row.title.clone(),
            custom_title: row.custom_title,
            pinned: row.pinned,
            muted: row.muted,
            archived: self.store.get(&archive_key(&row.id))?.is_some(),
            owner: self.store.get(&owner_key(&row.id))?.is_some(),
            unread: row.unread,
            last_ms: row.last_ms,
            members,
            messages,
        })
    }

    /// Новое устройство: разложить снимок по только что заведённому (вступающему) чату.
    fn import_chat(&self, chat_id: &str, c: &SnapChat) -> Result<()> {
        if c.custom_title {
            self.store.set_title(chat_id, &c.title, true)?;
        } else if !c.title.is_empty() {
            self.store.set_title(chat_id, &c.title, false)?;
        }
        self.store.set_flag(chat_id, "pinned", c.pinned)?;
        self.store.set_flag(chat_id, "muted", c.muted)?;
        if c.archived {
            self.store.set(&archive_key(chat_id), b"1")?;
        }
        if c.owner {
            self.store.set(&owner_key(chat_id), b"1")?;
        }
        for m in &c.members {
            self.store.upsert_member(chat_id, &m.id, &m.name, m.avatar.as_deref())?;
        }
        for m in &c.messages {
            let mine = m.sender == self.me;
            self.store.insert_message(&MessageRow {
                id: m.id.clone(),
                chat_id: chat_id.into(),
                sender_id: m.sender.clone(),
                outgoing: mine,
                ts: m.ts,
                text: m.text.clone(),
                attachment: m.att.clone(),
                status: MessageStatus::from_i64(m.status),
                file_path: None,
                reply_to: m.reply_to.clone(),
                link: m.link.clone(),
                fwd: m.fwd.clone(),
                fwd_id: m.fwd_id.clone(),
            })?;
            for (emoji, sender) in &m.reactions {
                self.store.set_reaction(&m.id, sender, Some(emoji), m.ts)?;
            }
        }
        self.store.touch_chat(chat_id, c.last_ms, 0)?;
        self.store.set_unread(chat_id, c.unread)?;
        Ok(())
    }
}

impl Client {
    /// Старое устройство: собрать снимок, отдать его по каналу и дождаться подтверждения.
    pub(crate) async fn link_send(&self, ch: &LinkChannel) -> Result<()> {
        if ch.role() != LinkRole::Existing || ch.peer_name().is_none() {
            return Err(Error::NotReady);
        }
        let inner = &self.inner;
        let saved_id = self.saved_chat().await?;
        let (name, avatar) = match inner.profile_payload()? {
            Payload::Profile { name, avatar } => (name, inner.store.get("profile.avatar")?.or(avatar)),
            _ => (String::new(), None),
        };
        let mut snap = Snapshot {
            name,
            avatar,
            media: inner.store.get(MEDIA_SETTINGS_KEY)?.map(|v| String::from_utf8_lossy(&v).into_owned()),
            app: inner
                .store
                .get_prefix(APP_PREFIX)?
                .into_iter()
                .filter_map(|(k, v)| {
                    let (value, ts): (String, u64) = serde_json::from_slice(&v).ok()?;
                    Some((k[APP_PREFIX.len()..].to_string(), value, ts))
                })
                .collect(),
            ..Default::default()
        };
        for row in inner.store.chats()?.into_iter().filter(|c| c.state == ChatState::Active) {
            let link = match inner.invite_link(&row.id).await {
                Ok(l) => l,
                Err(e) => {
                    warn!("⚠️ link: chat {} skipped: {e}", row.id);
                    continue;
                }
            };
            let chat = inner.snap_chat(&row, link)?;
            if row.id == saved_id {
                snap.saved = Some(chat);
            } else {
                snap.chats.push(chat);
            }
        }
        info!("📦 link snapshot: {} chats", snap.chats.len());

        let path = inner.dir.join(format!("link-{}.json", crate::new_id()));
        std::fs::write(&path, serde_json::to_vec(&snap).unwrap()).map_err(|e| Error::Other(e.to_string()))?;
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let mut att = AttachmentRef {
            kind: "file".into(),
            name: "account.json".into(),
            mime: "application/json".into(),
            size,
            ..Default::default()
        };
        let uploaded = media::upload(&ch.conn, &ch.node, &path, &mut att).await;
        let _ = std::fs::remove_file(&path);
        uploaded?;

        ch.send(&LinkMsg::Account { account_id: inner.me.clone(), snapshot: Box::new(att) }).await?;
        let reply = ch.recv(Duration::from_secs(180)).await;
        ch.close().await;
        match reply? {
            LinkMsg::Linked => {
                info!("✅ device «{}» linked", ch.peer_name().unwrap_or_default());
                Ok(())
            }
            LinkMsg::Declined => Err(Error::Other("Новое устройство отменило подключение".into())),
            other => Err(Error::Other(format!("unexpected link message {other:?}"))),
        }
    }

    /// Новое устройство после связывания: вступить во все чаты аккаунта и разложить историю.
    pub(crate) async fn finish_link(&self) {
        let inner = &self.inner;
        let Ok(Some(path)) = inner.store.get(LINK_PENDING_KEY) else { return };
        // Имя файла в каталоге аккаунта: приложение может перенести каталог целиком после связывания.
        let path = inner.dir.join(String::from_utf8_lossy(&path).as_ref());
        let snap: Snapshot = match std::fs::read(&path).map(|b| serde_json::from_slice(&b)) {
            Ok(Ok(s)) => s,
            _ => {
                warn!("⚠️ link snapshot unreadable — giving up");
                let _ = inner.store.delete(LINK_PENDING_KEY);
                return;
            }
        };
        if let Some(media) = &snap.media {
            let _ = inner.store.set(MEDIA_SETTINGS_KEY, media.as_bytes());
        }
        for (k, v, ts) in &snap.app {
            let _ = inner.store_app_setting(k, v, *ts);
        }
        // «Избранное» — первым: через него идёт вся синхронизация.
        if let Some(saved) = &snap.saved {
            match inner.accept_invite(&saved.link, Some(&saved.gid)).await {
                Ok(id) => {
                    let _ = inner.store.set(SAVED_CHAT_KEY, id.as_bytes());
                    if let Err(e) = inner.import_chat(&id, saved) {
                        warn!("⚠️ saved messages history import failed: {e}");
                    }
                }
                Err(e) => warn!("⚠️ joining saved messages failed: {e}"),
            }
        }
        let mut joined = 0;
        for chat in &snap.chats {
            if inner.chat_by_gid(&chat.gid).ok().flatten().is_some() {
                continue;
            }
            match inner.accept_invite(&chat.link, Some(&chat.gid)).await {
                Ok(id) => {
                    joined += 1;
                    if let Err(e) = inner.import_chat(&id, chat) {
                        warn!("⚠️ history import for chat {id} failed: {e}");
                    }
                }
                Err(e) => warn!("⚠️ joining chat failed: {e}"),
            }
        }
        let _ = inner.store.delete(LINK_PENDING_KEY);
        let _ = std::fs::remove_file(&path);
        info!("✅ link finished: joining {joined} chats");
        inner.notify(None);
        inner.synced("*");
    }

    /// «Избранное», если оно уже есть на этом устройстве (на новом — после вступления).
    pub fn saved_chat_id(&self) -> Option<String> {
        self.inner.saved_id().filter(|id| self.inner.store.chat(id).ok().flatten().is_some())
    }

    /// Это устройство отключили с другого устройства аккаунта.
    pub fn is_removed(&self) -> bool {
        self.inner.store.get(DEVICE_REMOVED_KEY).ok().flatten().is_some()
    }
}

/// Новое устройство (ещё без клиента): принять аккаунт по открытому каналу и подготовить базу в `dir`.
/// Дальше приложение открывает клиент как обычно — он сам вступит во все чаты. Возвращает имя аккаунта.
pub async fn link_receive_account(ch: &LinkChannel, dir: &Path, db_key: Option<&[u8]>) -> Result<String> {
    if ch.role() != LinkRole::New {
        return Err(Error::Other("only a new device receives an account".into()));
    }
    // Показывали QR — сначала дождаться, пока его отсканируют.
    ch.wait_peer(Duration::from_secs(600)).await?;
    let (account_id, snapshot) = loop {
        match ch.recv(Duration::from_secs(600)).await? {
            LinkMsg::Account { account_id, snapshot } => break (account_id, snapshot),
            LinkMsg::Declined => return Err(Error::Other("Подключение отклонено на другом устройстве".into())),
            _ => continue,
        }
    };
    std::fs::create_dir_all(dir.join("media")).map_err(|e| Error::Other(e.to_string()))?;
    let path = dir.join(SNAPSHOT_FILE);
    media::download(&ch.conn, &snapshot, &path).await?;
    let snap: Snapshot = serde_json::from_slice(&std::fs::read(&path).map_err(|e| Error::Other(e.to_string()))?)
        .map_err(|e| Error::Other(format!("bad snapshot: {e}")))?;

    let store = Store::open(&dir.join("client.db"), db_key)?;
    if !store.chats()?.is_empty() {
        let _ = ch.decline().await;
        return Err(Error::Other("На этом устройстве уже есть аккаунт — сначала сбросьте данные".into()));
    }
    store.set("account.id", account_id.as_bytes())?;
    store.set("profile.name", snap.name.trim().as_bytes())?;
    if let Some(a) = &snap.avatar {
        store.set("profile.avatar", a)?;
    }
    store.delete(SAVED_CHAT_KEY)?;
    store.set(LINK_PENDING_KEY, SNAPSHOT_FILE.as_bytes())?;
    drop(store);

    ch.send(&LinkMsg::Linked).await?;
    ch.close().await;
    info!("✅ account received from «{}»", ch.peer_name().unwrap_or_default());
    Ok(snap.name)
}

pub(crate) fn sig_hex(signer: &openmls_basic_credential::SignatureKeyPair) -> String {
    hex::encode(signer.to_public_vec())
}

pub(crate) const SIG_KEY: &str = DEVICE_SIG_KEY;
