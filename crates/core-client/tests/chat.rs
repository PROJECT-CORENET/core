//! Сквозной сценарий с настоящей нодой: приглашение → MLS-группа → сообщения → файл → третий участник.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use core_client::{ChatState, Client, Listener, MessageStatus, OutgoingAttachment};
use core_node::{Config, Node, NodeIdentity, Store};

async fn node() -> String {
    let config = Config { listen: "127.0.0.1:0".into(), ..Config::default() };
    let node = Node::bind(config, NodeIdentity::generate(), Store::open_in_memory().unwrap()).await.unwrap();
    let addr = node.address().to_string();
    tokio::spawn(node.run());
    addr
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while !f() {
        assert!(tokio::time::Instant::now() < deadline, "timeout waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn client(dir: &tempfile::TempDir, name: &str, node: &str) -> Client {
    let c = Client::open(&dir.path().join(name), node).await.unwrap();
    c.set_profile(name, None).await.unwrap();
    c
}

fn texts(c: &Client, chat: &str) -> Vec<String> {
    c.messages(chat, 100, None).unwrap().into_iter().map(|m| m.text).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn invite_chat_files_and_group() {
    let node = node().await;
    let dir = tempfile::tempdir().unwrap();
    let alice = client(&dir, "Alice", &node).await;
    let bob = client(&dir, "Bob", &node).await;

    // Приглашение и вступление.
    let (a_chat, link) = alice.create_chat(None).await.unwrap();
    assert!(link.starts_with("core-invite:"));
    let b_chat = bob.accept_invite(&link).await.unwrap();
    // Под нагрузкой Алиса успевает принять Боба ещё до этой проверки — тогда чат уже активен.
    assert!(matches!(bob.chat(&b_chat).unwrap().state, ChatState::Joining | ChatState::Active));
    eventually("bob joins", || bob.chat(&b_chat).unwrap().state == ChatState::Active).await;

    // Имена приходят внутри MLS: у Алисы чат называется «Bob», у Боба — «Alice».
    eventually("names", || alice.chat(&a_chat).unwrap().title == "Bob" && bob.chat(&b_chat).unwrap().title == "Alice")
        .await;

    // Переписка в обе стороны.
    let preview = core_client::LinkPreview {
        url: "https://example.org/".into(),
        title: "Example".into(),
        desc: "Описание".into(),
        site: "example.org".into(),
        image: Some(vec![7; 100]),
    };
    alice.send_text(&a_chat, "Привет, Боб!", None, Some(preview.clone())).await.unwrap();
    eventually("bob gets message", || texts(&bob, &b_chat) == ["Привет, Боб!"]).await;
    let m = bob.messages(&b_chat, 10, None).unwrap().pop().unwrap();
    assert_eq!(m.link, Some(preview), "link preview travels inside MLS");
    assert!(!m.outgoing);
    assert_eq!(m.sender_name, "Alice");
    assert_eq!(bob.chat(&b_chat).unwrap().unread, 1);
    // Отчёт о доставке: сообщение дошло до устройства Боба, но ещё не прочитано.
    eventually("delivery receipt", || alice.messages(&a_chat, 10, None).unwrap()[0].status == MessageStatus::Delivered)
        .await;

    // «Печатает…»: Алиса набирает — у Боба приходит событие с её id и видом действия.
    struct TypingSpy(Mutex<Vec<(String, String)>>);
    impl Listener for TypingSpy {
        fn changed(&self, _: Option<String>) {}
        fn typing(&self, chat_id: String, _member: String, kind: String) {
            self.0.lock().unwrap().push((chat_id, kind));
        }
    }
    let spy = Arc::new(TypingSpy(Mutex::default()));
    bob.set_listener(spy.clone());
    alice.send_typing(&a_chat, "voice").await.unwrap();
    eventually("typing event", || spy.0.lock().unwrap().contains(&(b_chat.clone(), "voice".to_string()))).await;
    assert_eq!(texts(&bob, &b_chat), ["Привет, Боб!"], "typing is not a message");

    let alice_spy = Arc::new(TypingSpy(Mutex::default()));
    alice.set_listener(alice_spy.clone());
    alice.set_presence(true);
    bob.set_presence(true);
    eventually("bob appears online without a message", || {
        alice_spy.0.lock().unwrap().iter().any(|(id, kind)| id == &a_chat && kind.starts_with("online:"))
    })
    .await;
    bob.set_presence(false);
    eventually("bob goes offline without a message", || {
        alice_spy.0.lock().unwrap().iter().any(|(id, kind)| id == &a_chat && kind.starts_with("offline:"))
    })
    .await;
    assert_eq!(texts(&bob, &b_chat), ["Привет, Боб!"], "presence is not a message");
    alice.set_presence(false);

    // Архив: чат прячется, а новое сообщение возвращает его (чат не заглушён).
    alice.set_archived(&a_chat, true).unwrap();
    assert!(alice.chat(&a_chat).unwrap().archived);

    bob.send_text(&b_chat, "Привет!", None, None).await.unwrap();
    eventually("alice gets reply", || texts(&alice, &a_chat) == ["Привет, Боб!", "Привет!"]).await;
    assert!(!alice.chat(&a_chat).unwrap().archived, "new message brings the chat back from the archive");

    // Отчёт о прочтении: Боб открыл чат → у Алисы её сообщение «прочитано».
    bob.mark_read(&b_chat).await.unwrap();
    assert_eq!(bob.chat(&b_chat).unwrap().unread, 0);
    eventually("read receipt", || alice.messages(&a_chat, 10, None).unwrap()[0].status == MessageStatus::Read).await;

    assert!(alice.chat(&a_chat).unwrap().peer_read_ms > 0);
    assert_eq!(bob.chat(&b_chat).unwrap().peer_read_ms, 0);

    // Пересылка: у получателя видно, от кого оригинал.
    let karl = "ab".repeat(32);
    bob.forward_text(&b_chat, "Встреча в 7", None, "Карл", Some(karl.clone())).await.unwrap();
    eventually("alice gets forward", || {
        alice.messages(&a_chat, 10, None).unwrap().last().is_some_and(|m| m.text == "Встреча в 7")
    })
    .await;
    let fwd = alice.messages(&a_chat, 10, None).unwrap().pop().unwrap();
    assert_eq!(fwd.forwarded_from.as_deref(), Some("Карл"));
    assert_eq!(fwd.forwarded_from_id.as_deref(), Some(karl.as_str()), "author key travels for the profile link");
    assert_eq!(bob.messages(&b_chat, 10, None).unwrap().pop().unwrap().forwarded_from.as_deref(), Some("Карл"));
    // Реакции: у обоих одна общая сводка, повторная заменяет, пустая — снимает.
    let fwd_id = fwd.id.clone();
    let b_fwd = bob.messages(&b_chat, 10, None).unwrap().into_iter().find(|m| m.id == fwd_id).unwrap();
    alice.react(&fwd_id, Some("🔥")).await.unwrap();
    bob.react(&b_fwd.id, Some("🔥")).await.unwrap();
    let reactions = |c: &Client, chat: &str| {
        c.messages(chat, 10, None).unwrap().into_iter().find(|m| m.id == fwd_id).unwrap().reactions
    };
    eventually("both reactions", || reactions(&alice, &a_chat).first().is_some_and(|r| r.count == 2)).await;
    assert!(reactions(&alice, &a_chat)[0].mine);
    assert_eq!(reactions(&alice, &a_chat)[0].senders.len(), 2, "who reacted is visible");
    alice.react(&fwd_id, Some("👍")).await.unwrap();
    eventually("reaction replaced", || reactions(&bob, &b_chat).len() == 2).await;
    alice.react(&fwd_id, None).await.unwrap();
    eventually("reaction removed", || {
        let r = reactions(&bob, &b_chat);
        r.len() == 1 && r[0].emoji == "🔥" && r[0].mine
    })
    .await;

    // Скрытый автор: ключ не похож на ключ — его отбрасывают, остаётся только имя.
    bob.forward_text(&b_chat, "Без ключа", None, "Карл", Some("не ключ".into())).await.unwrap();
    assert_eq!(bob.messages(&b_chat, 10, None).unwrap().pop().unwrap().forwarded_from_id, None);

    // Файл 300 КБ: шифруется, уходит кусками, скачивается и совпадает побайтно.
    let data: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 251) as u8).collect();
    let src = dir.path().join("photo.jpg");
    std::fs::write(&src, &data).unwrap();
    let att = OutgoingAttachment {
        path: src.to_string_lossy().into(),
        kind: "photo".into(),
        name: "photo.jpg".into(),
        mime: "image/jpeg".into(),
        thumb: Some(vec![1, 2, 3]),
        notification_thumb: None,
        width: 800,
        height: 600,
        spoiler: true,
        spoiler_hearts: true,
        ..Default::default()
    };
    alice.send_attachment(&a_chat, att, "Смотри").await.unwrap();
    eventually("bob downloads photo", || {
        bob.messages(&b_chat, 10, None).unwrap().last().is_some_and(|m| m.local_path.is_some())
    })
    .await;
    let m = bob.messages(&b_chat, 10, None).unwrap().pop().unwrap();
    assert_eq!(m.text, "Смотри");
    let a = m.attachment.unwrap();
    assert_eq!((a.kind.as_str(), a.w, a.h, a.size), ("photo", 800, 600, 300_000));
    assert_eq!(a.thumb.as_deref(), Some(&[1u8, 2, 3][..]));
    assert!(a.spoiler, "spoiler flag survives MLS");
    assert!(a.spoiler_hearts, "heart spoiler style survives MLS");
    assert_eq!(std::fs::read(m.local_path.unwrap()).unwrap(), data);
    assert!(bob.storage_usage().unwrap().photos >= 300_000);

    // Лимит кэша: лишние файлы удаляются (сообщение остаётся, файл можно скачать снова).
    assert_eq!(bob.media_settings(), core_client::MediaSettings::default());
    let tight = core_client::MediaSettings { cache_limit_bytes: 1_000, ..Default::default() };
    bob.set_media_settings(&tight).unwrap();
    assert_eq!(bob.media_settings(), tight);
    assert_eq!(bob.storage_usage().unwrap().photos, 0);
    assert!(bob.messages(&b_chat, 10, None).unwrap().last().unwrap().local_path.is_none());
    bob.set_media_settings(&core_client::MediaSettings::default()).unwrap();
    let path = bob.download(&m.id).await.unwrap();
    assert_eq!(std::fs::read(path).unwrap(), data);

    // Третий участник по ссылке Боба: коммит идёт через журнал, Алиса его применяет.
    let carol = client(&dir, "Carol", &node).await;
    let link2 = bob.invite_link(&b_chat).await.unwrap();
    let c_chat = carol.accept_invite(&link2).await.unwrap();
    eventually("carol joins", || carol.chat(&c_chat).unwrap().state == ChatState::Active).await;
    eventually("group of three", || {
        alice.chat(&a_chat).unwrap().members.len() == 3 && carol.chat(&c_chat).unwrap().members.len() == 3
    })
    .await;
    assert!(alice.chat(&a_chat).unwrap().is_group);

    carol.send_text(&c_chat, "Всем привет", None, None).await.unwrap();
    eventually("everyone gets carol", || {
        texts(&alice, &a_chat).last().map(String::as_str) == Some("Всем привет")
            && texts(&bob, &b_chat).last().map(String::as_str) == Some("Всем привет")
    })
    .await;
    // Кэрол не видит переписку до своего вступления (forward secrecy MLS).
    assert_eq!(texts(&carol, &c_chat), ["Всем привет"]);

    alice.send_text(&a_chat, "Добро пожаловать, Кэрол", None, None).await.unwrap();
    eventually("carol gets alice", || texts(&carol, &c_chat).len() == 2).await;

    // Удаление у всех.
    let id = alice.messages(&a_chat, 1, None).unwrap()[0].id.clone();
    alice.delete_message_for_all(&id).await.unwrap();
    eventually("deleted everywhere", || texts(&carol, &c_chat) == ["Всем привет"]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn edit_text_and_caption() {
    let node = node().await;
    let dir = tempfile::tempdir().unwrap();
    let alice = client(&dir, "Alice", &node).await;
    let bob = client(&dir, "Bob", &node).await;
    let (a_chat, link) = alice.create_chat(None).await.unwrap();
    let b_chat = bob.accept_invite(&link).await.unwrap();
    eventually("bob joins", || bob.chat(&b_chat).unwrap().state == ChatState::Active).await;
    let id = alice.send_text(&a_chat, "original", None, None).await.unwrap();
    eventually("original received", || texts(&bob, &b_chat) == ["original"]).await;
    let original = bob.messages(&b_chat, 10, None).unwrap()[0].clone();
    assert!(bob.edit_message(&id, "forged").await.is_err());
    assert!(alice.edit_message(&id, "\u{2003}\n").await.is_err());
    assert!(alice.edit_message(&id, &"x".repeat(20_000)).await.is_err());
    assert_eq!(texts(&alice, &a_chat), ["original"], "failed edit must not change local text");
    alice.edit_message(&id, "**edited**").await.unwrap();
    eventually("edit received", || texts(&bob, &b_chat) == ["**edited**"]).await;
    let edited = bob.messages(&b_chat, 10, None).unwrap()[0].clone();
    assert!(edited.edited_ms > 0);
    assert_eq!(edited.id, original.id);
    assert_eq!(edited.ts, original.ts);
    assert_eq!(bob.chat(&b_chat).unwrap().unread, 1, "edit is not a new unread message");
    assert_eq!(bob.chat(&b_chat).unwrap().last_message.unwrap().text, "**edited**");
    let src = dir.path().join("data.bin");
    std::fs::write(&src, b"attachment").unwrap();
    let att = OutgoingAttachment {
        path: src.to_string_lossy().into_owned(),
        kind: "file".into(),
        name: "data.bin".into(),
        mime: "application/octet-stream".into(),
        ..Default::default()
    };
    let media_id = alice.send_attachment(&a_chat, att, "caption").await.unwrap();
    eventually("media received", || texts(&bob, &b_chat).len() == 2).await;
    alice.edit_message(&media_id, "").await.unwrap();
    eventually("caption removed", || {
        bob.messages(&b_chat, 10, None).unwrap().last().is_some_and(|m| m.text.is_empty() && m.edited_ms > 0)
    })
    .await;
    let media = bob.messages(&b_chat, 10, None).unwrap().pop().unwrap();
    assert!(media.attachment.is_some());
    let path = bob.download(&media_id).await.unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"attachment");
    drop(bob);
    let bob = Client::open(&dir.path().join("Bob"), &node).await.unwrap();
    assert_eq!(texts(&bob, &b_chat), ["**edited**", ""]);
    assert!(bob.messages(&b_chat, 10, None).unwrap().iter().all(|m| m.edited_ms > 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn state_survives_restart() {
    let node = node().await;
    let dir = tempfile::tempdir().unwrap();
    let alice = client(&dir, "Alice", &node).await;
    let bob = client(&dir, "Bob", &node).await;
    let (a_chat, link) = alice.create_chat(Some("Проект")).await.unwrap();
    let b_chat = bob.accept_invite(&link).await.unwrap();
    eventually("bob joins", || bob.chat(&b_chat).unwrap().state == ChatState::Active).await;
    eventually("title", || bob.chat(&b_chat).unwrap().title == "Проект").await;
    // «Избранное»: один участник, свой журнал, одно на аккаунт.
    let saved = alice.saved_chat().await.unwrap();
    assert_eq!(alice.saved_chat().await.unwrap(), saved);
    let info = alice.chat(&saved).unwrap();
    assert!(info.is_saved && !info.is_group && !info.can_invite);
    assert_eq!(info.title, "Избранное");
    assert!(alice.invite_link(&saved).await.is_err());
    alice.send_text(&saved, "Заметка", None, None).await.unwrap();
    assert_eq!(texts(&alice, &saved), ["Заметка"]);
    let alice_id = alice.profile().unwrap().id;
    drop(alice);

    // Перезапуск Алисы: ключи MLS и аккаунт читаются с диска, переписка продолжается.
    let alice = Client::open(&dir.path().join("Alice"), &node).await.unwrap();
    assert_eq!(alice.profile().unwrap().id, alice_id);
    assert_eq!(alice.profile().unwrap().name, "Alice");
    assert_eq!(alice.saved_chat().await.unwrap(), saved);
    assert_eq!(texts(&alice, &saved), ["Заметка"]);
    bob.send_text(&b_chat, "Ты тут?", None, None).await.unwrap();
    eventually("alice after restart", || texts(&alice, &a_chat) == ["Ты тут?"]).await;
    alice.send_text(&a_chat, "Да!", None, None).await.unwrap();
    eventually("bob gets answer", || texts(&bob, &b_chat) == ["Ты тут?", "Да!"]).await;
}

/// Нода в собственном рантайме — чтобы в тесте её можно было «уронить» целиком.
fn killable_node() -> (String, tokio::runtime::Runtime) {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let addr = rt.block_on(async {
            let config = Config { listen: "127.0.0.1:0".into(), ..Config::default() };
            let node = Node::bind(config, NodeIdentity::generate(), Store::open_in_memory().unwrap()).await.unwrap();
            let addr = node.address().to_string();
            tokio::spawn(node.run());
            addr
        });
        (addr, rt)
    })
    .join()
    .unwrap()
}

fn member_ids(c: &Client, chat: &str) -> Vec<String> {
    let mut ids: Vec<String> = c.chat(chat).unwrap().members.into_iter().map(|m| m.name).collect();
    ids.sort();
    ids
}

#[tokio::test(flavor = "multi_thread")]
async fn group_remove_and_leave() {
    let node = node().await;
    let dir = tempfile::tempdir().unwrap();
    let alice = client(&dir, "Alice", &node).await;
    let bob = client(&dir, "Bob", &node).await;
    let carol = client(&dir, "Carol", &node).await;

    let (a_chat, link) = alice.create_chat(Some("Команда")).await.unwrap();
    let a = alice.chat(&a_chat).unwrap();
    assert!(a.is_group && a.is_owner);
    let b_chat = bob.accept_invite(&link).await.unwrap();
    eventually("bob joins", || bob.chat(&b_chat).unwrap().state == ChatState::Active).await;
    let c_chat = carol.accept_invite(&link).await.unwrap();
    eventually("carol joins", || carol.chat(&c_chat).unwrap().state == ChatState::Active).await;
    eventually("everyone sees three", || {
        member_ids(&alice, &a_chat).len() == 3 && member_ids(&bob, &b_chat).len() == 3
    })
    .await;
    assert!(!bob.chat(&b_chat).unwrap().is_owner);

    // Алиса удаляет Кэрол: у Кэрол чат закрыт, у остальных её больше нет.
    let carol_id = alice.chat(&a_chat).unwrap().members.into_iter().find(|m| m.name == "Carol").unwrap().id;
    alice.remove_member(&a_chat, &carol_id).await.unwrap();
    eventually("carol removed", || carol.chat(&c_chat).unwrap().state == ChatState::Left).await;
    eventually("bob sees removal", || member_ids(&bob, &b_chat) == ["Alice", "Bob"]).await;
    assert_eq!(member_ids(&alice, &a_chat), ["Alice", "Bob"]);

    // Переписка продолжается без Кэрол.
    alice.send_text(&a_chat, "без Кэрол", None, None).await.unwrap();
    eventually("bob still gets messages", || texts(&bob, &b_chat).contains(&"без Кэрол".to_string())).await;

    // Боб выходит сам: чат у него удалён, Алиса удаляет его коммитом.
    bob.leave_chat(&b_chat).await.unwrap();
    assert!(bob.chat(&b_chat).is_err());
    eventually("alice processes leave", || member_ids(&alice, &a_chat) == ["Alice"]).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn chat_survives_its_node() {
    // Чат живёт на отдельной ноде (например, семейной); оба участника знают основную сеть.
    let (family, family_rt) = killable_node();
    let main = node().await;
    let dir = tempfile::tempdir().unwrap();
    let alice = client(&dir, "Alice", &family).await;
    let bob = client(&dir, "Bob", &family).await;
    for c in [&alice, &bob] {
        c.set_failover_after(Duration::from_millis(500));
    }

    let (a_chat, link) = alice.create_chat(None).await.unwrap();
    let b_chat = bob.accept_invite(&link).await.unwrap();
    eventually("bob joins", || bob.chat(&b_chat).unwrap().state == ChatState::Active).await;

    // Резервный журнал на основной сети: заводит Алиса, ключи Боб получает внутри MLS.
    alice.set_backup_nodes(vec![main.clone()]);
    alice.ensure_mirrors().await;
    assert_eq!(alice.chat(&a_chat).unwrap().backup_node.as_deref(), Some(main.as_str()));
    eventually("bob knows the mirror", || bob.chat(&b_chat).unwrap().backup_node.as_deref() == Some(main.as_str()))
        .await;
    alice.send_text(&a_chat, "до падения", None, None).await.unwrap();
    eventually("before", || texts(&bob, &b_chat) == ["до падения"]).await;

    // Единственная нода сети падает.
    family_rt.shutdown_background();
    eventually("alice moves", || alice.chat(&a_chat).unwrap().node == main).await;
    eventually("bob moves", || bob.chat(&b_chat).unwrap().node == main).await;

    // Чат жив: переписка идёт через основную сеть в обе стороны.
    alice.send_text(&a_chat, "после падения", None, None).await.unwrap();
    eventually("bob gets it", || texts(&bob, &b_chat).ends_with(&["после падения".to_string()])).await;
    bob.send_text(&b_chat, "живём!", None, None).await.unwrap();
    eventually("alice gets reply", || texts(&alice, &a_chat).ends_with(&["живём!".to_string()])).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn group_survives_its_node() {
    // Группа из трёх на отдельной ноде; все знают основную сеть.
    let (family, family_rt) = killable_node();
    let main = node().await;
    let dir = tempfile::tempdir().unwrap();
    let alice = client(&dir, "Alice", &family).await;
    let bob = client(&dir, "Bob", &family).await;
    let carol = client(&dir, "Carol", &family).await;
    for c in [&alice, &bob, &carol] {
        c.set_failover_after(Duration::from_millis(500));
    }

    let (a_chat, link) = alice.create_chat(Some("Семья")).await.unwrap();
    let b_chat = bob.accept_invite(&link).await.unwrap();
    eventually("bob joins", || bob.chat(&b_chat).unwrap().state == ChatState::Active).await;
    let c_chat = carol.accept_invite(&link).await.unwrap();
    eventually("carol joins", || carol.chat(&c_chat).unwrap().state == ChatState::Active).await;
    eventually("everyone sees three", || {
        [(&alice, &a_chat), (&bob, &b_chat), (&carol, &c_chat)]
            .iter()
            .all(|(c, id)| c.chat(id).unwrap().members.len() == 3)
    })
    .await;

    alice.set_backup_nodes(vec![main.clone()]);
    alice.ensure_mirrors().await;
    for (c, id) in [(&bob, &b_chat), (&carol, &c_chat)] {
        eventually("mirror known", || c.chat(id).unwrap().backup_node.as_deref() == Some(main.as_str())).await;
    }

    family_rt.shutdown_background();
    for (c, id) in [(&alice, &a_chat), (&bob, &b_chat), (&carol, &c_chat)] {
        eventually("moves to the mirror", || c.chat(id).unwrap().node == main).await;
    }

    // Все трое на основной сети, сообщения доходят до каждого.
    carol.send_text(&c_chat, "все здесь?", None, None).await.unwrap();
    eventually("alice gets it", || texts(&alice, &a_chat).ends_with(&["все здесь?".to_string()])).await;
    eventually("bob gets it", || texts(&bob, &b_chat).ends_with(&["все здесь?".to_string()])).await;
    bob.send_text(&b_chat, "да", None, None).await.unwrap();
    eventually("carol gets reply", || texts(&carol, &c_chat).ends_with(&["да".to_string()])).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn database_encryption() {
    let node = node().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("acc");
    let key = [7u8; 32];

    // Старая открытая база…
    {
        let c = Client::open(&path, &node).await.unwrap();
        c.set_profile("Алиса", None).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let raw = std::fs::read(path.join("client.db")).unwrap();
    assert!(raw.starts_with(b"SQLite format 3"));

    // …шифруется при первом открытии с ключом, данные на месте.
    {
        let c = Client::open_with_key(&path, &node, Some(&key)).await.unwrap();
        assert_eq!(c.profile().unwrap().name, "Алиса");
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let raw = std::fs::read(path.join("client.db")).unwrap();
    assert!(!raw.starts_with(b"SQLite format 3"), "file must be encrypted");
    assert!(!raw.windows("Алиса".len()).any(|w| w == "Алиса".as_bytes()));

    // Без ключа или с чужим ключом — не открыть.
    assert!(Client::open(&path, &node).await.is_err());
    assert!(Client::open_with_key(&path, &node, Some(&[8u8; 32])).await.is_err());
    let c = Client::open_with_key(&path, &node, Some(&key)).await.unwrap();
    assert_eq!(c.profile().unwrap().name, "Алиса");
}

/// Нода, которую можно уронить и поднять заново: тот же ключ, порт и база на диске.
fn restartable_node(identity: &NodeIdentity, db: &std::path::Path, port: u16) -> (String, tokio::runtime::Runtime) {
    let (identity, db) = (identity.clone(), db.to_path_buf());
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let addr = rt.block_on(async {
            let config = Config { listen: format!("127.0.0.1:{port}"), ..Config::default() };
            let node = Node::bind(config, identity, Store::open(&db).unwrap()).await.unwrap();
            let addr = node.address().to_string();
            tokio::spawn(node.run());
            addr
        });
        (addr, rt)
    })
    .join()
    .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn retry_failed_message() {
    let dir = tempfile::tempdir().unwrap();
    let identity = NodeIdentity::generate();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let db = dir.path().join("node.db");
    let (node, rt) = restartable_node(&identity, &db, port);

    let alice = client(&dir, "Alice", &node).await;
    let bob = client(&dir, "Bob", &node).await;
    let (a_chat, link) = alice.create_chat(None).await.unwrap();
    let b_chat = bob.accept_invite(&link).await.unwrap();
    eventually("bob joins", || alice.chat(&a_chat).unwrap().title == "Bob").await;

    // Нода упала — сообщение остаётся у Алисы с ошибкой, а не «отправляется» вечно.
    rt.shutdown_background();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(alice.send_text(&a_chat, "Ты тут?", None, None).await.is_err());
    let failed = alice.messages(&a_chat, 10, None).unwrap().pop().unwrap();
    assert_eq!(failed.status, MessageStatus::Failed);
    assert!(alice.retry_message(&failed.id).await.is_err(), "node is still down");
    assert_eq!(alice.messages(&a_chat, 10, None).unwrap().pop().unwrap().status, MessageStatus::Failed);

    // Нода вернулась — повтор доходит, у Боба сообщение одно (без дубликатов).
    let (_, rt) = restartable_node(&identity, &db, port);
    let mut sent = false;
    for _ in 0..100 {
        if alice.retry_message(&failed.id).await.is_ok() {
            sent = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(sent, "retry after the node is back");
    eventually("bob gets it once", || texts(&bob, &b_chat) == ["Ты тут?"]).await;
    assert_ne!(alice.messages(&a_chat, 10, None).unwrap().pop().unwrap().status, MessageStatus::Failed);
    // Повтор отправленного — ничего не делает.
    alice.retry_message(&failed.id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(texts(&bob, &b_chat), ["Ты тут?"]);
    rt.shutdown_background();
}

#[tokio::test(flavor = "multi_thread")]
async fn shared_message_handoff_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let identity = NodeIdentity::generate();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let db = dir.path().join("node.db");
    let (node, rt) = restartable_node(&identity, &db, port);
    let alice = client(&dir, "Alice", &node).await;
    let bob = client(&dir, "Bob", &node).await;
    let (a_chat, link) = alice.create_chat(None).await.unwrap();
    let b_chat = bob.accept_invite(&link).await.unwrap();
    eventually("bob joins", || alice.chat(&a_chat).unwrap().title == "Bob").await;

    let id = "a1234567890123456789012345678901";
    alice.accept_shared(&a_chat, id.into(), "Shared link", None).await.unwrap();
    alice.accept_shared(&a_chat, id.into(), "Shared link", None).await.unwrap();
    eventually("bob receives share", || texts(&bob, &b_chat) == ["Shared link"]).await;
    assert_eq!(alice.messages(&a_chat, 10, None).unwrap().iter().filter(|m| m.id == id).count(), 1);
    rt.shutdown_background();
}

#[tokio::test(flavor = "multi_thread")]
async fn blocked_member_is_ignored() {
    let node = node().await;
    let dir = tempfile::tempdir().unwrap();
    let alice = client(&dir, "Alice", &node).await;
    let bob = client(&dir, "Bob", &node).await;
    let (a_chat, link) = alice.create_chat(None).await.unwrap();
    let b_chat = bob.accept_invite(&link).await.unwrap();
    eventually("bob joins", || alice.chat(&a_chat).unwrap().title == "Bob").await;
    let bob_id = alice.chat(&a_chat).unwrap().members.into_iter().find(|m| !m.is_me).unwrap().id;

    // Заблокировали — его сообщения не приходят.
    alice.set_app_setting(core_client::BLOCKED_KEY, &serde_json::to_string(&[&bob_id]).unwrap()).unwrap();
    bob.send_text(&b_chat, "Спам", None, None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(texts(&alice, &a_chat).is_empty(), "blocked message is dropped");

    // Разблокировали — снова приходят; сам он писать мог всё время.
    alice.set_app_setting(core_client::BLOCKED_KEY, "[]").unwrap();
    bob.send_text(&b_chat, "Привет", None, None).await.unwrap();
    eventually("message after unblock", || texts(&alice, &a_chat) == ["Привет"]).await;
}

/// Шпион звонков: изменения и пришедшие кадры.
#[derive(Default)]
struct CallSpy {
    changed: Mutex<Vec<String>>,
    media: Mutex<Vec<(u8, Vec<u8>)>>,
}

impl Listener for CallSpy {
    fn changed(&self, _: Option<String>) {}
    fn call_changed(&self, call_id: String) {
        self.changed.lock().unwrap().push(call_id);
    }
    fn call_media(&self, _call: String, _peer: String, kind: u8, data: Vec<u8>) {
        self.media.lock().unwrap().push((kind, data));
    }
}

/// Личный звонок: вызов → звонит у собеседника → ответ → звук и видео (большой кадр режется и
/// собирается) → микрофон выключен → конец у обоих, история одинаковая; отклонённый вызов.
#[tokio::test(flavor = "multi_thread")]
async fn direct_call() {
    use core_client::call_media;
    let node = node().await;
    let dir = tempfile::tempdir().unwrap();
    let alice = client(&dir, "Alice", &node).await;
    let bob = client(&dir, "Bob", &node).await;
    let (a_chat, link) = alice.create_chat(None).await.unwrap();
    let b_chat = bob.accept_invite(&link).await.unwrap();
    eventually("bob joins", || bob.chat(&b_chat).unwrap().state == ChatState::Active).await;
    eventually("names", || alice.chat(&a_chat).unwrap().title == "Bob").await;
    let (a_spy, b_spy) = (Arc::new(CallSpy::default()), Arc::new(CallSpy::default()));
    alice.set_listener(a_spy.clone());
    bob.set_listener(b_spy.clone());

    let id = alice.start_call(&a_chat, true).await.unwrap();
    assert_eq!(alice.call(&id).unwrap().state, "outgoing");
    eventually("bob rings", || bob.call(&id).is_ok_and(|c| c.state == "ringing")).await;
    let ring = bob.call(&id).unwrap();
    assert!(!ring.outgoing && ring.video && !ring.group && ring.chat_id == b_chat);

    bob.accept_call(&id).await.unwrap();
    eventually("alice sees answer", || alice.call(&id).unwrap().state == "active").await;
    eventually("peers see each other", || {
        alice.call_peers(&id).len() == 1 && bob.call_peers(&id).first().is_some_and(|p| p.mic && p.cam)
    })
    .await;

    // Звук и большой ключевой кадр видео (несколько частей) доходят целиком.
    let frame: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
    alice.call_send(&id, call_media::AUDIO, b"opus-packet");
    alice.call_send(&id, call_media::VIDEO_KEY, &frame);
    eventually("media arrives", || {
        let m = b_spy.media.lock().unwrap();
        m.contains(&(call_media::AUDIO, b"opus-packet".to_vec())) && m.contains(&(call_media::VIDEO_KEY, frame.clone()))
    })
    .await;

    // Боб выключил микрофон — Алиса видит.
    bob.set_call_media(&id, false, true);
    eventually("mute visible", || alice.call_peers(&id).first().is_some_and(|p| !p.mic)).await;

    alice.end_call(&id).await.unwrap();
    eventually("bob sees end", || bob.call(&id).unwrap().state == "ended").await;
    assert_eq!(alice.call(&id).unwrap().result, "answered");
    assert_eq!(bob.call(&id).unwrap().result, "answered");
    assert!(bob.call_peers(&id).is_empty());
    assert_eq!(bob.calls(10).unwrap().len(), 1, "history on both sides");

    // Отклонённый вызов: у звонящего «отклонён», у обоих в истории.
    let id2 = bob.start_call(&b_chat, false).await.unwrap();
    eventually("alice rings", || alice.call(&id2).is_ok_and(|c| c.state == "ringing")).await;
    alice.decline_call(&id2).await.unwrap();
    eventually("bob sees decline", || bob.call(&id2).unwrap().result == "declined").await;
    assert_eq!(bob.call(&id2).unwrap().state, "ended");
    assert_eq!(alice.calls(10).unwrap().len(), 2);
    alice.hide_calls(std::slice::from_ref(&id2)).unwrap();
    assert_eq!(alice.calls(10).unwrap().len(), 1);
    assert!(!a_spy.changed.lock().unwrap().is_empty());
}
