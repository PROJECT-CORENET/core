//! Несколько устройств одного аккаунта: связывание по QR (устройства на разных нодах),
//! сообщения на все устройства, синхронизация прочтений, флагов, новых чатов, настроек и отключение.

use std::time::Duration;

use core_client::{link_receive_account, ChatState, Client, LinkChannel, LinkRole};
use core_node::{Config, Node, NodeIdentity, Store};

async fn node() -> String {
    let config = Config { listen: "127.0.0.1:0".into(), ..Config::default() };
    let node = Node::bind(config, NodeIdentity::generate(), Store::open_in_memory().unwrap()).await.unwrap();
    let addr = node.address().to_string();
    tokio::spawn(node.run());
    addr
}

async fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !f() {
        assert!(tokio::time::Instant::now() < deadline, "timeout waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn texts(c: &Client, chat: &str) -> Vec<String> {
    c.messages(chat, 100, None).unwrap().into_iter().map(|m| m.text).collect()
}

/// Чат на устройстве по общему group id.
fn by_gid(c: &Client, gid: &str) -> Option<String> {
    c.chats().unwrap().into_iter().find(|ch| ch.gid.as_deref() == Some(gid)).map(|ch| ch.id)
}

#[tokio::test(flavor = "multi_thread")]
async fn second_device_full_sync() {
    // Телефон и собеседник — на одной ноде, новое устройство (Mac) — на другой.
    let (node_a, node_b) = (node().await, node().await);
    let dir = tempfile::tempdir().unwrap();
    let phone = Client::open(&dir.path().join("phone"), &node_a).await.unwrap();
    phone.set_profile("Alice", None).await.unwrap();
    let bob = Client::open(&dir.path().join("bob"), &node_a).await.unwrap();
    bob.set_profile("Bob", None).await.unwrap();
    phone.saved_chat().await.unwrap();

    let (p_chat, link) = phone.create_chat(None).await.unwrap();
    let b_chat = bob.accept_invite(&link).await.unwrap();
    eventually("bob joins", || bob.chat(&b_chat).unwrap().state == ChatState::Active).await;
    let history_id = bob.send_text(&b_chat, "original history", None, None).await.unwrap();
    eventually("phone gets original history", || texts(&phone, &p_chat) == ["original history"]).await;
    bob.edit_message(&history_id, "до связывания").await.unwrap();
    eventually("phone gets history", || texts(&phone, &p_chat) == ["до связывания"]).await;
    phone.set_pinned(&p_chat, true).unwrap();
    phone.set_app_setting("folders", r#"[{"name":"Работа"}]"#).unwrap();
    let gid = phone.chat(&p_chat).unwrap().gid.unwrap();

    // Mac показывает QR, телефон сканирует, подтверждает и отдаёт аккаунт.
    let mac_ch = LinkChannel::offer(&node_b, LinkRole::New, "MacBook").await.unwrap();
    let qr = mac_ch.qr().unwrap();
    let phone_ch = LinkChannel::scan(&qr, LinkRole::Existing, "iPhone").await.unwrap();
    assert_eq!(phone_ch.peer_name().as_deref(), Some("MacBook"));
    assert!(LinkChannel::scan(&qr, LinkRole::New, "x").await.is_err(), "two new devices can't link");
    let mac_dir = dir.path().join("mac");
    let (received, sent) =
        tokio::join!(link_receive_account(&mac_ch, &mac_dir, None), phone.link_send_account(&phone_ch));
    assert_eq!(received.unwrap(), "Alice");
    sent.unwrap();

    let mac = Client::open(&mac_dir, &node_b).await.unwrap();
    assert_eq!(mac.profile().unwrap().id, phone.profile().unwrap().id, "same account");
    assert_eq!(mac.profile().unwrap().name, "Alice");
    eventually("mac joins the chat", || {
        by_gid(&mac, &gid).is_some_and(|id| mac.chat(&id).unwrap().state == ChatState::Active)
    })
    .await;
    let m_chat = by_gid(&mac, &gid).unwrap();
    assert_eq!(texts(&mac, &m_chat), ["до связывания"], "history came with the snapshot");
    assert!(mac.messages(&m_chat, 10, None).unwrap()[0].edited_ms > 0, "snapshot retains edits");
    assert!(mac.chat(&m_chat).unwrap().pinned);
    assert_eq!(mac.app_setting("folders").unwrap().as_deref(), Some(r#"[{"name":"Работа"}]"#));
    assert_eq!(mac.chat(&m_chat).unwrap().title, "Bob");
    eventually("mac saved messages", || mac.saved_chat_id().is_some()).await;

    // Новое сообщение собеседника — на обоих устройствах.
    bob.send_text(&b_chat, "оба видят?", None, None).await.unwrap();
    eventually("phone gets it", || texts(&phone, &p_chat).last().map(String::as_str) == Some("оба видят?")).await;
    eventually("mac gets it", || texts(&mac, &m_chat).last().map(String::as_str) == Some("оба видят?")).await;
    assert_eq!(bob.chat(&b_chat).unwrap().members.len(), 2, "two devices are still one member for Bob");

    // Отправка с Mac: у телефона — исходящее, у Боба — от Алисы.
    mac.send_text(&m_chat, "пишу с мака", None, None).await.unwrap();
    eventually("phone sees own message", || {
        phone.messages(&p_chat, 10, None).unwrap().last().is_some_and(|m| m.text == "пишу с мака" && m.outgoing)
    })
    .await;
    eventually("bob sees it", || texts(&bob, &b_chat).last().map(String::as_str) == Some("пишу с мака")).await;
    assert_eq!(bob.messages(&b_chat, 10, None).unwrap().last().unwrap().sender_name, "Alice");

    // Правку своего сообщения можно сделать с другого устройства аккаунта.
    let own_id = phone.messages(&p_chat, 10, None).unwrap().last().unwrap().id.clone();
    phone.edit_message(&own_id, "исправлено с телефона").await.unwrap();
    eventually("edit on mac", || texts(&mac, &m_chat).last().map(String::as_str) == Some("исправлено с телефона"))
        .await;
    eventually("edit on bob", || texts(&bob, &b_chat).last().map(String::as_str) == Some("исправлено с телефона"))
        .await;
    mac.edit_message(&own_id, "исправлено с мака").await.unwrap();
    eventually("edit back on phone", || texts(&phone, &p_chat).last().map(String::as_str) == Some("исправлено с мака"))
        .await;
    eventually("second edit on bob", || texts(&bob, &b_chat).last().map(String::as_str) == Some("исправлено с мака"))
        .await;

    let (p_edit, m_edit) =
        tokio::join!(phone.edit_message(&own_id, "concurrent phone"), mac.edit_message(&own_id, "concurrent mac"));
    p_edit.unwrap();
    m_edit.unwrap();
    eventually("concurrent edits converge", || {
        let p = phone.messages(&p_chat, 10, None).unwrap().pop().unwrap();
        let m = mac.messages(&m_chat, 10, None).unwrap().pop().unwrap();
        let b = bob.messages(&b_chat, 10, None).unwrap().pop().unwrap();
        p.text.starts_with("concurrent")
            && p.text == m.text
            && p.text == b.text
            && p.edited_ms == m.edited_ms
            && p.edited_ms == b.edited_ms
    })
    .await;

    // Прочитали на Mac — на телефоне счётчик тоже сброшен.
    assert!(phone.chat(&p_chat).unwrap().unread > 0);
    mac.mark_read(&m_chat).await.unwrap();
    eventually("read synced", || phone.chat(&p_chat).unwrap().unread == 0).await;

    // Флаги и настройки.
    phone.set_muted(&p_chat, true).unwrap();
    eventually("mute synced", || mac.chat(&m_chat).unwrap().muted).await;
    mac.set_archived(&m_chat, true).unwrap();
    eventually("archive synced", || phone.chat(&p_chat).unwrap().archived).await;
    mac.set_app_setting("folders", "[]").unwrap();
    eventually("setting synced", || phone.app_setting("folders").unwrap().as_deref() == Some("[]")).await;

    // Реакция с одного устройства — «моя» на обоих.
    let msg = mac.messages(&m_chat, 10, None).unwrap()[0].id.clone();
    mac.react(&msg, Some("👍")).await.unwrap();
    eventually("reaction on phone", || {
        phone.messages(&p_chat, 10, None).unwrap()[0].reactions.first().is_some_and(|r| r.mine)
    })
    .await;

    // Новый чат на Mac — телефон вступает в него сам.
    let (new_chat, _) = mac.create_chat(Some("Проект")).await.unwrap();
    let new_gid = mac.chat(&new_chat).unwrap().gid.unwrap();
    eventually("phone joins new chat", || {
        by_gid(&phone, &new_gid).is_some_and(|id| phone.chat(&id).unwrap().state == ChatState::Active)
    })
    .await;
    assert_eq!(phone.chat(&by_gid(&phone, &new_gid).unwrap()).unwrap().title, "Проект");

    // Устройства: каждое видит оба, со своими нодами.
    phone.set_device("iPhone", "ios", &node_a).unwrap();
    mac.set_device("MacBook", "macos", &node_b).unwrap();
    eventually("phone sees mac", || phone.devices().unwrap().iter().any(|d| d.name == "MacBook" && d.node == node_b))
        .await;
    eventually("mac sees phone", || mac.devices().unwrap().iter().any(|d| d.name == "iPhone" && d.node == node_a))
        .await;
    assert!(phone.devices().unwrap()[0].is_this);

    // Отключение Mac: он получает команду, Боб больше не шлёт ему сообщения.
    let mac_id = phone.devices().unwrap().into_iter().find(|d| !d.is_this).unwrap().id;
    phone.remove_device(&mac_id).await.unwrap();
    eventually("mac knows it was removed", || mac.is_removed()).await;
    eventually("mac left the chat", || mac.chat(&m_chat).unwrap().state == ChatState::Left).await;
    assert_eq!(phone.devices().unwrap().len(), 1);
    bob.send_text(&b_chat, "после отключения", None, None).await.unwrap();
    eventually("phone still gets messages", || {
        texts(&phone, &p_chat).last().map(String::as_str) == Some("после отключения")
    })
    .await;
}
