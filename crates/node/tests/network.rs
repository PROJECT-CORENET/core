//! Сеть нод, снимок сети, presence, отписка — с настоящими нодами на 127.0.0.1.

use std::time::Duration;

use core_crypto::{random_bytes, Ed25519Key};
use core_directory::{mutual_links, node_id_of, sign_descriptor, sign_session, verify_snapshot, NodeId};
use core_net::{Client, NetError, NodeAddr};
use core_node::{Config, Node, NodeIdentity, Store};
use core_proto::msg::{
    event, gossip, request, response, ErrorCode, Event, Gossip, LogAppend, LogNew, LogWatch, NetNode, NetSnapshot,
    NodeDescriptor, PeerHello, PresencePut, PresenceUpdate, PresenceWatch, Unsubscribe,
};
use tokio::sync::mpsc;

struct TestNode {
    addr: NodeAddr,
    id: NodeId,
}

async fn start(bootstrap: Vec<String>) -> TestNode {
    let config = Config {
        listen: "127.0.0.1:0".into(),
        bootstrap,
        gossip_interval_secs: 1,
        peer_check_interval_secs: 1,
        name: "test".into(),
        region: "NL".into(),
        ..Config::default()
    };
    let identity = NodeIdentity::generate();
    let id = identity.node_id();
    let node = Node::bind(config, identity, Store::open_in_memory().unwrap()).await.unwrap();
    let addr = node.address();
    tokio::spawn(node.run());
    TestNode { addr, id }
}

async fn snapshot(client: &Client) -> (Vec<NetNode>, Vec<u8>) {
    let mut nodes = vec![];
    let mut cursor = vec![];
    loop {
        let response::Body::NetSnapshotReply(r) =
            client.request(request::Body::NetSnapshot(NetSnapshot { cursor }), None).await.unwrap()
        else {
            panic!()
        };
        nodes.extend(r.nodes);
        if r.next_cursor.is_empty() {
            return (nodes, r.self_id);
        }
        cursor = r.next_cursor;
    }
}

fn code(err: NetError) -> ErrorCode {
    err.node_code().unwrap_or_else(|| panic!("expected node error, got {err}"))
}

async fn next_event(events: &mut mpsc::Receiver<Event>) -> event::Body {
    tokio::time::timeout(Duration::from_secs(5), events.recv()).await.expect("event timeout").unwrap().body.unwrap()
}

#[tokio::test]
async fn three_nodes_discover_each_other() {
    // Цепочка: B знает только A, C знает только B. Через gossip все должны узнать всех.
    let a = start(vec![]).await;
    let b = start(vec![a.addr.to_string()]).await;
    let c = start(vec![b.addr.to_string()]).await;

    let (client, _ev) = Client::connect(&a.addr).await.unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let (nodes, self_id) = snapshot(&client).await;
        assert_eq!(self_id, a.id.to_vec());
        // Клиент сам проверяет подписи — не доверяет ноде.
        let dir = verify_snapshot(nodes, core_node::now_ms());
        let links = mutual_links(&dir);
        let all_known = [a.id, b.id, c.id].iter().all(|id| dir.get(id).is_some_and(|e| e.stats.is_some()));
        // C подключается к B, а узнав о A через gossip — и к A.
        let has = |x: NodeId, y: NodeId| links.contains(&(x.min(y), x.max(y)));
        if all_known && has(a.id, b.id) && has(b.id, c.id) {
            let e = dir.get(&c.id).unwrap();
            assert_eq!(e.descriptor.region, "NL");
            assert!(e.is_online(core_node::now_ms()));
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "network did not converge: {} nodes, links {links:?}",
            dir.len()
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

fn hello(key: &Ed25519Key, session_hash: &[u8]) -> PeerHello {
    let mut d = NodeDescriptor {
        x25519_pk: vec![7; 32],
        addresses: vec!["127.0.0.1:1".into()],
        published_at_ms: core_node::now_ms(),
        expires_at_ms: core_node::now_ms() + 60_000,
        ..Default::default()
    };
    sign_descriptor(&mut d, key);
    PeerHello { descriptor: Some(d), session_sig: sign_session(key, session_hash) }
}

#[tokio::test]
async fn peer_auth_and_gossip_rules() {
    let node = start(vec![]).await;
    let key = Ed25519Key::generate();

    // Подпись не того хеша сессии — отказ (нельзя переиграть чужой PeerHello).
    let (c1, _e1) = Client::connect(&node.addr).await.unwrap();
    let replay = hello(&key, b"some other session");
    assert_eq!(code(c1.request(request::Body::PeerHello(replay), None).await.unwrap_err()), ErrorCode::Auth);

    // Gossip от того, кто не представился нодой, — отказ.
    let mut fake = NodeDescriptor::default();
    sign_descriptor(&mut fake, &key);
    let g = Gossip { msg_id: random_bytes::<16>().to_vec(), ttl: 3, payload: Some(gossip::Payload::Descriptor(fake)) };
    assert_eq!(code(c1.request(request::Body::Gossip(g), None).await.unwrap_err()), ErrorCode::Auth);

    // Правильный PeerHello → Welcome с дескриптором ноды; поддельный gossip молча отбрасывается.
    let (c2, _e2) = Client::connect(&node.addr).await.unwrap();
    let good = hello(&key, c2.session_hash());
    let response::Body::PeerWelcome(w) = c2.request(request::Body::PeerHello(good), None).await.unwrap() else {
        panic!()
    };
    let d = w.descriptor.unwrap();
    assert_eq!(d.x25519_pk, node.addr.public_key.to_vec());
    assert_eq!(node_id_of(&d.ed25519_pk), node.id);

    let mut tampered = d.clone();
    tampered.name = "evil".into();
    let g =
        Gossip { msg_id: random_bytes::<16>().to_vec(), ttl: 3, payload: Some(gossip::Payload::Descriptor(tampered)) };
    c2.request(request::Body::Gossip(g), None).await.unwrap();

    let (client, _e) = Client::connect(&node.addr).await.unwrap();
    let (nodes, _) = snapshot(&client).await;
    let ids: Vec<_> = nodes.iter().map(|n| node_id_of(&n.descriptor.as_ref().unwrap().ed25519_pk)).collect();
    assert!(ids.contains(&node_id_of(&key.public_key())), "peer descriptor should be known");
    let own = nodes.iter().find(|n| node_id_of(&n.descriptor.as_ref().unwrap().ed25519_pk) == node.id).unwrap();
    assert_eq!(own.descriptor.as_ref().unwrap().name, "test");
}

fn put(id: &[u8], key: &Ed25519Key, sealed: &[u8], ttl_secs: u32) -> request::Body {
    request::Body::PresencePut(PresencePut {
        presence_id: id.to_vec(),
        write_pk: key.public_key().to_vec(),
        sealed: sealed.to_vec(),
        ttl_secs,
    })
}

async fn presence_event(events: &mut mpsc::Receiver<Event>) -> PresenceUpdate {
    match next_event(events).await {
        event::Body::PresenceUpdate(u) => u,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn presence_heartbeat_watch_and_expiry() {
    let node = start(vec![]).await;
    let alice = Ed25519Key::generate();
    let id = random_bytes::<16>();
    let (a, _ea) = Client::connect(&node.addr).await.unwrap();
    let (bob, mut events) = Client::connect(&node.addr).await.unwrap();

    a.request(put(&id, &alice, b"online", 60), Some(&alice)).await.unwrap();

    // Подписка сразу отдаёт текущее состояние.
    bob.request(request::Body::PresenceWatch(PresenceWatch { presence_ids: vec![id.to_vec()] }), None).await.unwrap();
    let u = presence_event(&mut events).await;
    assert!(u.online);
    assert_eq!(u.sealed, b"online");

    // Тот же статус — без события; новый статус — событие.
    a.request(put(&id, &alice, b"online", 60), Some(&alice)).await.unwrap();
    a.request(put(&id, &alice, b"busy", 1), Some(&alice)).await.unwrap();
    let u = presence_event(&mut events).await;
    assert_eq!(u.sealed, b"busy");

    // Heartbeat с TTL 1 с истекает → офлайн, последний статус сохраняется.
    let u = presence_event(&mut events).await;
    assert!(!u.online);
    assert_eq!(u.sealed, b"busy");

    // Чужой ключ не может писать в занятый presence_id; без подписи — тоже.
    let mallory = Ed25519Key::generate();
    assert_eq!(code(a.request(put(&id, &mallory, b"x", 60), Some(&mallory)).await.unwrap_err()), ErrorCode::Auth);
    assert_eq!(code(a.request(put(&id, &alice, b"x", 60), None).await.unwrap_err()), ErrorCode::Auth);
}

#[tokio::test]
async fn unsubscribe_stops_events() {
    let node = start(vec![]).await;
    let (c, mut events) = Client::connect(&node.addr).await.unwrap();
    let (write, read) = (Ed25519Key::generate(), Ed25519Key::generate());
    let log_id = random_bytes::<32>().to_vec();
    c.request(
        request::Body::LogNew(LogNew {
            log_id: log_id.clone(),
            write_pk: write.public_key().to_vec(),
            read_pk: read.public_key().to_vec(),
        }),
        None,
    )
    .await
    .unwrap();
    let append = |b: &[u8]| request::Body::LogAppend(LogAppend { log_id: log_id.clone(), blob: b.to_vec() });

    c.request(request::Body::LogWatch(LogWatch { log_id: log_id.clone(), from_offset: 0 }), Some(&read)).await.unwrap();
    c.request(append(b"1"), Some(&write)).await.unwrap();
    assert!(matches!(next_event(&mut events).await, event::Body::LogEvent(_)));

    c.request(request::Body::Unsubscribe(Unsubscribe { id: log_id.clone() }), None).await.unwrap();
    c.request(append(b"2"), Some(&write)).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_millis(300), events.recv()).await.is_err(), "event after unsubscribe");
}
