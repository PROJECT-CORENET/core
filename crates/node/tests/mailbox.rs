//! Интеграционные тесты: настоящая нода на 127.0.0.1:0 + клиент через Noise.

use std::time::Duration;

use core_crypto::{random_bytes, Ed25519Key};
use core_net::{Client, NetError, NodeAddr};
use core_node::{Config, Node, NodeIdentity, Store};
use core_proto::msg::{
    event, request, response, EntryKind, ErrorCode, Event, LogAppend, LogCommit, LogEntry, LogNew, LogRead, LogWatch,
    Ping, QueueAck, QueueCreated, QueueDel, QueueNew, QueueSecure, QueueSend, QueueSub, Request, MAX_BLOB,
};
use tokio::sync::mpsc;

async fn start_node() -> NodeAddr {
    let config = Config { listen: "127.0.0.1:0".into(), ..Config::default() };
    let node = Node::bind(config, NodeIdentity::generate(), Store::open_in_memory().unwrap()).await.unwrap();
    let addr = node.address();
    tokio::spawn(node.run());
    addr
}

async fn connect(addr: &NodeAddr) -> (Client, mpsc::Receiver<Event>) {
    Client::connect(addr).await.unwrap()
}

async fn next_event(events: &mut mpsc::Receiver<Event>) -> event::Body {
    tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("таймаут ожидания события")
        .expect("соединение закрыто")
        .body
        .expect("пустое событие")
}

async fn no_event(events: &mut mpsc::Receiver<Event>) {
    assert!(tokio::time::timeout(Duration::from_millis(200), events.recv()).await.is_err(), "лишнее событие");
}

fn code(err: NetError) -> ErrorCode {
    err.node_code().unwrap_or_else(|| panic!("ожидалась ошибка ноды, получено {err}"))
}

async fn new_queue(client: &Client, recipient: &Ed25519Key) -> QueueCreated {
    match client
        .request(request::Body::QueueNew(QueueNew { recipient_auth_pk: recipient.public_key().to_vec() }), None)
        .await
        .unwrap()
    {
        response::Body::QueueCreated(q) => q,
        other => panic!("{other:?}"),
    }
}

fn send(sender_id: &[u8], body: &[u8]) -> request::Body {
    request::Body::QueueSend(QueueSend { sender_id: sender_id.to_vec(), body: body.to_vec() })
}

#[tokio::test]
async fn ping() {
    let addr = start_node().await;
    let (client, _ev) = connect(&addr).await;
    assert!(matches!(client.request(request::Body::Ping(Ping {}), None).await.unwrap(), response::Body::Pong(_)));
}

#[tokio::test]
async fn wrong_node_key_fails_handshake() {
    let mut addr = start_node().await;
    addr.public_key = NodeIdentity::generate().noise.public;
    let result = async {
        let (client, _ev) = Client::connect(&addr).await?;
        client.request(request::Body::Ping(Ping {}), None).await
    }
    .await;
    assert!(result.is_err(), "MITM с чужим ключом не должен проходить");
}

#[tokio::test]
async fn queue_full_flow() {
    let addr = start_node().await;
    let recipient = Ed25519Key::generate();
    let sender = Ed25519Key::generate();

    // Получатель и отправитель — разные соединения, как в реальности.
    let (rc, mut events) = connect(&addr).await;
    let (sc, _sev) = connect(&addr).await;
    let q = new_queue(&rc, &recipient).await;

    // До закрепления писать может кто угодно (ответ на приглашение).
    sc.request(send(&q.sender_id, b"offline-1"), None).await.unwrap();

    // Подписка отдаёт недоставленное.
    rc.request(request::Body::QueueSub(QueueSub { recipient_id: q.recipient_id.clone() }), Some(&recipient))
        .await
        .unwrap();
    let event::Body::QueueMessage(m1) = next_event(&mut events).await else { panic!() };
    assert_eq!(m1.body, b"offline-1");

    // Закрепляем отправителя.
    rc.request(
        request::Body::QueueSecure(QueueSecure {
            recipient_id: q.recipient_id.clone(),
            sender_auth_pk: sender.public_key().to_vec(),
        }),
        Some(&recipient),
    )
    .await
    .unwrap();

    // Без подписи / с чужим ключом — отказ.
    assert_eq!(code(sc.request(send(&q.sender_id, b"x"), None).await.unwrap_err()), ErrorCode::Auth);
    assert_eq!(
        code(sc.request(send(&q.sender_id, b"x"), Some(&Ed25519Key::generate())).await.unwrap_err()),
        ErrorCode::Auth
    );

    // С правильной подписью — приходит подписчику сразу.
    sc.request(send(&q.sender_id, b"live"), Some(&sender)).await.unwrap();
    let event::Body::QueueMessage(m2) = next_event(&mut events).await else { panic!() };
    assert_eq!(m2.body, b"live");

    // ACK удаляет; повторный ACK — NotFound.
    let ack = |msg_id: Vec<u8>| request::Body::QueueAck(QueueAck { recipient_id: q.recipient_id.clone(), msg_id });
    rc.request(ack(m1.msg_id.clone()), Some(&recipient)).await.unwrap();
    assert_eq!(code(rc.request(ack(m1.msg_id), Some(&recipient)).await.unwrap_err()), ErrorCode::NotFound);

    // Неподтверждённое сообщение придёт снова при переподписке (новое соединение).
    drop(rc);
    let (rc2, mut events2) = connect(&addr).await;
    rc2.request(request::Body::QueueSub(QueueSub { recipient_id: q.recipient_id.clone() }), Some(&recipient))
        .await
        .unwrap();
    let event::Body::QueueMessage(again) = next_event(&mut events2).await else { panic!() };
    assert_eq!(again.msg_id, m2.msg_id);
    no_event(&mut events2).await;

    // Чужой ключ не может управлять очередью.
    let stranger = Ed25519Key::generate();
    let del = request::Body::QueueDel(QueueDel { recipient_id: q.recipient_id.clone() });
    assert_eq!(code(rc2.request(del.clone(), Some(&stranger)).await.unwrap_err()), ErrorCode::Auth);

    rc2.request(del, Some(&recipient)).await.unwrap();
    assert_eq!(code(sc.request(send(&q.sender_id, b"x"), Some(&sender)).await.unwrap_err()), ErrorCode::Auth);
}

#[tokio::test]
async fn signature_is_bound_to_session() {
    let addr = start_node().await;
    let recipient = Ed25519Key::generate();
    let (a, _ea) = connect(&addr).await;
    let (b, _eb) = connect(&addr).await;
    let q = new_queue(&a, &recipient).await;

    // Подпись, сделанная для сессии A, перехвачена и воспроизведена в сессии B.
    let mut req = Request {
        corr_id: 1000,
        auth_sig: vec![],
        body: Some(request::Body::QueueSub(QueueSub { recipient_id: q.recipient_id.clone() })),
    };
    req.auth_sig = recipient.sign(&req.signing_bytes(a.session_hash())).to_vec();
    assert_eq!(code(b.send_request(req.clone()).await.unwrap_err()), ErrorCode::Auth);
    a.send_request(req).await.unwrap();
}

#[tokio::test]
async fn validation() {
    let addr = start_node().await;
    let (c, _ev) = connect(&addr).await;
    let recipient = Ed25519Key::generate();

    let bad_pk = request::Body::QueueNew(QueueNew { recipient_auth_pk: vec![1; 5] });
    assert_eq!(code(c.request(bad_pk, None).await.unwrap_err()), ErrorCode::BadRequest);

    let q = new_queue(&c, &recipient).await;
    let too_big = send(&q.sender_id, &vec![0; MAX_BLOB + 1]);
    assert_eq!(code(c.request(too_big, None).await.unwrap_err()), ErrorCode::TooLarge);
    c.request(send(&q.sender_id, &vec![0; MAX_BLOB]), None).await.unwrap();

    let empty = Request { corr_id: 0, auth_sig: vec![], body: None };
    assert_eq!(code(c.send_request(empty).await.unwrap_err()), ErrorCode::BadRequest);
}

#[tokio::test]
async fn queue_quota() {
    let config = Config { listen: "127.0.0.1:0".into(), max_queue_messages: 2, ..Config::default() };
    let node = Node::bind(config, NodeIdentity::generate(), Store::open_in_memory().unwrap()).await.unwrap();
    let addr = node.address();
    tokio::spawn(node.run());

    let (c, _ev) = connect(&addr).await;
    let q = new_queue(&c, &Ed25519Key::generate()).await;
    c.request(send(&q.sender_id, b"1"), None).await.unwrap();
    c.request(send(&q.sender_id, b"2"), None).await.unwrap();
    assert_eq!(code(c.request(send(&q.sender_id, b"3"), None).await.unwrap_err()), ErrorCode::QuotaExceeded);
}

struct TestLog {
    id: Vec<u8>,
    write: Ed25519Key,
    read: Ed25519Key,
}

async fn new_log(c: &Client) -> TestLog {
    let log =
        TestLog { id: random_bytes::<32>().to_vec(), write: Ed25519Key::generate(), read: Ed25519Key::generate() };
    c.request(
        request::Body::LogNew(LogNew {
            log_id: log.id.clone(),
            write_pk: log.write.public_key().to_vec(),
            read_pk: log.read.public_key().to_vec(),
        }),
        None,
    )
    .await
    .unwrap();
    log
}

fn append(log: &TestLog, blob: &[u8]) -> request::Body {
    request::Body::LogAppend(LogAppend { log_id: log.id.clone(), blob: blob.to_vec(), ..Default::default() })
}

fn read(log: &TestLog, from: u64, limit: u32) -> request::Body {
    request::Body::LogRead(LogRead { log_id: log.id.clone(), from_offset: from, limit })
}

#[tokio::test]
async fn log_append_read_and_keys() {
    let addr = start_node().await;
    let (c, _ev) = connect(&addr).await;
    let log = new_log(&c).await;

    for i in 0..3u64 {
        let response::Body::LogAppended(a) = c.request(append(&log, &[i as u8]), Some(&log.write)).await.unwrap()
        else {
            panic!()
        };
        assert_eq!(a.offset, i);
    }
    // Ключ чтения не даёт права записи, и наоборот.
    assert_eq!(code(c.request(append(&log, b"x"), Some(&log.read)).await.unwrap_err()), ErrorCode::Auth);
    assert_eq!(code(c.request(read(&log, 0, 10), Some(&log.write)).await.unwrap_err()), ErrorCode::Auth);

    let response::Body::LogEntries(e) = c.request(read(&log, 1, 10), Some(&log.read)).await.unwrap() else { panic!() };
    assert_eq!(e.entries.iter().map(|e| e.blob[0]).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(e.next_offset, 3);

    // Повторное создание журнала с тем же ID — отказ.
    let dup = request::Body::LogNew(LogNew { log_id: log.id.clone(), write_pk: vec![0; 32], read_pk: vec![0; 32] });
    assert_eq!(code(c.request(dup, None).await.unwrap_err()), ErrorCode::AlreadyExists);
}

#[tokio::test]
async fn log_read_paginates_large_entries() {
    let addr = start_node().await;
    let (c, _ev) = connect(&addr).await;
    let log = new_log(&c).await;
    for _ in 0..3 {
        c.request(append(&log, &vec![7; MAX_BLOB]), Some(&log.write)).await.unwrap();
    }
    // Каждая запись почти на целый кадр — читаем по одной, по next_offset.
    let mut from = 0;
    let mut got = 0;
    while got < 3 {
        let response::Body::LogEntries(e) = c.request(read(&log, from, 100), Some(&log.read)).await.unwrap() else {
            panic!()
        };
        assert_eq!(e.entries.len(), 1);
        got += e.entries.len();
        from = e.next_offset;
    }
    assert_eq!(from, 3);
}

#[tokio::test]
async fn log_commit_compare_and_swap() {
    let addr = start_node().await;
    let (alice, _ea) = connect(&addr).await;
    let (bob, _eb) = connect(&addr).await;
    let log = new_log(&alice).await;
    let commit =
        |epoch, blob: &[u8]| request::Body::LogCommit(LogCommit { log_id: log.id.clone(), epoch, blob: blob.to_vec() });

    assert!(matches!(
        alice.request(commit(1, b"alice"), Some(&log.write)).await.unwrap(),
        response::Body::LogAppended(_)
    ));
    match bob.request(commit(1, b"bob"), Some(&log.write)).await.unwrap() {
        response::Body::CommitConflict(c) => {
            let w = c.winner.unwrap();
            assert_eq!(w.blob, b"alice");
            assert_eq!(w.kind, EntryKind::Commit as i32);
            assert_eq!(w.epoch, 1);
        }
        other => panic!("{other:?}"),
    }
    // Боб применяет коммит Алисы и коммитит следующую эпоху.
    bob.request(commit(2, b"bob"), Some(&log.write)).await.unwrap();
    // Опоздавший коммит на занятую эпоху снова получает победителя.
    assert!(matches!(
        alice.request(commit(1, b"late"), Some(&log.write)).await.unwrap(),
        response::Body::CommitConflict(_)
    ));
    // Эпоха из прошлого, на которую коммита не было, — «устарела».
    alice.request(commit(5, b"jump"), Some(&log.write)).await.unwrap();
    assert_eq!(code(alice.request(commit(4, b"late"), Some(&log.write)).await.unwrap_err()), ErrorCode::Conflict);
}

#[tokio::test]
async fn log_watch_history_then_live() {
    let addr = start_node().await;
    let (writer, _ew) = connect(&addr).await;
    let (reader, mut events) = connect(&addr).await;
    let log = new_log(&writer).await;

    for b in [b"a", b"b", b"c"] {
        writer.request(append(&log, b), Some(&log.write)).await.unwrap();
    }
    reader
        .request(request::Body::LogWatch(LogWatch { log_id: log.id.clone(), from_offset: 1 }), Some(&log.read))
        .await
        .unwrap();

    let mut got: Vec<LogEntry> = vec![];
    for _ in 0..2 {
        let event::Body::LogEvent(e) = next_event(&mut events).await else { panic!() };
        assert_eq!(e.log_id, log.id);
        got.push(e.entry.unwrap());
    }
    assert_eq!(got.iter().map(|e| e.offset).collect::<Vec<_>>(), vec![1, 2]);

    writer.request(append(&log, b"d"), Some(&log.write)).await.unwrap();
    let event::Body::LogEvent(e) = next_event(&mut events).await else { panic!() };
    let e = e.entry.unwrap();
    assert_eq!((e.offset, e.blob.as_slice()), (3, &b"d"[..]));
    no_event(&mut events).await;
}

#[tokio::test]
async fn many_concurrent_writers_keep_order_dense() {
    let addr = start_node().await;
    let (c, _ev) = connect(&addr).await;
    let log = new_log(&c).await;
    let log = std::sync::Arc::new(log);

    let mut tasks = vec![];
    for i in 0..8u8 {
        let addr = addr.clone();
        let log = log.clone();
        tasks.push(tokio::spawn(async move {
            let (c, _ev) = Client::connect(&addr).await.unwrap();
            for j in 0..10u8 {
                c.request(append(&log, &[i, j]), Some(&log.write)).await.unwrap();
            }
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let mut offsets = vec![];
    let mut from = 0;
    loop {
        let response::Body::LogEntries(e) = c.request(read(&log, from, 256), Some(&log.read)).await.unwrap() else {
            panic!()
        };
        if e.entries.is_empty() {
            break;
        }
        offsets.extend(e.entries.iter().map(|e| e.offset));
        from = e.next_offset;
    }
    assert_eq!(offsets, (0..80).collect::<Vec<_>>());
}
