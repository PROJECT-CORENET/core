//! Тесты безопасности ноды: мусор и обрывы на входе, «тихие» соединения, лимит соединений,
//! перебор идентификаторов, чужие ключи. Нода должна отказывать, не падать и продолжать обслуживать остальных.

use std::time::Duration;

use core_crypto::{random_bytes, Ed25519Key};
use core_net::{Client, NetError, NodeAddr};
use core_node::{Config, Node, NodeIdentity, Store};
use core_proto::msg::{
    request, response, ErrorCode, LogAppend, LogCommit, LogNew, LogRead, Ping, QueueCreated, QueueDel, QueueNew,
    QueueSecure, QueueSub,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn start(config: Config) -> NodeAddr {
    let config = Config { listen: "127.0.0.1:0".into(), ..config };
    let node = Node::bind(config, NodeIdentity::generate(), Store::open_in_memory().unwrap()).await.unwrap();
    let addr = node.address();
    tokio::spawn(node.run());
    addr
}

fn code(err: NetError) -> ErrorCode {
    err.node_code().unwrap_or_else(|| panic!("ожидалась ошибка ноды, получено {err}"))
}

/// Нода жива: новое соединение проходит рукопожатие и отвечает на Ping.
async fn assert_alive(addr: &NodeAddr) {
    let (c, _ev) = tokio::time::timeout(Duration::from_secs(5), Client::connect(addr))
        .await
        .expect("нода не приняла соединение")
        .expect("рукопожатие не прошло");
    assert!(matches!(c.request(request::Body::Ping(Ping {}), None).await.unwrap(), response::Body::Pong(_)));
}

/// Нода закрывает сокет (EOF или сброс) не позже чем за `within`.
async fn assert_closed(stream: &mut TcpStream, within: Duration) {
    let mut buf = [0u8; 256];
    let closed = tokio::time::timeout(within, async {
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => continue, // всё, что нода успела отправить, не важно — ждём закрытия
            }
        }
    })
    .await;
    assert!(closed.is_ok(), "нода не закрыла соединение с мусором");
}

async fn new_queue(c: &Client, owner: &Ed25519Key) -> QueueCreated {
    match c
        .request(request::Body::QueueNew(QueueNew { recipient_auth_pk: owner.public_key().to_vec() }), None)
        .await
        .unwrap()
    {
        response::Body::QueueCreated(q) => q,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn garbage_instead_of_handshake_is_dropped() {
    let addr = start(Config::default()).await;
    for garbage in [
        random_bytes::<512>().to_vec(),
        b"GET / HTTP/1.1\r\nHost: node\r\n\r\n".to_vec(),
        vec![0u8; 3],
        vec![0xFF; 4096],
    ] {
        let mut s = TcpStream::connect(&addr.host).await.unwrap();
        let _ = s.write_all(&garbage).await;
        assert_closed(&mut s, Duration::from_secs(12)).await;
    }
    assert_alive(&addr).await;
}

#[tokio::test]
async fn huge_frame_length_does_not_allocate_or_crash() {
    let addr = start(Config::default()).await;
    // Заголовок кадра обещает 4 ГБ — нода не должна ждать и выделять память под это.
    let mut s = TcpStream::connect(&addr.host).await.unwrap();
    let _ = s.write_all(&[0xFF, 0xFF, 0xFF, 0xFF]).await;
    let _ = s.write_all(&random_bytes::<64>()).await;
    assert_closed(&mut s, Duration::from_secs(12)).await;
    assert_alive(&addr).await;
}

#[tokio::test]
async fn truncated_handshakes_do_not_break_the_node() {
    let addr = start(Config::default()).await;
    for _ in 0..20 {
        let mut s = TcpStream::connect(&addr.host).await.unwrap();
        // Половина первого сообщения Noise — и обрыв.
        let _ = s.write_all(&random_bytes::<24>()).await;
        drop(s);
    }
    assert_alive(&addr).await;
}

#[tokio::test]
async fn silent_connections_do_not_starve_others() {
    // Slowloris: много TCP-соединений без единого байта — остальные клиенты всё равно обслуживаются.
    let addr = start(Config::default()).await;
    let mut idle = vec![];
    for _ in 0..50 {
        idle.push(TcpStream::connect(&addr.host).await.unwrap());
    }
    assert_alive(&addr).await;
    // А «тихие» нода сама закрывает по таймауту рукопожатия.
    assert_closed(&mut idle[0], Duration::from_secs(15)).await;
}

#[tokio::test]
async fn connection_limit_rejects_and_recovers() {
    let addr = start(Config { max_connections: 2, ..Config::default() }).await;
    let (a, _ea) = Client::connect(&addr).await.unwrap();
    let (b, _eb) = Client::connect(&addr).await.unwrap();
    a.request(request::Body::Ping(Ping {}), None).await.unwrap();
    b.request(request::Body::Ping(Ping {}), None).await.unwrap();

    // Третье — сверх лимита: нода сразу закрывает сокет, рукопожатие не проходит.
    let third = tokio::time::timeout(Duration::from_secs(5), async {
        let (c, _ev) = Client::connect(&addr).await?;
        c.request(request::Body::Ping(Ping {}), None).await
    })
    .await
    .expect("отказ должен быть быстрым");
    assert!(third.is_err(), "соединение сверх лимита не должно обслуживаться");

    // Освободили место — снова можно.
    drop(a);
    let mut ok = false;
    for _ in 0..50 {
        if let Ok(Ok((c, _ev))) = tokio::time::timeout(Duration::from_secs(2), Client::connect(&addr)).await {
            if c.request(request::Body::Ping(Ping {}), None).await.is_ok() {
                ok = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "после закрытия соединения лимит должен освобождаться");
}

#[tokio::test]
async fn queue_ids_are_not_enumerable() {
    // Чужая существующая очередь и несуществующая отвечают одинаково — по ответу не узнать, что ID занят.
    let addr = start(Config::default()).await;
    let (c, _ev) = Client::connect(&addr).await.unwrap();
    let owner = Ed25519Key::generate();
    let q = new_queue(&c, &owner).await;
    let stranger = Ed25519Key::generate();

    let sub = |id: Vec<u8>| request::Body::QueueSub(QueueSub { recipient_id: id });
    let existing = code(c.request(sub(q.recipient_id.clone()), Some(&stranger)).await.unwrap_err());
    let missing = code(c.request(sub(random_bytes::<24>().to_vec()), Some(&stranger)).await.unwrap_err());
    assert_eq!(existing, missing, "ответ выдаёт существование очереди");

    let del = |id: Vec<u8>| request::Body::QueueDel(QueueDel { recipient_id: id });
    let existing = code(c.request(del(q.recipient_id.clone()), Some(&stranger)).await.unwrap_err());
    let missing = code(c.request(del(random_bytes::<24>().to_vec()), Some(&stranger)).await.unwrap_err());
    assert_eq!(existing, missing, "ответ выдаёт существование очереди");

    // ID отправителя и получателя — разные: зная адрес для отправки, очередь не прочитать.
    assert_ne!(q.sender_id, q.recipient_id);
    assert!(c.request(sub(q.sender_id.clone()), Some(&owner)).await.is_err());
}

#[tokio::test]
async fn stranger_cannot_take_over_queue_or_log() {
    let addr = start(Config::default()).await;
    let (c, _ev) = Client::connect(&addr).await.unwrap();
    let owner = Ed25519Key::generate();
    let thief = Ed25519Key::generate();
    let q = new_queue(&c, &owner).await;

    // Закрепить «своего» отправителя на чужой очереди нельзя — ни без подписи, ни с чужим ключом.
    let secure = request::Body::QueueSecure(QueueSecure {
        recipient_id: q.recipient_id.clone(),
        sender_auth_pk: thief.public_key().to_vec(),
    });
    assert!(c.request(secure.clone(), None).await.is_err());
    assert!(c.request(secure, Some(&thief)).await.is_err());

    // Журнал: писать, читать и коммитить можно только своими ключами.
    let write = Ed25519Key::generate();
    let read = Ed25519Key::generate();
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
    let append = request::Body::LogAppend(LogAppend { log_id: log_id.clone(), blob: b"x".to_vec() });
    assert_eq!(code(c.request(append.clone(), None).await.unwrap_err()), ErrorCode::Auth);
    assert_eq!(code(c.request(append.clone(), Some(&thief)).await.unwrap_err()), ErrorCode::Auth);
    c.request(append, Some(&write)).await.unwrap();

    let read_req = request::Body::LogRead(LogRead { log_id: log_id.clone(), from_offset: 0, limit: 10 });
    assert_eq!(code(c.request(read_req.clone(), None).await.unwrap_err()), ErrorCode::Auth);
    assert_eq!(code(c.request(read_req.clone(), Some(&thief)).await.unwrap_err()), ErrorCode::Auth);
    c.request(read_req, Some(&read)).await.unwrap();

    let commit = request::Body::LogCommit(LogCommit {
        log_id: log_id.clone(),
        expected_offset: 1,
        blob: b"evil".to_vec(),
    });
    assert!(c.request(commit, Some(&thief)).await.is_err(), "коммит в чужой журнал");

    // Пересоздать чужой журнал со своими ключами — тоже нельзя.
    let hijack = request::Body::LogNew(LogNew {
        log_id,
        write_pk: thief.public_key().to_vec(),
        read_pk: thief.public_key().to_vec(),
    });
    assert_eq!(code(c.request(hijack, None).await.unwrap_err()), ErrorCode::AlreadyExists);
}
