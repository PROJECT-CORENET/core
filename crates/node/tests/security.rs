//! Тесты безопасности ноды: мусор и обрывы на входе, «тихие» соединения, лимит соединений,
//! перебор идентификаторов, чужие ключи, подмена подписанных команд, мусор внутри шифрованного канала, лимиты.
//! Нода должна отказывать, не падать и продолжать обслуживать остальных.

use std::time::Duration;

use core_crypto::{random_bytes, Ed25519Key};
use core_net::{Client, NetError, NodeAddr};
use core_node::{Config, Node, NodeIdentity, Store};
use core_proto::frame::FrameType;
use core_proto::msg::{
    event, request, response, ErrorCode, LogAppend, LogCommit, LogNew, LogRead, Ping, PresenceWatch, QueueAck,
    QueueCreated, QueueDel, QueueNew, QueueSecure, QueueSend, QueueSub, RelayJoin, Request, MAX_PRESENCE_WATCH,
    MAX_ROOMS_PER_CONN, PRESENCE_ID_LEN, ROOM_ID_LEN,
};
use prost::Message;
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

    let commit = request::Body::LogCommit(LogCommit { log_id: log_id.clone(), epoch: 1, blob: b"evil".to_vec() });
    assert_eq!(code(c.request(commit, Some(&thief)).await.unwrap_err()), ErrorCode::Auth, "коммит в чужой журнал");

    // Пересоздать чужой журнал со своими ключами — тоже нельзя.
    let hijack = request::Body::LogNew(LogNew {
        log_id,
        write_pk: thief.public_key().to_vec(),
        read_pk: thief.public_key().to_vec(),
    });
    assert_eq!(code(c.request(hijack, None).await.unwrap_err()), ErrorCode::AlreadyExists);
}

#[tokio::test]
async fn signed_command_cannot_be_altered() {
    // Подпись покрывает всю команду: поменять тело или corr_id под чужой подписью нельзя.
    let addr = start(Config::default()).await;
    let (c, _ev) = Client::connect(&addr).await.unwrap();
    let write = Ed25519Key::generate();
    let log_id = random_bytes::<32>().to_vec();
    c.request(
        request::Body::LogNew(LogNew {
            log_id: log_id.clone(),
            write_pk: write.public_key().to_vec(),
            read_pk: Ed25519Key::generate().public_key().to_vec(),
        }),
        None,
    )
    .await
    .unwrap();

    let append =
        |blob: &[u8]| Some(request::Body::LogAppend(LogAppend { log_id: log_id.clone(), blob: blob.to_vec() }));
    let mut signed = Request { corr_id: 1000, auth_sig: vec![], body: append(b"honest") };
    signed.auth_sig = write.sign(&signed.signing_bytes(c.session_hash())).to_vec();

    let forged_body = Request { body: append(b"forged"), ..signed.clone() };
    assert_eq!(code(c.send_request(forged_body).await.unwrap_err()), ErrorCode::Auth);
    let forged_corr = Request { corr_id: 1001, ..signed.clone() };
    assert_eq!(code(c.send_request(forged_corr).await.unwrap_err()), ErrorCode::Auth);
    let mut broken_sig = signed.clone();
    broken_sig.auth_sig[0] ^= 1;
    assert_eq!(code(c.send_request(broken_sig).await.unwrap_err()), ErrorCode::Auth);
    let short_sig = Request { auth_sig: signed.auth_sig[..10].to_vec(), ..signed.clone() };
    assert_eq!(code(c.send_request(short_sig).await.unwrap_err()), ErrorCode::Auth);

    // Подлинная команда проходит.
    c.send_request(signed).await.unwrap();
}

#[tokio::test]
async fn garbage_inside_encrypted_channel_closes_only_that_connection() {
    let addr = start(Config::default()).await;
    let (bystander, _ev) = Client::connect(&addr).await.unwrap();

    // Рукопожатие честное, а дальше — не протобаф, чужой тип кадра, ответ вместо запроса.
    for (ty, body) in [
        (FrameType::Request, random_bytes::<200>().to_vec()),
        (FrameType::Request, vec![0xFF; 64]),
        (FrameType::Response, Request { corr_id: 1, auth_sig: vec![], body: None }.encode_to_vec()),
        (FrameType::Event, vec![]),
    ] {
        let mut s = core_net::connect(&addr).await.unwrap();
        s.writer.send(ty, &body).await.unwrap();
        let closed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if s.reader.recv().await.is_err() {
                    return;
                }
            }
        })
        .await;
        assert!(closed.is_ok(), "нода не закрыла соединение с мусорным кадром {ty:?}");
    }

    // Остальные соединения не задеты.
    assert!(matches!(bystander.request(request::Body::Ping(Ping {}), None).await.unwrap(), response::Body::Pong(_)));
    assert_alive(&addr).await;
}

#[tokio::test]
async fn stranger_cannot_ack_or_delete_foreign_messages() {
    // Зная recipient_id и msg_id, чужой не может ни подтвердить (стереть) сообщение, ни удалить очередь.
    let addr = start(Config::default()).await;
    let (c, mut events) = Client::connect(&addr).await.unwrap();
    let owner = Ed25519Key::generate();
    let stranger = Ed25519Key::generate();
    let q = new_queue(&c, &owner).await;
    c.request(request::Body::QueueSend(QueueSend { sender_id: q.sender_id.clone(), body: b"secret".to_vec() }), None)
        .await
        .unwrap();
    c.request(request::Body::QueueSub(QueueSub { recipient_id: q.recipient_id.clone() }), Some(&owner)).await.unwrap();
    let ev = tokio::time::timeout(Duration::from_secs(5), events.recv()).await.unwrap().unwrap();
    let Some(event::Body::QueueMessage(m)) = ev.body else {
        panic!("ожидалось сообщение очереди")
    };

    let ack = request::Body::QueueAck(QueueAck { recipient_id: q.recipient_id.clone(), msg_id: m.msg_id.clone() });
    assert_eq!(code(c.request(ack.clone(), Some(&stranger)).await.unwrap_err()), ErrorCode::Auth);
    assert_eq!(code(c.request(ack.clone(), None).await.unwrap_err()), ErrorCode::Auth);
    let del = request::Body::QueueDel(QueueDel { recipient_id: q.recipient_id.clone() });
    assert_eq!(code(c.request(del, Some(&stranger)).await.unwrap_err()), ErrorCode::Auth);

    // Сообщение на месте: владелец подтверждает его сам.
    c.request(ack, Some(&owner)).await.unwrap();
}

#[tokio::test]
async fn per_connection_limits() {
    let addr = start(Config::default()).await;

    // Комнаты звонков: не больше MAX_ROOMS_PER_CONN на соединение, повторный вход в свою — можно.
    let (media, _em) = Client::connect_media(&addr).await.unwrap();
    let join = |room: &[u8]| request::Body::RelayJoin(RelayJoin { room_id: room.to_vec() });
    let rooms: Vec<_> = (0..MAX_ROOMS_PER_CONN).map(|_| random_bytes::<ROOM_ID_LEN>()).collect();
    for room in &rooms {
        media.request(join(room), None).await.unwrap();
    }
    let extra = random_bytes::<ROOM_ID_LEN>();
    assert_eq!(code(media.request(join(&extra), None).await.unwrap_err()), ErrorCode::QuotaExceeded);
    media.request(join(&rooms[0]), None).await.unwrap();
    assert_eq!(code(media.request(join(&[1; 3]), None).await.unwrap_err()), ErrorCode::BadRequest);

    // Presence: за раз не больше MAX_PRESENCE_WATCH id, и все — правильной длины.
    let (c, _ev) = Client::connect(&addr).await.unwrap();
    let watch = |ids: Vec<Vec<u8>>| request::Body::PresenceWatch(PresenceWatch { presence_ids: ids });
    let too_many = (0..=MAX_PRESENCE_WATCH).map(|_| random_bytes::<PRESENCE_ID_LEN>().to_vec()).collect();
    assert_eq!(code(c.request(watch(too_many), None).await.unwrap_err()), ErrorCode::BadRequest);
    let bad_len = vec![random_bytes::<PRESENCE_ID_LEN>().to_vec(), vec![0; PRESENCE_ID_LEN + 1]];
    assert_eq!(code(c.request(watch(bad_len), None).await.unwrap_err()), ErrorCode::BadRequest);

    // Неверная длина ключей и id журнала — отказ до записи в базу.
    let pk = Ed25519Key::generate().public_key().to_vec();
    for (log_id, write_pk) in [(vec![0; 31], pk.clone()), (vec![0; 32], vec![0; 31]), (vec![], pk.clone())] {
        let req = request::Body::LogNew(LogNew { log_id, write_pk, read_pk: pk.clone() });
        assert_eq!(code(c.request(req, None).await.unwrap_err()), ErrorCode::BadRequest);
    }
}

#[tokio::test]
async fn request_flood_does_not_block_other_clients() {
    let addr = start(Config::default()).await;
    let (flooder, _ef) = Client::connect(&addr).await.unwrap();
    let flooder = std::sync::Arc::new(flooder);
    let mut tasks = vec![];
    for _ in 0..2000 {
        let f = flooder.clone();
        tasks.push(tokio::spawn(async move {
            let _ = f.request(request::Body::Ping(Ping {}), None).await;
        }));
    }
    // Пока один клиент заваливает ноду запросами, другой обслуживается быстро.
    tokio::time::timeout(Duration::from_secs(5), assert_alive(&addr)).await.expect("нода не отвечает другим");
    for t in tasks {
        t.await.unwrap();
    }
}
