//! CLI для разработки: проверить, что нода жива и mailbox работает.

use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use core_crypto::{random_bytes, Ed25519Key};
use core_net::{Client, NodeAddr};
use core_proto::msg::{
    event, request, response, Event, LogAppend, LogCommit, LogNew, LogRead, NetSnapshot, Ping, QueueAck, QueueNew,
    QueueSecure, QueueSend, QueueSub,
};
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(name = "core-cli", version, about = "CLI-клиент CORE")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Измерить задержку до ноды.
    Ping {
        /// core://<ключ>@host:port
        addr: NodeAddr,
        #[arg(short, long, default_value_t = 3)]
        count: u32,
    },
    /// Прогнать сценарий: очередь (создать → закрепить → отправить → получить → ACK) и журнал.
    Demo { addr: NodeAddr },
    /// Показать сеть глазами ноды: ноды, связи, клиенты (подписи проверяются локально).
    Net { addr: NodeAddr },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Ping { addr, count } => ping(&addr, count).await,
        Command::Demo { addr } => demo(&addr).await,
        Command::Net { addr } => net(&addr).await,
    }
}

async fn ping(addr: &NodeAddr, count: u32) -> anyhow::Result<()> {
    let started = Instant::now();
    let (client, _events) = Client::connect(addr).await.context("подключение")?;
    println!("соединение + Noise: {:?}", started.elapsed());
    for i in 1..=count {
        let t = Instant::now();
        client.request(request::Body::Ping(Ping {}), None).await?;
        println!("ping #{i}: {:?}", t.elapsed());
    }
    Ok(())
}

async fn demo(addr: &NodeAddr) -> anyhow::Result<()> {
    let (client, mut events) = Client::connect(addr).await.context("подключение")?;
    println!("✓ подключено к {addr}");

    // ── Очередь ──
    let recipient = Ed25519Key::generate();
    let sender = Ed25519Key::generate();
    let response::Body::QueueCreated(q) = client
        .request(request::Body::QueueNew(QueueNew { recipient_auth_pk: recipient.public_key().to_vec() }), None)
        .await?
    else {
        bail!("неожиданный ответ на QueueNew")
    };
    println!(
        "✓ очередь: recipient_id={}… sender_id={}…",
        &hex::encode(&q.recipient_id)[..12],
        &hex::encode(&q.sender_id)[..12]
    );

    client
        .request(
            request::Body::QueueSecure(QueueSecure {
                recipient_id: q.recipient_id.clone(),
                sender_auth_pk: sender.public_key().to_vec(),
            }),
            Some(&recipient),
        )
        .await?;
    println!("✓ ключ отправителя закреплён");

    client
        .request(request::Body::QueueSub(QueueSub { recipient_id: q.recipient_id.clone() }), Some(&recipient))
        .await?;
    for text in ["привет", "это CORE"] {
        client
            .request(
                request::Body::QueueSend(QueueSend { sender_id: q.sender_id.clone(), body: text.as_bytes().to_vec() }),
                Some(&sender),
            )
            .await?;
    }
    for _ in 0..2 {
        let Some(event::Body::QueueMessage(m)) = next_event(&mut events).await?.body else {
            bail!("ожидалось сообщение очереди")
        };
        println!("✓ получено: {:?}", String::from_utf8_lossy(&m.body));
        client
            .request(
                request::Body::QueueAck(QueueAck { recipient_id: q.recipient_id.clone(), msg_id: m.msg_id }),
                Some(&recipient),
            )
            .await?;
    }
    println!("✓ ACK — сообщения удалены с ноды");

    // ── Журнал ──
    let log_id = random_bytes::<32>().to_vec();
    let write = Ed25519Key::generate();
    let read = Ed25519Key::generate();
    client
        .request(
            request::Body::LogNew(LogNew {
                log_id: log_id.clone(),
                write_pk: write.public_key().to_vec(),
                read_pk: read.public_key().to_vec(),
            }),
            None,
        )
        .await?;
    for text in ["первое", "второе"] {
        client
            .request(
                request::Body::LogAppend(LogAppend {
                    log_id: log_id.clone(),
                    blob: text.as_bytes().to_vec(),
                    ..Default::default()
                }),
                Some(&write),
            )
            .await?;
    }
    let commit = |blob: &str| {
        request::Body::LogCommit(LogCommit { log_id: log_id.clone(), epoch: 1, blob: blob.as_bytes().to_vec() })
    };
    client.request(commit("коммит Алисы"), Some(&write)).await?;
    match client.request(commit("коммит Боба"), Some(&write)).await? {
        response::Body::CommitConflict(c) => {
            let winner = c.winner.map(|w| String::from_utf8_lossy(&w.blob).into_owned()).unwrap_or_default();
            println!("✓ второй коммит на эпоху 1 отклонён, победитель: {winner:?}");
        }
        other => bail!("ожидался CommitConflict, получено {other:?}"),
    }
    let response::Body::LogEntries(entries) = client
        .request(request::Body::LogRead(LogRead { log_id: log_id.clone(), from_offset: 0, limit: 100 }), Some(&read))
        .await?
    else {
        bail!("неожиданный ответ на LogRead")
    };
    println!("✓ журнал ({} записей):", entries.entries.len());
    for e in entries.entries {
        println!("    #{} kind={} {:?}", e.offset, e.kind, String::from_utf8_lossy(&e.blob));
    }
    println!("готово");
    Ok(())
}

async fn net(addr: &NodeAddr) -> anyhow::Result<()> {
    let (client, _events) = Client::connect(addr).await.context("подключение")?;
    let mut nodes = vec![];
    let mut cursor = vec![];
    let self_id = loop {
        let response::Body::NetSnapshotReply(r) =
            client.request(request::Body::NetSnapshot(NetSnapshot { cursor }), None).await?
        else {
            bail!("неожиданный ответ на NetSnapshot")
        };
        let total = r.nodes.len();
        nodes.extend(r.nodes);
        if r.next_cursor.is_empty() || total == 0 {
            break r.self_id;
        }
        cursor = r.next_cursor;
    };
    let received = nodes.len();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis() as u64;
    let dir = core_directory::verify_snapshot(nodes, now);
    let short = |id: &[u8]| hex::encode(&id[..4]);

    println!("🗺️  сеть глазами {} ({} записей, подписи верны у {})", short(&self_id), received, dir.len());
    for (id, e) in dir.iter() {
        let d = &e.descriptor;
        let status = if e.is_online(now) { "🟢" } else { "⚪" };
        let me = if id.as_slice() == self_id.as_slice() { " ← эта нода" } else { "" };
        let (clients, load, uptime) = e.stats.as_ref().map_or((0, 0, 0), |s| (s.clients_online, s.load, s.uptime_secs));
        println!(
            "  {status} ▲ {} {:<8} {:<3} клиентов≈{clients:<4} нагрузка={load}/10 аптайм={uptime}с  {}{me}",
            short(id),
            if d.name.is_empty() { "—" } else { &d.name },
            if d.region.is_empty() { "—" } else { &d.region },
            d.addresses.join(", "),
        );
    }
    let links = core_directory::mutual_links(&dir);
    println!("🔗 связи (подтверждены обеими сторонами): {}", links.len());
    for (a, b) in links {
        println!("     {} ━━ {}", short(&a), short(&b));
    }
    Ok(())
}

async fn next_event(events: &mut mpsc::Receiver<Event>) -> anyhow::Result<Event> {
    tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .context("таймаут ожидания события")?
        .context("соединение закрыто")
}
