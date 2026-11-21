//! Opt-in APNs gateway. The API is exposed only over the node's Noise transport.
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use core_crypto::{random_bytes, sha256};
use core_proto::msg::{PushNotify, PushRegister};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::json;
use tokio::{io::AsyncWriteExt, process::Command, sync::mpsc};

use crate::{now_ms, NodeIdentity};

const LIMIT: i64 = 100_000;
const LIFETIME_MS: i64 = 30 * 24 * 60 * 60 * 1000;

pub(crate) struct Gateway {
    db: Arc<Mutex<Connection>>,
    cipher: XChaCha20Poly1305,
    pending: mpsc::Sender<Notification>,
}

struct Notification {
    handle: Vec<u8>,
    token: Vec<u8>,
    sandbox: bool,
    call: Option<Vec<u8>>,
    queued_at: Instant,
}

struct Apns {
    key: SigningKey,
    key_id: String,
    team_id: String,
    topic: String,
    jwt: Option<(Instant, String)>,
}

impl Gateway {
    pub(crate) fn from_env(identity: &NodeIdentity) -> Result<Option<Self>> {
        let Some(database) = std::env::var_os("CORE_PUSH_DB") else { return Ok(None) };
        let key_path = std::env::var_os("APNS_KEY_FILE").map(PathBuf::from).context("APNS_KEY_FILE required")?;
        let pem = std::fs::read_to_string(key_path).context("read APNs signing key")?;
        let provider = Apns {
            key: SigningKey::from_pkcs8_pem(&pem).map_err(|_| anyhow::anyhow!("invalid APNs .p8 key"))?,
            key_id: std::env::var("APNS_KEY_ID")?,
            team_id: std::env::var("APNS_TEAM_ID")?,
            topic: std::env::var("APNS_TOPIC").unwrap_or_else(|_| "org.corenet.app".into()),
            jwt: None,
        };
        ensure!(
            !provider.topic.is_empty()
                && provider.topic.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "invalid APNs topic"
        );
        let (pending, queue) = mpsc::channel(128);
        let gateway = Self::open(Connection::open(database)?, identity, pending)?;
        tokio::spawn(provider.run(queue, gateway.db.clone()));
        Ok(Some(gateway))
    }

    fn open(db: Connection, identity: &NodeIdentity, pending: mpsc::Sender<Notification>) -> Result<Self> {
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS push_targets (
                token_id BLOB PRIMARY KEY, handle BLOB UNIQUE NOT NULL, sealed BLOB NOT NULL,
                sandbox INTEGER NOT NULL, voip INTEGER NOT NULL, expires INTEGER NOT NULL,
                next_send INTEGER NOT NULL DEFAULT 0
            );",
        )?;
        let key = sha256(&[b"CORE/APNs/storage/v1".as_slice(), identity.signing.to_bytes().as_slice()].concat());
        Ok(Self { db: Arc::new(Mutex::new(db)), cipher: XChaCha20Poly1305::new((&key).into()), pending })
    }

    pub(crate) fn register(&self, request: &PushRegister) -> Result<Vec<u8>> {
        ensure!((16..=128).contains(&request.token.len()), "invalid APNs token");
        let nonce = random_bytes::<24>();
        let sealed = self
            .cipher
            .encrypt(XNonce::from_slice(&nonce), request.token.as_slice())
            .map_err(|_| anyhow::anyhow!("failed to protect token"))?;
        ensure!(request.scope.is_empty() || request.scope.len() == 16, "invalid registration scope");
        let token_id = sha256(
            &[&[request.sandbox as u8, request.voip as u8], request.scope.as_slice(), request.token.as_slice()]
                .concat(),
        );
        let handle = random_bytes::<32>();
        let db = self.db.lock().unwrap();
        let now = now_ms() as i64;
        db.execute("DELETE FROM push_targets WHERE expires <= ?", [now])?;
        db.execute(
            "INSERT INTO push_targets (token_id, handle, sealed, sandbox, voip, expires)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6
             WHERE EXISTS (SELECT 1 FROM push_targets WHERE token_id = ?1)
                OR (SELECT COUNT(*) FROM push_targets) < ?7
             ON CONFLICT(token_id) DO UPDATE SET expires = excluded.expires",
            params![
                token_id,
                handle,
                [&nonce[..], &sealed].concat(),
                request.sandbox,
                request.voip,
                now + LIFETIME_MS,
                LIMIT
            ],
        )?;
        Ok(db.query_row("SELECT handle FROM push_targets WHERE token_id = ?", [token_id], |row| row.get(0))?)
    }

    pub(crate) fn notify(&self, request: &PushNotify) -> Result<()> {
        ensure!(request.capability.len() == 32, "invalid capability");
        let db = self.db.lock().unwrap();
        let now = now_ms() as i64;
        let target = db
            .query_row(
                "SELECT sealed, sandbox, voip, next_send FROM push_targets WHERE handle = ? AND expires > ?",
                params![request.capability, now],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, bool>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?;
        let Some((sealed, sandbox, voip, next_send)) = target else { bail!("invalid capability") };
        ensure!(if voip { request.call_id.len() == 12 } else { request.call_id.is_empty() }, "invalid push kind");
        if next_send > now {
            return Ok(());
        }
        let (nonce, data) = sealed.split_at_checked(24).context("invalid token envelope")?;
        let token = self
            .cipher
            .decrypt(XNonce::from_slice(nonce), data)
            .map_err(|_| anyhow::anyhow!("invalid token envelope"))?;
        self.pending
            .try_send(Notification {
                handle: request.capability.clone(),
                token,
                sandbox,
                call: voip.then(|| request.call_id.clone()),
                queued_at: Instant::now(),
            })
            .map_err(|_| anyhow::anyhow!("push queue full"))?;
        db.execute("UPDATE push_targets SET next_send = ? WHERE handle = ?", params![now + 3_000, request.capability])?;
        Ok(())
    }
}

impl Apns {
    fn jwt(&mut self) -> &str {
        if self.jwt.as_ref().is_none_or(|(issued, _)| issued.elapsed() >= Duration::from_secs(45 * 60)) {
            let header = URL_SAFE_NO_PAD.encode(json!({"alg":"ES256","kid":self.key_id}).to_string());
            let claims = URL_SAFE_NO_PAD.encode(json!({"iss":self.team_id,"iat":now_ms()/1000}).to_string());
            let message = format!("{header}.{claims}");
            let signature: Signature = self.key.sign(message.as_bytes());
            self.jwt = Some((Instant::now(), format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))));
        }
        &self.jwt.as_ref().unwrap().1
    }

    async fn run(mut self, mut queue: mpsc::Receiver<Notification>, db: Arc<Mutex<Connection>>) {
        while let Some(item) = queue.recv().await {
            if item.call.is_some() && item.queued_at.elapsed() > Duration::from_secs(5) {
                continue;
            }
            let mut result = self.send(&item).await;
            if item.call.is_none() && (result.is_err() || matches!(result, Ok(500..=599))) {
                tokio::time::sleep(Duration::from_secs(1)).await;
                result = self.send(&item).await;
            }
            match result {
                Ok(200) => {}
                Ok(410) => {
                    if db.lock().unwrap().execute("DELETE FROM push_targets WHERE handle = ?", [item.handle]).is_err() {
                        tracing::warn!("failed to remove expired APNs token");
                    }
                }
                Ok(status) => tracing::warn!(status, "APNs rejected notification"),
                Err(_) => tracing::warn!("APNs transport failed"),
            }
        }
    }

    async fn send(&mut self, item: &Notification) -> Result<u16> {
        let host = if item.sandbox { "api.sandbox.push.apple.com" } else { "api.push.apple.com" };
        let endpoint = format!("https://{host}/3/device/{}", hex::encode(&item.token));
        let (topic, push_type, priority, expires, payload) = if let Some(id) = &item.call {
            (format!("{}.voip", self.topic), "voip", "10", 0, json!({"aps":{},"call":hex::encode(id)}))
        } else {
            (
                self.topic.clone(),
                "alert",
                "10",
                now_ms() / 1000 + 300,
                json!({"aps":{"alert":{"title":"CORE","loc-key":"Новое сообщение"},"sound":"default"}}),
            )
        };
        let jwt = self.jwt();
        // Curl's stdin config keeps the device token and authorization header out of argv.
        let config = [
            ("url", endpoint),
            ("header", format!("authorization: bearer {jwt}")),
            ("header", format!("apns-topic: {topic}")),
            ("header", format!("apns-push-type: {push_type}")),
            ("header", format!("apns-priority: {priority}")),
            ("header", format!("apns-expiration: {expires}")),
            ("header", "content-type: application/json".into()),
            ("data-binary", payload.to_string()),
        ]
        .into_iter()
        .map(|(key, value)| format!("{key} = {}\n", json!(value)))
        .collect::<String>();
        let mut child = Command::new("curl")
            .args([
                "--disable",
                "--http2",
                "--proto",
                "=https",
                "--max-time",
                "8",
                "--silent",
                "--output",
                "/dev/null",
                "--write-out",
                "%{http_code}",
                "--config",
                "-",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        child.stdin.take().context("curl stdin")?.write_all(config.as_bytes()).await?;
        let output = child.wait_with_output().await?;
        ensure!(output.status.success(), "curl failed");
        Ok(std::str::from_utf8(&output.stdout)?.parse()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_are_scoped_and_tokens_are_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("push.db");
        let identity = NodeIdentity::generate();
        let (sender, mut receiver) = mpsc::channel(4);
        let token = vec![0xab; 32];
        let request = PushRegister { token: token.clone(), sandbox: true, voip: true, scope: vec![9; 16] };
        let gateway = Gateway::open(Connection::open(&path).unwrap(), &identity, sender.clone()).unwrap();
        let capability = gateway.register(&request).unwrap();
        assert_eq!(capability, gateway.register(&request).unwrap());
        let normal = gateway.register(&PushRegister { voip: false, ..request.clone() }).unwrap();
        assert_ne!(normal, capability);
        drop(gateway);

        assert!(!std::fs::read(&path).unwrap().windows(token.len()).any(|window| window == token));
        let gateway = Gateway::open(Connection::open(&path).unwrap(), &identity, sender).unwrap();
        assert!(gateway.notify(&PushNotify { capability: vec![0; 32], call_id: vec![1; 12] }).is_err());
        assert!(gateway.notify(&PushNotify { capability: normal, call_id: vec![1; 12] }).is_err());
        let call = PushNotify { capability, call_id: vec![1; 12] };
        gateway.notify(&call).unwrap();
        gateway.notify(&call).unwrap();
        let item = receiver.try_recv().unwrap();
        assert_eq!(item.token, token);
        assert!(item.sandbox);
        assert_eq!(item.call, Some(call.call_id));
        assert!(receiver.try_recv().is_err());
    }
}

/// Mailboxes use an operator-pinned address; clients cannot make a mailbox dial an arbitrary host.
pub(crate) fn forwarder() -> std::io::Result<Option<mpsc::Sender<PushNotify>>> {
    let Ok(raw) = std::env::var("CORE_PUSH_GATEWAY") else { return Ok(None) };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    let address: core_net::NodeAddr = raw.parse().map_err(std::io::Error::other)?;
    let (sender, mut receiver) = mpsc::channel::<PushNotify>(256);
    tokio::spawn(async move {
        let mut conn: Option<core_net::Client> = None;
        while let Some(notification) = receiver.recv().await {
            if conn.is_none() {
                let dial = tokio::time::timeout(Duration::from_secs(3), core_net::Client::connect(&address)).await;
                if let Ok(Ok((client, _events))) = dial {
                    conn = Some(client);
                }
            }
            if let Some(client) = &conn {
                let request = client.request(core_proto::msg::request::Body::PushNotify(notification), None);
                if !matches!(tokio::time::timeout(Duration::from_secs(3), request).await, Ok(Ok(_))) {
                    conn = None;
                }
            }
        }
    });
    Ok(Some(sender))
}
