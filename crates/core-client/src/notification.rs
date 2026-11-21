//! A push preview uses a separate key from the current MLS epoch. Only group members can
//! decrypt it, and the MLS leaf signature binds it to the sending device.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use openmls_traits::signatures::Signer;
use serde::Serialize;

use super::*;

const LABEL: &str = "CORE/v1/notification-preview";
const SIGN_DOMAIN: &[u8] = b"CORE notification preview v1\0";

#[derive(Serialize)]
struct Preview<'a> {
    text: String,
    id: &'a str,
    sent_ms: u64,
    kind: Option<&'a str>,
    thumb: Option<String>,
}

#[derive(Serialize)]
struct NotificationKey {
    chat: String,
    key: String,
    members: HashMap<String, String>,
}

fn preview_key(engine: &Engine, group: &MlsGroup) -> Result<[u8; 32]> {
    let key = group.export_secret(engine.provider.crypto(), LABEL, &[], 32).map_err(mls)?;
    key.try_into().map_err(|_| Error::Other("invalid notification key".into()))
}

impl Client {
    /// Export only notification-specific epoch keys and authenticated public leaf keys.
    pub async fn notification_keys(&self, chat_ids: &[String]) -> Result<String> {
        let inner = &self.inner;
        let engine = inner.engine.lock().await;
        let mut entries = vec![];
        for id in chat_ids {
            let Some(chat) = inner.store.chat(id)?.filter(|chat| chat.state == ChatState::Active) else { continue };
            if inner.saved_id().as_deref() == Some(id) {
                continue;
            }
            let Ok(group) = engine.group(&chat) else { continue };
            if !group.is_active() {
                continue;
            }
            let key = preview_key(&engine, &group)?;
            let members = group
                .members()
                .filter_map(|m| {
                    let id = std::str::from_utf8(m.credential.serialized_content()).ok()?;
                    Some((STANDARD.encode(m.signature_key), id.to_owned()))
                })
                .collect();
            entries.push(NotificationKey { chat: id.clone(), key: STANDARD.encode(key), members });
        }
        serde_json::to_string(&entries).map_err(|e| Error::Other(e.to_string()))
    }
}

pub(super) fn seal_preview(engine: &Engine, group: &MlsGroup, payload: &Payload) -> Result<Vec<u8>> {
    let Payload::Message { id, text, att, .. } = payload else { return Ok(vec![]) };
    let key = preview_key(engine, group)?;
    let hash = core_crypto::sha256(&key);
    let tag = &hash[..12];
    let nonce = random_bytes::<12>();
    let mut preview = Preview {
        text: if text.contains("||") { String::new() } else { text.chars().take(180).collect() },
        id,
        sent_ms: now_ms(),
        kind: att.as_ref().map(|a| a.kind.as_str()),
        thumb: att
            .as_ref()
            .filter(|a| !a.spoiler)
            .and_then(|a| a.notification_thumb.as_ref().or(a.thumb.as_ref()))
            .filter(|thumb| thumb.len() <= 1_350)
            .map(|thumb| STANDARD.encode(thumb)),
    };
    if att.as_ref().is_some_and(|a| a.spoiler) {
        preview.text.clear();
    }
    let encode = |p: &Preview<'_>| serde_json::to_vec(p).map_err(|e| Error::Other(e.to_string()));
    let mut bytes = encode(&preview)?;
    const OVERHEAD: usize = 12 + 12 + 32 + 64 + 16;
    if bytes.len() + OVERHEAD > core_proto::msg::MAX_PUSH_PREVIEW {
        preview.thumb = None;
        bytes = encode(&preview)?;
    }
    if bytes.len() + OVERHEAD > core_proto::msg::MAX_PUSH_PREVIEW {
        return Ok(vec![]);
    }
    let signature = engine
        .signer
        .sign(&[SIGN_DOMAIN, tag, &bytes].concat())
        .map_err(|_| Error::Other("notification signature failed".into()))?;
    let plaintext = [engine.signer.to_public_vec().as_slice(), &signature, &bytes].concat();
    let sealed = ChaCha20Poly1305::new((&key).into())
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| Error::Other("notification encryption failed".into()))?;
    Ok([tag, &nonce, &sealed].concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_preview_omits_spoiler_text_and_media() {
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
        let provider = OpenMlsRustCrypto::default();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(b"sender".to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let engine = Engine { provider, signer, credential };
        let group =
            MlsGroup::new(&engine.provider, &engine.signer, &Engine::create_config(), engine.credential.clone())
                .unwrap();
        let preview_payload = |text: &str, spoiler| Payload::Message {
            id: "message".into(),
            ts: now_ms(),
            text: text.into(),
            att: Some(Box::new(AttachmentRef {
                kind: "photo".into(),
                notification_thumb: Some(vec![1, 2, 3]),
                spoiler,
                ..Default::default()
            })),
            reply_to: None,
            link: None,
            fwd: None,
            fwd_id: None,
        };
        let key = preview_key(&engine, &group).unwrap();
        let unpack = |payload: &Payload| {
            let packet = seal_preview(&engine, &group, payload).unwrap();
            let (tag, tail) = packet.split_at(12);
            assert_eq!(tag, &core_crypto::sha256(&key)[..12]);
            let (nonce, sealed) = tail.split_at(12);
            let plain = ChaCha20Poly1305::new((&key).into()).decrypt(Nonce::from_slice(nonce), sealed).unwrap();
            let bytes = &plain[96..];
            assert!(core_crypto::verify(&plain[..32], &[SIGN_DOMAIN, tag, bytes].concat(), &plain[32..96]));
            serde_json::from_slice::<serde_json::Value>(bytes).unwrap()
        };
        let visible = unpack(&preview_payload("hello", false));
        assert_eq!(visible["text"], "hello");
        assert_eq!(visible["thumb"], "AQID");
        let hidden_media = unpack(&preview_payload("caption", true));
        assert!(hidden_media["thumb"].is_null());
        let hidden_text = unpack(&preview_payload("||secret||", false));
        assert_eq!(hidden_text["text"], "");
    }
}
