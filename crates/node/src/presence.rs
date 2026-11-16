//! Статусы «в сети» (§15.2): только последняя запись, в памяти, без истории.
//!
//! Нода видит, что `presence_id` активен, но не знает, чей он, и не может прочитать
//! статус — он зашифрован ключом, который есть только у допущенных контактов.

use std::collections::HashMap;

use core_proto::msg::PresenceUpdate;

/// Максимальный TTL одного heartbeat.
pub const MAX_PRESENCE_TTL_SECS: u32 = 300;
/// Сколько `presence_id` остаётся закреплён за ключом без новых PUT.
const BINDING_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const MAX_SLOTS: usize = 1_000_000;

#[derive(Debug, PartialEq, Eq)]
pub enum PresenceError {
    /// `presence_id` закреплён за другим ключом.
    WrongKey,
    Full,
}

struct Slot {
    write_pk: Vec<u8>,
    sealed: Vec<u8>,
    online: bool,
    online_until_ms: u64,
    updated_at_ms: u64,
    last_put_ms: u64,
}

impl Slot {
    fn update(&self, id: &[u8]) -> PresenceUpdate {
        PresenceUpdate {
            presence_id: id.to_vec(),
            online: self.online,
            sealed: self.sealed.clone(),
            updated_at_ms: self.updated_at_ms,
        }
    }
}

#[derive(Default)]
pub struct PresenceTable {
    slots: HashMap<Vec<u8>, Slot>,
}

impl PresenceTable {
    /// Heartbeat. Возвращает обновление для подписчиков, если что-то изменилось.
    pub fn put(
        &mut self,
        id: &[u8],
        write_pk: &[u8],
        sealed: &[u8],
        ttl_secs: u32,
        now: u64,
    ) -> Result<Option<PresenceUpdate>, PresenceError> {
        let online = ttl_secs > 0;
        let online_until_ms = now + ttl_secs.min(MAX_PRESENCE_TTL_SECS) as u64 * 1000;
        if let Some(slot) = self.slots.get_mut(id) {
            if slot.write_pk != write_pk {
                return Err(PresenceError::WrongKey);
            }
            let changed = slot.online != online || slot.sealed != sealed;
            slot.online = online;
            slot.online_until_ms = online_until_ms;
            slot.last_put_ms = now;
            if !changed {
                return Ok(None);
            }
            slot.sealed = sealed.to_vec();
            slot.updated_at_ms = now;
            return Ok(Some(slot.update(id)));
        }
        if self.slots.len() >= MAX_SLOTS {
            return Err(PresenceError::Full);
        }
        let slot = Slot {
            write_pk: write_pk.to_vec(),
            sealed: sealed.to_vec(),
            online,
            online_until_ms,
            updated_at_ms: now,
            last_put_ms: now,
        };
        let update = slot.update(id);
        self.slots.insert(id.to_vec(), slot);
        Ok(Some(update))
    }

    pub fn get(&self, id: &[u8]) -> Option<PresenceUpdate> {
        self.slots.get(id).map(|s| s.update(id))
    }

    /// Перевести в офлайн тех, чей heartbeat истёк; забыть давно брошенные слоты.
    pub fn expire(&mut self, now: u64) -> Vec<PresenceUpdate> {
        let mut went_offline = vec![];
        for (id, slot) in self.slots.iter_mut() {
            if slot.online && slot.online_until_ms <= now {
                slot.online = false;
                slot.updated_at_ms = now;
                went_offline.push(slot.update(id));
            }
        }
        self.slots.retain(|_, s| s.last_put_ms + BINDING_TTL_MS > now);
        went_offline
    }

    pub fn online_count(&self) -> usize {
        self.slots.values().filter(|s| s.online).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &[u8] = &[1; 16];
    const PK: &[u8] = &[2; 32];

    #[test]
    fn heartbeat_and_expiry() {
        let mut t = PresenceTable::default();
        let first = t.put(ID, PK, b"s1", 60, 0).unwrap().unwrap();
        assert!(first.online);
        // Тот же статус — подписчиков не дёргаем.
        assert!(t.put(ID, PK, b"s1", 60, 30_000).unwrap().is_none());
        assert!(t.expire(80_000).is_empty());
        let off = t.expire(90_000);
        assert_eq!(off.len(), 1);
        assert!(!off[0].online);
        assert_eq!(off[0].sealed, b"s1");
        assert!(t.put(ID, PK, b"s1", 60, 95_000).unwrap().unwrap().online);
        // Явный уход офлайн.
        assert!(!t.put(ID, PK, b"s1", 0, 96_000).unwrap().unwrap().online);
    }

    #[test]
    fn slot_is_bound_to_key() {
        let mut t = PresenceTable::default();
        t.put(ID, PK, b"x", 60, 0).unwrap();
        assert_eq!(t.put(ID, &[3; 32], b"evil", 60, 1).unwrap_err(), PresenceError::WrongKey);
        // Брошенный слот освобождается.
        t.expire(BINDING_TTL_MS + 1);
        assert!(t.put(ID, &[3; 32], b"new owner", 60, BINDING_TTL_MS + 2).is_ok());
    }
}
