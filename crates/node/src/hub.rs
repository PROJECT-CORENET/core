//! Рассылка новых сообщений/записей подписчикам внутри процесса ноды.

use std::collections::HashMap;
use std::sync::Mutex;

use core_proto::msg::{LogEntry, PresenceUpdate, QueueMessage};
use tokio::sync::broadcast;

const CHANNEL_CAPACITY: usize = 64;

/// Сообщение очереди + его внутренний порядковый номер (для дедупликации у подписчика).
pub type QueueItem = (i64, QueueMessage);

#[derive(Default)]
pub struct Hub {
    queues: Mutex<HashMap<Vec<u8>, broadcast::Sender<QueueItem>>>,
    logs: Mutex<HashMap<Vec<u8>, broadcast::Sender<LogEntry>>>,
    presence: Mutex<HashMap<Vec<u8>, broadcast::Sender<PresenceUpdate>>>,
}

impl Hub {
    pub fn subscribe_queue(&self, recipient_id: &[u8]) -> broadcast::Receiver<QueueItem> {
        subscribe(&self.queues, recipient_id)
    }

    pub fn publish_queue(&self, recipient_id: &[u8], item: QueueItem) {
        publish(&self.queues, recipient_id, item)
    }

    pub fn subscribe_log(&self, log_id: &[u8]) -> broadcast::Receiver<LogEntry> {
        subscribe(&self.logs, log_id)
    }

    pub fn publish_log(&self, log_id: &[u8], entry: LogEntry) {
        publish(&self.logs, log_id, entry)
    }

    pub fn subscribe_presence(&self, presence_id: &[u8]) -> broadcast::Receiver<PresenceUpdate> {
        subscribe(&self.presence, presence_id)
    }

    pub fn publish_presence(&self, presence_id: &[u8], update: PresenceUpdate) {
        publish(&self.presence, presence_id, update)
    }
}

fn subscribe<T: Clone>(map: &Mutex<HashMap<Vec<u8>, broadcast::Sender<T>>>, id: &[u8]) -> broadcast::Receiver<T> {
    map.lock().unwrap().entry(id.to_vec()).or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0).subscribe()
}

fn publish<T: Clone>(map: &Mutex<HashMap<Vec<u8>, broadcast::Sender<T>>>, id: &[u8], item: T) {
    let mut map = map.lock().unwrap();
    if let Some(tx) = map.get(id) {
        // Ошибка = подписчиков больше нет: канал больше не нужен.
        if tx.send(item).is_err() {
            map.remove(id);
        }
    }
}
