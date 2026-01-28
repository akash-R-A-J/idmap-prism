use anyhow::Result;
use redis::aio::{MultiplexedConnection, PubSub};
use redis::{AsyncCommands, Client};
use serde::Serialize;
use serde_json::Value;
use tokio::sync::broadcast;
use tracing::{error, info};

#[derive(Clone)]
pub struct RedisClient {
    client: Client,
    conn: MultiplexedConnection,
    tx: broadcast::Sender<(String, Value)>, // Internal broadcast bus
}

impl RedisClient {
    pub async fn new(url: &str) -> Result<Self> {
        let client = Client::open(url)?;
        let conn = client.get_multiplexed_async_connection().await?;
        let pubsub_conn = client.get_async_pubsub().await?;

        let (tx, _rx) = broadcast::channel(100); // Buffer 100 messages

        let redis_client = Self {
            client,
            conn,
            tx,
        };

        // Start background listener
        redis_client.spawn_listener(pubsub_conn);

        Ok(redis_client)
    }

    fn spawn_listener(&self, mut pubsub: PubSub) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            info!("Redis background listener started");
            
            // Subscribe to all known topics
            if let Err(e) = pubsub.subscribe("dkg-result").await {
                error!("Failed to subscribe dkg-result: {}", e);
            }
            if let Err(e) = pubsub.subscribe("auditor-dkg-result").await {
                error!("Failed to subscribe auditor-dkg-result: {}", e);
            }
            if let Err(e) = pubsub.subscribe("auditor-decrypt-result").await {
                error!("Failed to subscribe auditor-decrypt-result: {}", e);
            }
             if let Err(e) = pubsub.subscribe("sign-result").await {
                error!("Failed to subscribe sign-result: {}", e);
            }

            use futures::StreamExt;
            let mut stream = pubsub.on_message();

            while let Some(msg) = stream.next().await {
                let channel = msg.get_channel_name().to_string();
                let payload: String = match msg.get_payload() {
                    Ok(p) => p,
                    Err(e) => {
                        error!("Failed to get payload: {}", e);
                        continue;
                    }
                };

                let value: Value = match serde_json::from_str(&payload) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Failed to parse JSON from {}: {}", channel, e);
                        continue;
                    }
                };

                // Broadcast to internal handlers
                if let Err(_e) = tx.send((channel, value)) {
                     // Receiver lag or closed, not critical
                }
            }
        });
    }

    pub async fn publish<T: Serialize>(&self, channel: &str, message: &T) -> Result<()> {
        let payload = serde_json::to_string(message)?;
        let mut conn = self.conn.clone();
        conn.publish::<_, _, ()>(channel, payload).await?;
        Ok(())
    }

    /// Subscribe to the internal broadcast bus to receive Redis messages
    pub fn subscribe_internal(&self) -> broadcast::Receiver<(String, Value)> {
        self.tx.subscribe()
    }
    
    // --- KV Operations for Caching ---
    
    pub async fn get(&self, key: &str) -> Result<Option<String>> {
        let mut conn = self.conn.clone();
        let val: Option<String> = conn.get(key).await?;
        Ok(val)
    }

    pub async fn set(&self, key: &str, value: &str) -> Result<()> {
        let mut conn = self.conn.clone();
        let _: () = conn.set(key, value).await?;
        Ok(())
    }
}
