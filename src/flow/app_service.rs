use crate::constants::*;
use crate::external::mongo::*;
use crate::external::mq::*;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDaoImpl;
use millegrilles_common_rust::openssl::pkey::{PKey, Private};
use millegrilles_common_rust::tokio;
use millegrilles_common_rust::tokio::task::JoinSet;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::tracing::{debug, error, info};
use millegrilles_common_rust::v3::facades::message_inbound::MessageInboundValidator;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::impls::backup_restorer::RestorationState;
use millegrilles_common_rust::v3::impls::config_service::ConfigServiceDbImpl;
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;
use millegrilles_common_rust::v3::{BackupService, ChiffrageService, ConfigService, PkiService};
use std::sync::Arc;
use crate::flow::backup::process_backup;
use crate::flow::commands::{process_command, process_transaction};
use crate::flow::maintenance::process_ticker_job;
use crate::flow::presence::process_presence_event;
use crate::flow::requests::process_request;
use crate::flow::transactions::TopologyTransactionService;

/// Handles queue consumer threads, calls individual routing methods
pub struct ApplicationService {
    pki: Arc<dyn PkiService>,
    config: Arc<dyn ConfigService>,
    chiffrage: Arc<dyn ChiffrageService>,
    outbound: Arc<MessageOutboundFacade>,
    transaction: Arc<TopologyTransactionService>,
    mongo: Arc<MongoDaoImpl>,
    backup: Arc<dyn BackupService>,
}

impl ApplicationService {
    pub fn new(
        pki: Arc<dyn PkiService>,
        config: Arc<dyn ConfigService>,
        chiffrage: Arc<dyn ChiffrageService>,
        outbound: Arc<MessageOutboundFacade>,
        transaction: Arc<TopologyTransactionService>,
        mongo: Arc<MongoDaoImpl>,
        backup: Arc<dyn BackupService>,
    ) -> Self {
        Self {
            pki,
            config,
            chiffrage,
            outbound,
            transaction,
            mongo,
            backup,
        }
    }

    pub async fn configure(&self, mq: &MessagingServiceImpl, config: &ConfigServiceDbImpl) -> Result<(), CommonError> {
        init_queues(mq)?;
        create_index_mongodb(self.mongo.as_ref(), config.config.as_ref()).await?;
        Ok(())
    }

    /// Call to spawn the consumer threads
    pub fn start(self: Arc<Self>, join_set: &mut JoinSet<()>, incoming: Arc<MessageInboundValidator>) -> Result<(), CommonError> {

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_ticker_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_requests_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_volatiles_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_presence_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_filehosts_batch_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_filecontroler_events_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_transaction_thread(incoming_clone).await});

        let self_clone = self.clone();
        let incoming_clone = incoming.clone();
        join_set.spawn(async move {self_clone.process_backup_thread(incoming_clone).await});

        Ok(())
    }
    
    async fn process_ticker_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAIN_NAME, QUEUE_TICKER).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = process_ticker_job(
                        self.outbound.as_ref(),
                        self.backup.as_ref(),
                        message
                    ).await {
                        error!("Ticker job failed: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error processing ticker message: {}", e);
                }
            }
        }
        debug!("process_ticker_thread Closed");
    }
    
    // Requests
    async fn process_requests_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAIN_NAME, QUEUE_REQUESTS).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    let routing = message.message.routage.clone();
                    if let Err(e) = process_request(
                        self.mongo.as_ref(),
                        self.outbound.as_ref(),
                        self.config.as_ref(),
                        self.chiffrage.as_ref(),
                        message
                    ).await {
                        error!("Request {:?} failed: {}", routing, e);
                    }
                }
                Err(e) => {
                    error!("Error processing request message: {}", e);
                }
            }
        }
        debug!("process_requests_thread Closed");
    }

    // pub const QUEUE_VOLATILES: &str = "volatiles";
    async fn process_volatiles_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAIN_NAME, QUEUE_VOLATILES).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    let routing = message.message.routage.clone();
                    todo!()
                    // if let Err(e) = process_request(
                    //     self.mongo.as_ref(),
                    //     self.outbound.as_ref(),
                    //     message
                    // ).await {
                    //     error!("Request {:?} failed: {}", routing, e);
                    // }
                }
                Err(e) => {
                    error!("Error processing request message: {}", e);
                }
            }
        }
        debug!("process_requests_thread Closed");
    }

    // pub const QUEUE_PRESENCE: &str = "presence";
    async fn process_presence_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAIN_NAME, QUEUE_PRESENCE).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    let routing = message.message.routage.clone();
                    if let Err(e) = process_presence_event(self.mongo.as_ref(), message).await {
                        error!("Presence event {:?} handling failed: {}", routing, e);
                    }
                }
                Err(e) => {
                    error!("Error processing presence event: {}", e);
                }
            }
        }
        debug!("process_presence_thread Closed");
    }

    // pub const QUEUE_FILEHOSTS_BATCH: &str = "filehostsBatch";
    async fn process_filehosts_batch_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAIN_NAME, QUEUE_FILEHOSTS_BATCH).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    let routing = message.message.routage.clone();
                    todo!()
                    // if let Err(e) = process_request(
                    //     self.mongo.as_ref(),
                    //     self.outbound.as_ref(),
                    //     message
                    // ).await {
                    //     error!("Request {:?} failed: {}", routing, e);
                    // }
                }
                Err(e) => {
                    error!("Error processing request message: {}", e);
                }
            }
        }
        debug!("process_requests_thread Closed");
    }

    // pub const QUEUE_FILECONTROLER_EVENTS: &str = "filecontrolerEvents";
    async fn process_filecontroler_events_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAIN_NAME, QUEUE_FILECONTROLER_EVENTS).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    let routing = message.message.routage.clone();
                    todo!()
                    // if let Err(e) = process_request(
                    //     self.mongo.as_ref(),
                    //     self.outbound.as_ref(),
                    //     message
                    // ).await {
                    //     error!("Request {:?} failed: {}", routing, e);
                    // }
                }
                Err(e) => {
                    error!("Error processing request message: {}", e);
                }
            }
        }
        debug!("process_requests_thread Closed");
    }

    // Transactions
    async fn process_transaction_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAIN_NAME, QUEUE_TRANSACTIONS).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = process_transaction(
                        self.mongo.as_ref(),
                        self.pki.as_ref(),
                        self.outbound.as_ref(),
                        self.transaction.as_ref(),
                        message
                    ).await {
                        error!("Transaction job failed: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error processing transaction message: {}", e);
                }
            }
        }
        debug!("process_transaction_thread Closed");
    }

    async fn process_backup_thread(&self, incoming: Arc<MessageInboundValidator>) {
        let streamer = incoming.consume_named_queue(
            format!("{}/{}", DOMAIN_NAME, QUEUE_BACKUP).as_str(),
        ).expect("Consumer streaming init failed");
        tokio::pin!(streamer);
        while let Some(result) = streamer.next().await {
            match result {
                Ok(message) => {
                    if let Err(e) = process_backup(
                        self.outbound.as_ref(),
                        self.backup.as_ref(),
                        message
                    ).await {
                        error!("Reading job failed: {}", e);
                    }
                }
                Err(e) => {
                    error!("Error processing reading message: {}", e);
                }
            }
        }
        debug!("process_readings_thread Closed");
    }

    pub async fn restore(
        &self,
        master_key: Option<&PKey<Private>>,
        resume: bool,
        version: Option<String>,
    ) -> Result<RestorationState, CommonError> {
        // Wait for reply q (certificate queries)
        self.outbound.wait_ready(Some(20_000)).await?;

        let start_time = Utc::now();
        let result = self.backup.restore_domain(
            DOMAIN_NAME,
            COLLECTION_NAME_REDOLOG,
            COLLECTION_NAME_TRACKING,
            resume,
            true,   // This is the domain that handles certificates, can't check while resuming
            version,
            master_key,
        ).await?;
        let duration = Utc::now() - start_time;
        info!("restore_domain duration: {} ms", duration.num_milliseconds());

        Ok(result)
    }

}
