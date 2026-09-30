use crate::constants::*;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::rabbitmq_dao::{ConfigQueue, ConfigRoutingExchange};
use millegrilles_common_rust::v3::impls::messaging_service::MessagingServiceImpl;

pub const QUEUE_TTL_DEFAULT: u32 = 30_000;
pub const QUEUE_TTL_FILEHOSTS: u32 = 30 * 60_000;
pub const QUEUE_TTL_PRESENCE: u32 = 5_000;
pub const QUEUE_TICKER: &str = "job_ticker";
pub const QUEUE_REQUESTS: &str = "requests";
pub const QUEUE_VOLATILES: &str = "volatiles";
pub const QUEUE_PRESENCE: &str = "presence";
pub const QUEUE_FILEHOSTS_BATCH: &str = "filehostsBatch";
pub const QUEUE_FILECONTROLER_EVENTS: &str = "filecontrolerEvents";
pub const QUEUE_TRANSACTIONS: &str = "transactions";
pub const QUEUE_BACKUP: &str = "backup";

// Requests
pub const REQUETE_USERAPPS_DEPLOYEES_V2: &str = "listeUserappsDeployeesV2";
pub const REQUEST_DOMAIN_LIST: &str = "listeDomaines";
pub const REQUETE_GET_CLEID_BACKUP_DOMAINE: &str = "getCleidBackupDomaine";
pub const REQUETE_CONFIGURATION_FILEHOSTS: &str = "getFilehostConfiguration";
pub const REQUETE_GET_FILEHOSTS: &str = "getFilehosts";
pub const REQUETE_GET_FILECONTROLERS: &str = "getFilecontrolers";
pub const REQUETE_GET_DOMAINS_BACKUP_VERSIONS: &str = "getDomainBackupVersions";
pub const REQUEST_SERVER_INSTANCES_V2: &str = "requestServerInstancesV2";
pub const REQUEST_SERVER_INSTANCE_CONFIGURATION: &str = "requestServerInstanceConfiguration";
pub const REQUEST_FILEHOSTS_FOR_FUUIDS: &str = "requestFilehostsForFuuids";

// Commands
pub const COMMANDE_SET_CLEID_BACKUP_DOMAINE: &str = "setCleidBackupDomaine";
pub const COMMANDE_FILE_VISIT: &str = "fileVisit";
pub const COMMANDE_CLAIM_AND_FILEHOST_VISITS_FOR_FUUIDS: &str = "claimAndFilehostVisits";
pub const COMMANDE_FILEHOST_BATCH_TRANSFERS: &str = "batchTransfers";
pub const COMMANDE_FILEHOST_RESET_VISITS_CLAIMS: &str = "resetVisitsClaims";
pub const COMMAND_DOMAIN_CLAIM_FILES: &str = "claimFiles";
pub const COMMANDE_FILEHOST_RESET_TRANSFERS: &str = "resetTransfers";
pub const COMMANDE_BACKUP_SET_DOMAIN_VERSION: &str = "setBackupDomainVersion";

// Transactions

pub const TRANSACTION_INSTANCE: &str = "instance";
pub const TRANSACTION_MONITOR: &str = TRANSACTION_INSTANCE;
pub const TRANSACTION_SUPPRIMER_INSTANCE: &str = "supprimerInstance";
pub const TRANSACTION_SET_FICHIERS_PRIMAIRE: &str = "setFichiersPrimaire";
pub const TRANSACTION_CONFIGURER_CONSIGNATION: &str = "configurerConsignation";
pub const TRANSACTION_SET_FILEHOST_FOR_INSTANCE: &str = "setFilehostForInstance";
pub const TRANSACTION_SUPPRIMER_CONSIGNATION_INSTANCE: &str = "supprimerConsignation";
pub const TRANSACTION_FILEHOST_ADD: &str = "filehostAdd";
pub const TRANSACTION_FILEHOST_ADD_V2: &str = "filehostAddV2";
pub const TRANSACTION_FILEHOST_UPDATE: &str = "filehostUpdate";
pub const TRANSACTION_FILEHOST_DELETE: &str = "filehostDelete";
// pub const TRANSACTION_FILEHOST_RESTORE: &str = "filehostRestore";
pub const TRANSACTION_FILEHOST_DEFAULT: &str = "setDefaultFilehost";
pub const TRANSACTION_DELETE_DOMAIN: &str = "deleteDomain";

// Events

pub const EVENEMENT_PRESENCE_INSTANCE_V2: &str = "presenceInstanceV2";
pub const EVENEMENT_FILEHOST_USAGE: &str = "filehostUsage";
pub const EVENEMENT_FILEHOST_NEWFUUID: &str = "filehostNewFuuid";
pub const EVENEMENT_PRESENCE_INSTANCE_APPLICATIONS_V2: &str = "presenceInstanceApplicationsV2";
pub const EVENEMENT_RESET_VISITS_CLAIMS: &str = "resetVisitsClaims";
pub const EVENEMENT_FILEHOST_TRANSFERSUPDATED: &str = "transfersUpdated";
pub const EVENEMENT_FILEHOSTING_UPDATE: &str = "filehostingUpdate";

pub fn init_queues(mq: &MessagingServiceImpl) -> Result<(), CommonError> {
    // Configure the queues and add to messaging service (will spawn consumer threads)

    // System service level queues: ticker (maintenance) and backup
    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAIN_NAME, QUEUE_TICKER),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: "evenement.ceduleur.ping".to_string(), exchange: Securite::L1Public }
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: true,
        })?;

    mq.add_named_queue(ConfigQueue {
        nom_queue: format!("{}/{}", DOMAIN_NAME, QUEUE_BACKUP),
        routing_keys: vec![
            ConfigRoutingExchange { routing_key: format!("requete.{}.getNombreTransactions", DOMAIN_NAME), exchange: Securite::L2Prive },
            ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_DECLENCHER_BACKUP), exchange: Securite::L3Protege },
        ],
        ttl: Some(QUEUE_TTL_DEFAULT),
        durable: true,
        autodelete: true,
    })?;

    // Domain specific queues
    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAIN_NAME, QUEUE_REQUESTS),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUEST_DOMAIN_LIST), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUEST_SERVER_INSTANCES_V2), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUEST_SERVER_INSTANCE_CONFIGURATION), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_GET_CLEID_BACKUP_DOMAINE), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_CONFIGURATION_FILEHOSTS), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUEST_FILEHOSTS_FOR_FUUIDS), exchange: Securite::L3Protege },

                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUEST_DOMAIN_LIST), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_USERAPPS_DEPLOYEES_V2), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_FICHE_MILLEGRILLE), exchange: Securite::L2Prive },

                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_FICHE_MILLEGRILLE), exchange: Securite::L1Public },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_GET_FILEHOSTS), exchange: Securite::L1Public },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_GET_FILECONTROLERS), exchange: Securite::L1Public },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_GET_FILEHOST_FOR_INSTANCE), exchange: Securite::L1Public },
                ConfigRoutingExchange { routing_key: format!("requete.{}.{}", DOMAIN_NAME, REQUETE_GET_DOMAINS_BACKUP_VERSIONS), exchange: Securite::L1Public },
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAIN_NAME, QUEUE_VOLATILES),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_SET_CLEID_BACKUP_DOMAINE), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_CLAIM_AND_FILEHOST_VISITS_FOR_FUUIDS), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_FILEHOST_RESET_VISITS_CLAIMS), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_FILEHOST_RESET_TRANSFERS), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_BACKUP_SET_DOMAIN_VERSION), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMAND_DOMAIN_CLAIM_FILES), exchange: Securite::L3Protege },
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAIN_NAME, QUEUE_PRESENCE),
            routing_keys: vec![
                // Domain status
                ConfigRoutingExchange { routing_key: format!("evenement.*.{}", EVENEMENT_PRESENCE_DOMAINE), exchange: Securite::L3Protege },

                // Instance status
                ConfigRoutingExchange { routing_key: format!("evenement.*.{}", EVENEMENT_PRESENCE_INSTANCE_V2), exchange: Securite::L4Secure },
                ConfigRoutingExchange { routing_key: format!("evenement.*.{}", EVENEMENT_PRESENCE_INSTANCE_V2), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("evenement.*.{}", EVENEMENT_PRESENCE_INSTANCE_V2), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("evenement.*.{}", EVENEMENT_PRESENCE_INSTANCE_V2), exchange: Securite::L1Public },

                // Installed applications
                ConfigRoutingExchange { routing_key: format!("evenement.instance.{}", EVENEMENT_PRESENCE_INSTANCE_APPLICATIONS_V2), exchange: Securite::L4Secure },
                ConfigRoutingExchange { routing_key: format!("evenement.instance.{}", EVENEMENT_PRESENCE_INSTANCE_APPLICATIONS_V2), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("evenement.instance.{}", EVENEMENT_PRESENCE_INSTANCE_APPLICATIONS_V2), exchange: Securite::L2Prive },
                ConfigRoutingExchange { routing_key: format!("evenement.instance.{}", EVENEMENT_PRESENCE_INSTANCE_APPLICATIONS_V2), exchange: Securite::L1Public },
            ],
            ttl: Some(QUEUE_TTL_PRESENCE),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAIN_NAME, QUEUE_FILEHOSTS_BATCH),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_FILE_VISIT), exchange: Securite::L1Public },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, COMMANDE_FILEHOST_BATCH_TRANSFERS), exchange: Securite::L1Public },
            ],
            ttl: Some(QUEUE_TTL_FILEHOSTS),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAIN_NAME, QUEUE_FILECONTROLER_EVENTS),
            routing_keys: vec![
                ConfigRoutingExchange { routing_key: format!("evenement.filecontroler.{}", EVENEMENT_FILEHOST_USAGE), exchange: Securite::L1Public },
                ConfigRoutingExchange { routing_key: format!("evenement.filecontroler.{}", EVENEMENT_FILEHOST_NEWFUUID), exchange: Securite::L1Public },
            ],
            ttl: Some(QUEUE_TTL_FILEHOSTS),
            durable: true,
            autodelete: false,
        })?;

    mq.add_named_queue(
        ConfigQueue {
            nom_queue: format!("{}/{}", DOMAIN_NAME, QUEUE_TRANSACTIONS),
            routing_keys: vec![
                // 3.protege
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_SET_FILEHOST_FOR_INSTANCE), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_FILEHOST_DEFAULT), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_DELETE_DOMAIN), exchange: Securite::L3Protege },

                // 1.public
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_FILEHOST_ADD_V2), exchange: Securite::L1Public },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_FILEHOST_UPDATE), exchange: Securite::L1Public },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_FILEHOST_DELETE), exchange: Securite::L1Public },

                // Obsolete
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_FILEHOST_ADD), exchange: Securite::L1Public },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_CONFIGURER_CONSIGNATION), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_SET_FICHIERS_PRIMAIRE), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_MONITOR), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_SUPPRIMER_INSTANCE), exchange: Securite::L3Protege },
                ConfigRoutingExchange { routing_key: format!("commande.{}.{}", DOMAIN_NAME, TRANSACTION_SUPPRIMER_CONSIGNATION_INSTANCE), exchange: Securite::L3Protege },
            ],
            ttl: Some(QUEUE_TTL_DEFAULT),
            durable: true,
            autodelete: false,
        })?;

    Ok(())
}
