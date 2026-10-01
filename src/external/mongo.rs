use millegrilles_common_rust::configuration::ConfigMessages;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDao};

pub const COLLECTION_NAME_REDOLOG: &str = "CoreTopology/redolog";
pub const COLLECTION_NAME_TRACKING: &str = "CoreTopology/tracking";
pub const INDEX_REDO_LOG_ID: &str = "redo_log_id";

pub const COLLECTION_DOMAINS: &str = "CoreTopologie/domains";
pub const COLLECTION_CONFIGURED_APPLICATIONS_V2: &str = "CoreTopologie/instances/configuredApplicationsV2";
pub const NOM_COLLECTION_FILEHOSTINGCONFIGURATION: &str = "CoreTopologie/filehostingConfiguration";


// pub const NOM_COLLECTION_MILLEGRILLES: &str = "CoreTopologie/millegrilles";
// pub const NOM_COLLECTION_MILLEGRILLES_ADRESSES: &str = "CoreTopologie/millegrillesAdresses";
// pub const NOM_COLLECTION_TOKENS: &str = "CoreTopologie/tokens";
pub const NOM_COLLECTION_FILEHOSTS: &str = "CoreTopologie/filehosts";
pub const NOM_COLLECTION_FILECONTROLERS: &str = "CoreTopologie/filecontrolers";
pub const NOM_COLLECTION_FILEHOSTING_FUUIDS: &str = "CoreTopologie/filehostingFuuids";
pub const NOM_COLLECTION_FILEHOSTING_TRANSFERS: &str = "CoreTopologie/filehostingTransfers";
pub const NOM_COLLECTION_FILEHOSTING_CLAIMS: &str = "CoreTopologie/filehostingClaims";
pub const NOM_COLLECTION_FILEHOSTING_VISITS: &str = "CoreTopologie/filehostingVisits";
pub const NOM_COLLECTION_FILEHOSTING_SYNC_STATUS: &str = "CoreTopologie/filehostingSyncStatus";
pub const NOM_COLLECTION_FILEHOSTING_FUUIDS_WORK: &str = "CoreTopologie/filehostingFuuidsWork";
pub const NOM_COLLECTION_INSTANCE_STATUS_V2: &str = "CoreTopologie/instances/statusV2";
pub const NOM_COLLECTION_INSTANCE_CONFIGURATION: &str = "CoreTopologie/instances/configuration";

pub const INDEX_DOMAINE: &str = "domaine";
pub const INDEX_NOEUDS: &str = "noeuds";
pub const INDEX_IDMG: &str = "idmg";
pub const INDEX_ADRESSES: &str = "adresses";
pub const INDEX_ADRESSE: &str = "adresse";
pub const INDEX_INSTANCE_ID: &str = "instance_id";

pub const CHAMP_DOMAINE: &str = "domaine";
pub const CHAMP_INSTANCE_ID: &str = "instance_id";
pub const CHAMP_NOEUD_ID: &str = CHAMP_INSTANCE_ID;
pub const CHAMP_ADRESSE: &str = "adresse";
pub const CHAMP_ADRESSES: &str = "adresses";
pub const CHAMP_CONSIGNATION_ID: &str = "consignation_id";

pub const FIELD_CONFIGURATION_FILEHOST_DEFAULT: &str = "filehost.default";
pub const FIELD_CONFIGURATION_FILECONTROLER_PRIMARY: &str = "filecontroler.primary";
pub const FIELD_LAST_CLAIM_DATE: &str = "last_claim_date";
pub const FIELD_JOB_PICKED_UP: &str = "job_picked_up";

pub async fn create_index_mongodb(db: &dyn MongoDao, config: &dyn ConfigMessages) -> Result<(), CommonError> {
    db.create_index(
        COLLECTION_NAME_REDOLOG,
        vec!(
            ChampIndex { nom_champ: String::from(TRANSACTION_CHAMP_ID), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_REDO_LOG_ID)),
            unique: true,
        }),
    ).await?;

    db.create_index(
        COLLECTION_NAME_REDOLOG,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_PROCESSED), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_DATE_PROCESSED)),
            unique: false,
        }),
    ).await?;

    db.create_index(
        COLLECTION_NAME_TRACKING,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_BID), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_BID)),
            unique: true,
        }),
    ).await?;

    db.create_index(
        COLLECTION_NAME_TRACKING,
        vec!(
            ChampIndex { nom_champ: String::from(FIELD_DATE_PROCESSED), direction: 1 },
        ),
        Some(IndexOptions {
            nom_index: Some(String::from(INDEX_DATE_PROCESSED)),
            unique: false,
        })
    ).await?;

    // TDOD Collection indices
    
    Ok(())
}
