use crate::external::mongo::*;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::v3::impls::transaction_service::TransactionServiceImpl;
use millegrilles_common_rust::v3::models::{TransactionOperationAggregator, TransactionWrapper};
use millegrilles_common_rust::v3::{ConfigService, FormatService, TransactionRouter, TransactionService};
use std::sync::Arc;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::CHAMP_MODIFICATION;
use millegrilles_common_rust::mongodb::options::{DeleteOneModel, UpdateOneModel, WriteModel};
use millegrilles_common_rust::tracing::warn;
use crate::external::mq::*;
use crate::models::*;

pub struct TopologyTransactionService {
    pub transaction: Arc<dyn TransactionService>,
}

impl TopologyTransactionService {
    pub fn new(
        config: Arc<dyn ConfigService>,
        format: Arc<dyn FormatService>,
        mongo: Arc<MongoDaoImpl>,
        restoring: bool,
    ) -> Self {
        let router = TopologyTransactionRouter { mongo: mongo.clone(), ignore_duplicates: restoring };
        let service = TransactionServiceImpl::new(
            config,
            format,
            mongo,
            COLLECTION_NAME_REDOLOG.to_string(),
            COLLECTION_NAME_TRACKING.to_string(),
            Box::new(router),
        );

        Self { transaction: Arc::new(service) }
    }

    pub async fn process_transaction(&self, wrapper: TransactionWrapper, session: Option<&mut ClientSession>) -> Result<(), CommonError> {
        self.transaction.process_transaction(wrapper, session).await
    }

    pub async fn process_value(&self, domain: &str, action: &str, value: Value, session: Option<&mut ClientSession>) -> Result<(), CommonError> {
        self.transaction.process_value(domain, action, value, session).await
    }
}

struct TopologyTransactionRouter {
    mongo: Arc<MongoDaoImpl>,
    ignore_duplicates: bool,
}

#[async_trait]
impl TransactionRouter for TopologyTransactionRouter {
    async fn route(
        &self,
        action: String,
        wrapper: TransactionWrapper
    ) -> Result<TransactionOperationAggregator, CommonError> {
        match action.as_str() {
            TRANSACTION_SET_FILEHOST_FOR_INSTANCE => set_filehost_for_instance(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_FILEHOST_DEFAULT => set_filehost_default(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_DELETE_DOMAIN => delete_domain(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_FILEHOST_ADD_V2 => add_filehost_v2(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_FILEHOST_UPDATE => update_filehost(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_FILEHOST_DELETE => delete_filehost(self.mongo.as_ref(), wrapper).await,

            // Obsolete
            TRANSACTION_FILEHOST_ADD => obsolete(TRANSACTION_FILEHOST_ADD),
            TRANSACTION_CONFIGURER_CONSIGNATION => obsolete(TRANSACTION_CONFIGURER_CONSIGNATION),
            TRANSACTION_SET_FICHIERS_PRIMAIRE => obsolete(TRANSACTION_SET_FICHIERS_PRIMAIRE),
            TRANSACTION_MONITOR => obsolete(TRANSACTION_MONITOR),
            TRANSACTION_SUPPRIMER_INSTANCE => obsolete(TRANSACTION_SUPPRIMER_INSTANCE),
            TRANSACTION_SUPPRIMER_CONSIGNATION_INSTANCE => obsolete(TRANSACTION_SUPPRIMER_CONSIGNATION_INSTANCE),

            _ => Err(CommonError::Str("Unknown transaction action"))
        }
    }
}

async fn set_filehost_for_instance(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> {
    let transaction_value: TransactionSetFilehostInstance = wrapper.message.deserialize()?;

    let filter = doc! { CHAMP_INSTANCE_ID: &transaction_value.instance_id, "name": "filehost_id" };
    let set_ops = doc! {"value": transaction_value.filehost_id.as_ref()};
    let ops = doc! {
        "$set": set_ops,
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    let collection = mongo.get_collection(NOM_COLLECTION_INSTANCE_CONFIGURATION)?;

    let update_model_versions = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection.namespace())
            .filter(filter)
            .update(ops)
            .build()
    );
    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_versions]);

    Ok(aggregator)
}

fn obsolete(name: &str) -> Result<TransactionOperationAggregator,CommonError> {
    warn!("Obsolete transaction received: {}", name);
    Ok(TransactionOperationAggregator::new())
}

async fn set_filehost_default<M>(
    mongo: &M,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> where M: MongoDaoTyped {
    let transaction_value: TransactionFilehostSetDefault = wrapper.message.deserialize()?;

    let collection_config =
        mongo.get_collection_typed::<FilehostingCongurationRow>(NOM_COLLECTION_FILEHOSTINGCONFIGURATION)?;
    let filter = doc!{"name": FIELD_CONFIGURATION_FILEHOST_DEFAULT};
    let ops = doc! {
        "$set": {"value": transaction_value.filehost_id},
    };

    let update_model_versions = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection_config.namespace())
            .filter(filter)
            .update(ops)
            .build()
    );
    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_versions]);

    Ok(aggregator)
}

async fn delete_domain<M>(
    mongo: &M,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> where M: MongoDaoTyped {
    let transaction_value: TransactionDeleteDomain = wrapper.message.deserialize()?;

    let collection_domains =
        mongo.get_collection_typed::<DomainRow>(COLLECTION_DOMAINS)?;
    let filter = doc!{CHAMP_DOMAINE: &transaction_value.domain_name};

    let delete_model_versions = WriteModel::DeleteOne(
        DeleteOneModel::builder()
            .namespace(collection_domains.namespace())
            .filter(filter)
            .build()
    );
    let mut aggregator = TransactionOperationAggregator::new();
    // Ordered delete, domains get auto-added (business key is not a unique id)
    aggregator.ordered = Some(vec![delete_model_versions]);

    Ok(aggregator)
}

async fn add_filehost_v2<M>(
    mongo: &M,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> where M: MongoDaoTyped {
    let transaction_value: FilehostAddTransactionV2 = wrapper.message.deserialize()?;
    let transaction_id = &wrapper.message.id.as_str();

    let collection = mongo.get_collection(NOM_COLLECTION_FILEHOSTS)?;
    let now = Utc::now();

    let set_ops = doc! {
        "instance_id": transaction_value.instance_id,
        "url_external": transaction_value.url_external,
        "tls_external": transaction_value.tls_external,
    };
    let set_on_insert = doc! {
        "deleted": false,
        "sync_active": true,
        "created": now.clone(),
        "fuuid": None::<&str>,
    };

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": set_on_insert,
        "$currentDate": {"modified": true},
    };

    let filter = doc! {"filehost_id": &transaction_id};

    let update_model_versions = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .upsert(true)
            .namespace(collection.namespace())
            .filter(filter)
            .update(ops)
            .build()
    );
    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_versions]);

    Ok(aggregator)
}

async fn update_filehost<M>(
    mongo: &M,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> where M: MongoDaoTyped {
    todo!()
}

async fn delete_filehost<M>(
    mongo: &M,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> where M: MongoDaoTyped {
    todo!()
}
