use crate::external::mongo::*;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoImpl, MongoDaoTyped};
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::v3::impls::transaction_service::TransactionServiceImpl;
use millegrilles_common_rust::v3::models::{BatchInsertions, TransactionOperationAggregator, TransactionWrapper};
use millegrilles_common_rust::v3::{ConfigService, FormatService, TransactionRouter, TransactionService};
use std::sync::Arc;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::CHAMP_MODIFICATION;
use millegrilles_common_rust::mongodb::options::{DeleteManyModel, DeleteOneModel, UpdateOneModel, WriteModel};
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
        _restoring: bool,
    ) -> Self {
        let router = TopologyTransactionRouter { mongo: mongo.clone() };
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

    pub async fn process_value(&self, domain: &str, action: &str, value: Value, session: Option<&mut ClientSession>) -> Result<String, CommonError> {
        self.transaction.process_value(domain, action, value, session).await
    }
}

struct TopologyTransactionRouter {
    mongo: Arc<MongoDaoImpl>,
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
            TRANSACTION_FILEHOST_RESTORE => restore_filehost(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_CONFIGURATION_CREATE_FILE => configuration_create_file(wrapper).await,
            TRANSACTION_CONFIGURATION_UPDATE_FILE => configuration_update_file(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_CONFIGURATION_DELETE_FILE => configuration_delete_file(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_CONFIGURATION_SET_PROPERTY => configuration_set_property(self.mongo.as_ref(), wrapper).await,
            TRANSACTION_CONFIGURATION_DELETE_PROPERTY => configuration_delete_property(self.mongo.as_ref(), wrapper).await,

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
    let collection = mongo.get_collection(COLLECTION_INSTANCE_CONFIGURATION)?;

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
        mongo.get_collection_typed::<FilehostingCongurationRow>(COLLECTION_FILEHOSTINGCONFIGURATION)?;
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

    let collection = mongo.get_collection(COLLECTION_FILEHOSTS)?;
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
    let doc_transaction: FilehostUpdateTransaction = wrapper.message.deserialize()?;

    let collection = mongo.get_collection(COLLECTION_FILEHOSTS)?;
    let filter = doc! {"filehost_id": doc_transaction.filehost_id};
    let mut set_ops = doc!{};
    if let Some(inner) = doc_transaction.instance_id {
        set_ops.insert("instance_id", inner);
    }
    if let Some(inner) = doc_transaction.url_internal {
        set_ops.insert("url_internal", inner);
    }
    if let Some(inner) = doc_transaction.url_external {
        set_ops.insert("url_external", inner);
    }
    if let Some(inner) = doc_transaction.tls_external {
        set_ops.insert("tls_external", inner);
    }
    if let Some(inner) = doc_transaction.sync_active {
        set_ops.insert("sync_active", inner);
    }
    let ops = doc!{
        "$set": set_ops,
        "$currentDate": {"modified": true}
    };

    let update_model_versions = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .namespace(collection.namespace())
            .filter(filter)
            .update(ops)
            .build()
    );
    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_versions]);

    Ok(aggregator)
}

async fn delete_filehost<M>(
    mongo: &M,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> where M: MongoDaoTyped {
    let transaction_value: FilehostDeleteTransaction = wrapper.message.deserialize()?;

    let collection = mongo.get_collection(COLLECTION_FILEHOSTS)?;
    let filter = doc!{"filehost_id": &transaction_value.filehost_id };
    let ops = doc !{
        "$set": {"deleted": true},
        "$currentDate": {"modified": true},
    };
    let update_model_filehost = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .namespace(collection.namespace())
            .filter(filter)
            .update(ops)
            .build()
    );

    let mut ordered = vec![update_model_filehost];

    if transaction_value.reset_default == Some(true) {
        // Additional operation to remove the default filehost configuration
        let collection_configuration = mongo.get_collection_typed::<FilehostingCongurationRow>(COLLECTION_FILEHOSTINGCONFIGURATION)?;
        let filtre_configuration = doc!{"name": FIELD_CONFIGURATION_FILEHOST_DEFAULT, "value": &transaction_value.filehost_id};
        let delete_model_versions = WriteModel::DeleteOne(
            DeleteOneModel::builder()
                .namespace(collection_configuration.namespace())
                .filter(filtre_configuration)
                .build()
        );
        ordered.push(delete_model_versions);
    }

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(ordered);

    Ok(aggregator)
}

async fn restore_filehost<M>(
    mongo: &M,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> where M: MongoDaoTyped {
    let transaction_value: FilehostRestoreTransaction = wrapper.message.deserialize()?;
    let collection = mongo.get_collection(COLLECTION_FILEHOSTS)?;
    let filter = doc!{ "filehost_id": &transaction_value.filehost_id };
    let ops = doc !{
        "$set": {"deleted": false},
        "$currentDate": {"modified": true},
    };
    let update_model_filehost = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .namespace(collection.namespace())
            .filter(filter)
            .update(ops)
            .build()
    );

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_filehost]);

    Ok(aggregator)
}

async fn configuration_create_file(
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError>
{
    let transaction_value: TransactionCreateConfigurationFile = wrapper.message.deserialize()?;

    let row = ConfigurationFileRow {
        // The file_id is the transaction id
        file_id: wrapper.message.id,
        // Copy remaining values
        filename: transaction_value.filename,
        roles: transaction_value.roles,
        domains: transaction_value.domains,
        last_modified: wrapper.message.estampille,
        key_id: transaction_value.key_id,
        // This is a placeholder for re-encrypting the file key (volatile), always None in the transaction.
        encrypted_file_key: None,
    };

    let serialized_value = bson::serialize_to_document(&row)?;

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.batch_insertions = Some(vec![BatchInsertions::new(
        COLLECTION_CONFIGURATION_FILES,
        vec![serialized_value]
    )]);

    Ok(aggregator)
}

async fn configuration_update_file(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError>
{
    let transaction_value: TransactionUpdateConfigurationFile = wrapper.message.deserialize()?;
    let modification_date: bson::DateTime = wrapper.message.estampille.clone().into();

    let mut serialized_doc = bson::serialize_to_document(&transaction_value)?;
    serialized_doc.remove("file_id");  // Not re-setting the key
    serialized_doc.insert("last_modified", modification_date);
    let ops = doc!{"$set": serialized_doc};
    let filter = doc!{"file_id": &transaction_value.file_id};

    let collection = mongo.get_collection(COLLECTION_CONFIGURATION_FILES)?;

    let update_model_versions = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .namespace(collection.namespace())
            .filter(filter)
            .update(ops)
            .build()
    );
    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_versions]);

    Ok(aggregator)
}

async fn configuration_delete_file<M>(
    mongo: &M,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> where M: MongoDaoTyped
{
    let transaction_value: TransactionDeleteConfigurationFile = wrapper.message.deserialize()?;
    let filter = doc!{"file_id": &transaction_value.file_id};

    // Delete all properties associated to this file
    let collection_properties = mongo.get_collection(COLLECTION_CONFIGURATION_PROPERTIES)?;
    let delete_model_properties = WriteModel::DeleteMany(
        DeleteManyModel::builder()
            .namespace(collection_properties.namespace())
            .filter(filter.clone())
            .build()
    );

    let collection_files = mongo.get_collection(COLLECTION_CONFIGURATION_FILES)?;
    let delete_model_versions = WriteModel::DeleteOne(
        DeleteOneModel::builder()
            .namespace(collection_files.namespace())
            .filter(filter)
            .build()
    );

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.unordered = Some(vec![delete_model_properties, delete_model_versions]);

    Ok(aggregator)
}

async fn configuration_set_property<M>(
    mongo: &M,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> where M: MongoDaoTyped
{
    let transaction_value: TransactionSetFileProperty = wrapper.message.deserialize()?;
    let modification_date: bson::DateTime = wrapper.message.estampille.clone().into();

    let filter = doc!{"file_id": &transaction_value.file_id, "key": &transaction_value.key};
    let ops = doc!{
        "$set": {
            "value": bson::serialize_to_document(&transaction_value.value)?,
            "last_modified": &modification_date,
        },
    };

    let collection_properties = mongo.get_collection(COLLECTION_CONFIGURATION_PROPERTIES)?;

    let update_model_properties = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .namespace(collection_properties.namespace())
            .filter(filter)
            .update(ops)
            .upsert(true)
            .build()
    );

    // Update last_modified on file
    let collection_files = mongo.get_collection(COLLECTION_CONFIGURATION_FILES)?;
    let filter = doc!{"file_id": &transaction_value.file_id};
    let ops = doc!{
        "$set": {
            "last_modified": &modification_date,
        },
    };
    let update_model_file = WriteModel::UpdateOne(
        UpdateOneModel::builder()
            .namespace(collection_files.namespace())
            .filter(filter)
            .update(ops)
            .build()
    );

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.ordered = Some(vec![update_model_properties, update_model_file]);

    Ok(aggregator)
}

async fn configuration_delete_property<M>(
    mongo: &M,
    wrapper: TransactionWrapper,
) -> Result<TransactionOperationAggregator, CommonError> where M: MongoDaoTyped
{
    let transaction_value: TransactionDeleteFileProperty = wrapper.message.deserialize()?;
    let filter = doc!{"file_id": &transaction_value.file_id, "key": &transaction_value.key};

    let collection = mongo.get_collection(COLLECTION_CONFIGURATION_PROPERTIES)?;
    let delete_model = WriteModel::DeleteOne(
        DeleteOneModel::builder()
            .namespace(collection.namespace())
            .filter(filter)
            .build()
    );

    let mut aggregator = TransactionOperationAggregator::new();
    aggregator.unordered = Some(vec![delete_model]);

    Ok(aggregator)
}
