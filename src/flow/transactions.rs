use crate::external::mongo::*;
use millegrilles_common_rust::async_trait::async_trait;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::v3::impls::transaction_service::TransactionServiceImpl;
use millegrilles_common_rust::v3::models::{TransactionOperationAggregator, TransactionWrapper};
use millegrilles_common_rust::v3::{ConfigService, FormatService, TransactionRouter, TransactionService};
use std::sync::Arc;
use millegrilles_common_rust::tracing::warn;
use crate::external::mq::{TRANSACTION_CONFIGURER_CONSIGNATION, TRANSACTION_DELETE_DOMAIN, TRANSACTION_FILEHOST_ADD, TRANSACTION_FILEHOST_ADD_V2, TRANSACTION_FILEHOST_DEFAULT, TRANSACTION_FILEHOST_DELETE, TRANSACTION_FILEHOST_UPDATE, TRANSACTION_MONITOR, TRANSACTION_SET_FICHIERS_PRIMAIRE, TRANSACTION_SET_FILEHOST_FOR_INSTANCE, TRANSACTION_SUPPRIMER_CONSIGNATION_INSTANCE, TRANSACTION_SUPPRIMER_INSTANCE};

pub struct TopologyTransactionService {
    pub transaction: Arc<dyn TransactionService>,
}

impl TopologyTransactionService {
    pub fn new(
        config: Arc<dyn ConfigService>,
        format: Arc<dyn FormatService>,
        mongo: Arc<dyn MongoDao>,
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
    mongo: Arc<dyn MongoDao>,
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
            TRANSACTION_SET_FILEHOST_FOR_INSTANCE => todo!(),
            TRANSACTION_FILEHOST_DEFAULT => todo!(),
            TRANSACTION_DELETE_DOMAIN => todo!(),
            TRANSACTION_FILEHOST_ADD_V2 => todo!(),
            TRANSACTION_FILEHOST_UPDATE => todo!(),
            TRANSACTION_FILEHOST_DELETE => todo!(),

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

async fn save_certificate(
    mongo: &dyn MongoDao,
    wrapper: TransactionWrapper,
    ignore_duplicates: bool,
) -> Result<TransactionOperationAggregator, CommonError> {
    todo!()
    // let certificate: TransactionCertificat = wrapper.message.deserialize()?;
    // 
    // let mut enveloppe = EnveloppeCertificat::try_from(certificate.pem.as_str())?;
    // if let Some(ca) = certificate.ca {
    //     enveloppe.millegrille = Some(X509::from_pem(ca.as_bytes())?);
    // }
    // let row: CertificateRow = enveloppe.try_into()?;
    // 
    // let mut aggregator = TransactionOperationAggregator::new();
    // if ignore_duplicates {
    //     // Support for legacy systems with duplicates on restoration
    //     let collection = mongo.get_collection(COLLECTION_NAME_CERTIFICATES)?;
    //     let filtre_versions = doc! { PKI_DOCUMENT_CHAMP_FINGERPRINT: &row.fingerprint };
    //     let ops = doc!{"$set": bson::serialize_to_bson(&row)?};
    //     let update_model_versions = WriteModel::UpdateOne(
    //         UpdateOneModel::builder()
    //             .upsert(true)
    //             .namespace(collection.namespace())
    //             .filter(filtre_versions)
    //             .update(ops)
    //             .build()
    //     );
    //     aggregator.unordered = Some(vec![update_model_versions]);   // This really is just an insert
    // } else {
    //     // Default behavior, insert and raise Error on record duplication
    //     let doc_row = bson::serialize_to_document(&row)?;
    //     aggregator.batch_insertion(BatchInsertions::new(COLLECTION_NAME_CERTIFICATES, vec![doc_row]))?;
    // }
    // 
    // Ok(aggregator)
}

fn obsolete(name: &str) -> Result<TransactionOperationAggregator,CommonError> {
    warn!("Obsolete transaction received: {}", name);
    Ok(TransactionOperationAggregator::new())
}
