use crate::external::mongo::*;
use crate::external::mq::*;
use crate::flow::transactions::TopologyTransactionService;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::common_messages::DemandeSignature;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::millegrilles_cryptographie::x509::EnveloppeCertificat;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoTyped};
use millegrilles_common_rust::mongodb::options::Hint;
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::tracing::{info, warn};
use millegrilles_common_rust::v3::{ConfigService, PkiService};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::serde::{Serialize, Deserialize};
use crate::constants::DOMAIN_NAME;
use crate::models::*;

pub async fn process_command<M>(
    mongo: &M,
    config: &dyn ConfigService,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in command")).await
    };
    match action {
        COMMANDE_SET_CLEID_BACKUP_DOMAINE => set_domain_backup_keyid(mongo, outbound, wrapper).await,
        COMMANDE_CLAIM_AND_FILEHOST_VISITS_FOR_FUUIDS => todo!(),
        COMMANDE_FILEHOST_RESET_VISITS_CLAIMS => todo!(),
        COMMANDE_FILEHOST_RESET_TRANSFERS => todo!(),
        COMMANDE_BACKUP_SET_DOMAIN_VERSION => todo!(),
        COMMAND_DOMAIN_CLAIM_FILES => todo!(),
        _ => {
            info!("Unknown action {} for process_command, skipping", action);
            Ok(())
        }
    }
}

#[derive(Deserialize)]
pub struct CommandSetDomainBackupKeyid {
    pub domaine: String,
    pub cle_id: Option<String>,
    pub reset: Option<bool>,
}

async fn set_domain_backup_keyid<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let commande: CommandSetDomainBackupKeyid = wrapper.message.deserialize()?;

    let now = Utc::now();
    let certificate = wrapper.certificate.as_ref();
    let certificat_subject = certificate.subject()?;
    let instance_id = match certificat_subject.get("commonName") {
        Some(inner) => inner.as_str(),
        None => Err("Certificat sans commonName")?
    };

    let domaine = commande.domaine;

    if !certificate.verifier_exchanges(vec![Securite::L3Protege])? ||
        !certificate.verifier_domaines(vec![domaine.clone()])?
    {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    let filtre = doc!{"domaine": &domaine};
    let collection = mongo.get_collection_typed::<DomainRow>(COLLECTION_DOMAINS)?;
    let cle_id_backup = match commande.reset {
        Some(true) => None,
        _ => match commande.cle_id {
            Some(inner) => Some(inner),
            None => {
                // Err("cle_id manquant de la commande")?
                return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(400, "Value cle_id is missing from the command")).await
            }
        }
    };
    let ops = doc! {
        "$setOnInsert": {"instance_id": instance_id, CHAMP_CREATION: now, "dirty": true, "reclame_fuuids": false},
        "$set": { "cle_id_backup": cle_id_backup },
        "$currentDate": { CHAMP_MODIFICATION: true }
    };
    collection.update_one(filtre, ops).upsert(true).await?;

    outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
}

/// Process the command part of the transaction (checks, validations, volatile updates),
/// calls transaction processor and then handles responses and emits events.
pub async fn process_transaction<M>(
    mongo: &M,
    pki: &dyn PkiService,
    outbound: &MessageOutboundFacade,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in transaction")).await
    };
    match action {
        // TODO TRANSACTION_ACTION_SAVE_CERTIFICATE | TRANSACTION_ACTION_NEW_CERTIFICATE => save_certificate(mongo, pki, outbound, transaction, wrapper).await,
        _ => {
            info!("Unknown action {} for process_transaction, skipping", action);
            Ok(())
        }
    }
}

async fn save_certificate<M>(
    mongo: &M,
    pki: &dyn PkiService,
    outbound: &MessageOutboundFacade,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!()
    // let transaction_value: CommandSaveCertificate = wrapper.message.deserialize()?;
    //
    // let ca = match transaction_value.ca.as_ref() {
    //     Some(ca) => Some(ca.as_str()),
    //     None => None
    // };
    //
    // // Validate the certificate (current date)
    // let pem_chain_str = transaction_value.chaine_pem.join("\n");
    // let certificate = match pki.validate_pem(pem_chain_str.as_str(), ca.clone(), None) {
    //     Ok(certificate) => certificate,
    //     Err(_e) => {
    //         // Assume the certificate is not currently valid. Get the not-before-date to confirm.
    //         let enveloppe = match EnveloppeCertificat::try_from(pem_chain_str.as_str()) {
    //             Ok(enveloppe) => enveloppe,
    //             Err(e) => {
    //                 info!("Invalid certificate: {:?}", e);
    //                 return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(400, "Invalid certificate")).await
    //             }
    //         };
    //         let not_valid_before = enveloppe.not_valid_before()?;
    //         match pki.validate_pem(pem_chain_str.as_str(), ca, Some(&not_valid_before)) {
    //             Ok(certificate) => certificate,
    //             Err(e) => {
    //                 info!("Invalid certificate: {:?}", e);
    //                 return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(400, "Invalid certificate")).await
    //             }
    //         }
    //     }
    // };
    //
    // // Check if certificate already exists
    // let fingerprint = match certificate.fingerprint() {
    //     Ok(fingerprint) => fingerprint,
    //     Err(e) => {
    //         info!("Error getting fingerprint of certificate: {:?}", e);
    //         return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(500, "Error getting fingerprint")).await
    //     }
    // };
    //
    // // Do an existing query, ideally this will only hit the index
    // let filter = doc!{ PKI_DOCUMENT_CHAMP_FINGERPRINT: &fingerprint };
    // let collection = mongo.get_collection(COLLECTION_NAME_CERTIFICATES)?;
    // if let Some(_row) = collection
    //     .find_one(filter)
    //     .projection(doc!{PKI_DOCUMENT_CHAMP_FINGERPRINT: true})
    //     .hint(Hint::Name(PKI_DOCUMENT_CHAMP_FINGERPRINT.to_string()))
    //     .await?
    // {
    //     // The certificate has already been received and processed successfully - respond with OK
    //     return outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
    // }
    //
    // // Run transaction updates
    // let delivery_info = wrapper.delivery_info.clone();
    // //if let Err(e) = transaction.process_transaction(wrapper.into(), None).await {
    // let transaction_value = TransactionCertificat { pem: pem_chain_str, ca: transaction_value.ca };
    // if let Err(e) = transaction.process_value(
    //     DOMAIN_NAME,
    //     TRANSACTION_ACTION_NEW_CERTIFICATE,
    //     serde_json::to_value(transaction_value)?,
    //     None
    // ).await {
    //     info!("Error saving certificate: {:?}", e);
    //     return outbound.respond(delivery_info, ErrorMessage::err_code(500, "Error saving certificate")).await
    // }
    //
    // // Success
    // outbound.respond(delivery_info, ErrorMessage::ok()).await
}
