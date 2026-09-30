use crate::external::mongo::*;
use crate::external::mq::*;
use crate::flow::filecontroler::check_primary_filecontroler;
use crate::flow::transactions::TopologyTransactionService;
use crate::models::*;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::serde::ts_seconds;
use millegrilles_common_rust::chrono::{DateTime, Duration, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::mongodb::Cursor;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tracing::info;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::v3::{ConfigService, PkiService};

pub async fn process_command<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where
    M: MongoDaoTyped,
{
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in command")).await
    };
    match action {
        COMMANDE_SET_CLEID_BACKUP_DOMAINE => set_domain_backup_keyid(mongo, outbound, wrapper).await,
        COMMANDE_CLAIM_AND_FILEHOST_VISITS_FOR_FUUIDS => claim_filehost_visits_for_fuuids(mongo, outbound, wrapper).await,
        COMMANDE_FILEHOST_RESET_VISITS_CLAIMS => filehost_reset_visits_claims(mongo, outbound, wrapper).await,
        COMMANDE_FILEHOST_RESET_TRANSFERS => filehost_reset_transfers(mongo, outbound, wrapper).await,
        COMMANDE_BACKUP_SET_DOMAIN_VERSION => set_domain_backup_version(mongo, outbound, wrapper).await,
        COMMAND_DOMAIN_CLAIM_FILES => domain_claim_files(mongo, outbound, wrapper).await,
        COMMANDE_FILE_VISIT => file_visit(mongo, outbound, wrapper).await,
        COMMANDE_FILEHOST_BATCH_TRANSFERS => filehost_batch_transfers(mongo, outbound, wrapper).await,
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

async fn claim_filehost_visits_for_fuuids<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {

    todo!()
}

async fn filehost_reset_visits_claims<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    if ! wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    let collection_fuuids =
        mongo.get_collection_typed::<RowFilehostFuuid>(NOM_COLLECTION_FILEHOSTING_FUUIDS)?;
    let collection_transfers =
        mongo.get_collection_typed::<RowFilehostFuuid>(NOM_COLLECTION_FILEHOSTING_TRANSFERS)?;

    collection_fuuids.delete_many(doc!{}).await?;
    collection_transfers.delete_many(doc!{}).await?;

    // Emettre evenement reset claims (e.g. GrosFichiers), reload visites (filecontrolers).
    let routage_reset_claims = RoutageMessageAction::builder(
        TOPOLOGIE_NOM_DOMAINE, EVENEMENT_RESET_VISITS_CLAIMS, vec![Securite::L1Public]).build();
    outbound.emit_event(routage_reset_claims, ErrorMessage::ok()).await?;

    outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
}

async fn filehost_reset_transfers<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    if ! wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    // Retirer le champ job_picked_up pour permettre aux controleurs de reprendre les jobs immediatement
    let collection_transfers =
        mongo.get_collection_typed::<RowFilehostFuuid>(NOM_COLLECTION_FILEHOSTING_TRANSFERS)?;
    let filtre = doc!{"job_picked_up": {"$exists":true}};
    let ops = doc! {"$unset": {"job_picked_up": true}, "$currentDate": {"modified": true}};
    collection_transfers.update_many(filtre, ops).await?;

    // Reverifie chaque transfert, enleve ceux qui ne s'appliquent plus et cree les nouveaux
    todo!()
    // entretien_transfert_fichiers(middleware).await?;
    //
    // outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
}

#[derive(Deserialize)]
struct CommandSetDomainBackupVersion {
    domaine: String,
    version: String,
}

async fn set_domain_backup_version<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    if !wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    let command: CommandSetDomainBackupVersion = wrapper.message.deserialize()?;
    let collection = mongo.get_collection(COLLECTION_DOMAINS)?;
    let filtre = doc!{"domaine": &command.domaine};
    let ops = doc! {
        "$set": {"backup_version": &command.version},
        "$currentDate": {"modified": true},
    };
    let result = collection.update_one(filtre, ops).await?;

    if result.matched_count == 1 {
        // Emettre evenement de mise a jour de backup.
        // Va declencher une synchronisation des fichiers de backup.
        let routage = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, BACKUP_EVENEMENT_MAJ, vec![Securite::L1Public])
            .build();
        outbound.emit_event(routage, ErrorMessage::ok()).await?;

        outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
    } else {
        outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Domain not found")).await
    }
}

#[derive(Deserialize)]
struct RequestFuuidsVisits {
    fuuids: Vec<String>,
    done: Option<bool>,
}

async fn domain_claim_files<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let certificate = wrapper.certificate.as_ref();
    let domains = certificate.get_extensions()?.map(|e| e.domaines);

    let request: RequestFuuidsVisits = wrapper.message.deserialize()?;
    let now = Utc::now();

    let mut batch = Vec::with_capacity(request.fuuids.len());
    for fuuid in request.fuuids {
        batch.push(doc!{"fuuid": fuuid, "claim_date": &now, "domains": &domains});
    }
    if ! batch.is_empty() {
        let collection_claims = mongo.get_collection(NOM_COLLECTION_FILEHOSTING_CLAIMS)?;
        collection_claims.insert_many(batch).await?;
    }

    if request.done == Some(true) {
        // Put flag to indicate this domain has sent all its claims successfully
        let collection_files_status = mongo.get_collection(NOM_COLLECTION_FILEHOSTING_SYNC_STATUS)?;
        if let Some(domains) = &domains {
            if let Some(domains_list) = domains {
                for domain in domains_list {
                    let filtre = doc! {"claimer": domain, "claimer_type": "domain"};
                    let ops = doc! {
                        "$currentDate": {"date_ready": true},
                    };
                    collection_files_status.update_one(filtre, ops).upsert(true).await?;
                }
            }
        }
    }

    outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
}

#[derive(Deserialize)]
struct CommandFileVisit {
    filehost_id: String,
    #[serde(with="ts_seconds")]
    visit_time: DateTime<Utc>,
    fuuids: Vec<String>,
    done: Option<bool>,
}

async fn file_visit<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let instance_id = wrapper.certificate.get_common_name()?;

    if ! wrapper.certificate.verifier_roles_string(vec!["filecontroler".to_string()])? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    let commande: CommandFileVisit = wrapper.message.deserialize()?;

    let mut batch = Vec::new();
    let filehost_id = commande.filehost_id.as_str();
    for fuuid in commande.fuuids {
        batch.push(FilehostingVisitRow {
            fuuid,
            filehost_id: filehost_id.to_string(),
            visit_time: commande.visit_time
        });
    }
    if ! batch.is_empty() {
        let collection_visits = mongo.get_collection_typed::<FilehostingVisitRow>(NOM_COLLECTION_FILEHOSTING_VISITS)?;
        collection_visits.insert_many(batch).await?;
    }

    if commande.done == Some(true) {
        // Put flag to indicate this filehost_id has sent all its visits successfully
        let collection_files_status = mongo.get_collection(NOM_COLLECTION_FILEHOSTING_SYNC_STATUS)?;
        let filtre = doc!{"claimer": filehost_id, "claimer_type": "filehost"};
        let ops = doc! {
            "$currentDate": {"date_ready": true},
        };
        collection_files_status.update_one(filtre, ops).upsert(true).await?;
    }

    // S'assurer d'avoir un filecontroler primary
    check_primary_filecontroler(mongo, outbound, instance_id.as_str()).await?;

    outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
}

#[derive(Deserialize)]
struct CommandBatchTransfers {
    destination_filehost_id: String,
    batch_size: Option<usize>,
}

#[derive(Serialize)]
struct CommandBatchTransfersResponse {
    ok: bool,
    destination_filehost_id: String,
    fuuids: Option<Vec<CommandBatchTransfersResponseFuuid>>
}

async fn filehost_batch_transfers<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    if !wrapper.certificate.verifier_exchanges(vec![Securite::L1Public])? ||
        !wrapper.certificate.verifier_roles_string(vec!["filecontroler".to_string()])?
    {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    let commande: CommandBatchTransfers = wrapper.message.deserialize()?;
    let batch_limit = commande.batch_size.unwrap_or_else(|| 10);

    let collection_transfers =
        mongo.get_collection_typed::<FilehostTransfer>(NOM_COLLECTION_FILEHOSTING_TRANSFERS)?;

    // Recuperer les nouveaux transferts en premier (job_picked_up = null)
    let filtre = doc!{
        "destination_filehost_id": &commande.destination_filehost_id,
        "$or": [
            { FIELD_JOB_PICKED_UP: {"$exists": false} },
            { FIELD_JOB_PICKED_UP: None::<bool> },
        ]
    };
    let curseur = collection_transfers
        .find(filtre)
        .limit(batch_limit as i64)
        .await?;

    let mut fuuids_list = parse_filehost_visits(mongo, curseur).await?;
    if fuuids_list.len() < batch_limit {
        let timeout_transfert = Utc::now() - Duration::seconds(600);
        // On n'a pas une batch complete. Aller chercher les transferts a re-essayer.
        let batch_limit_2 = batch_limit - fuuids_list.len();
        let filtre = doc! {
            "destination_filehost_id": &commande.destination_filehost_id,
            FIELD_JOB_PICKED_UP: {"$lte": timeout_transfert}
        };
        let curseur = collection_transfers
            .find(filtre)
            .limit(batch_limit_2 as i64)
            .sort(doc!{FIELD_JOB_PICKED_UP: 1})
            .await?;
        let fuuids_list_2 = parse_filehost_visits(mongo, curseur).await?;
        fuuids_list.extend(fuuids_list_2);
    }

    // Marquer tous les fuuids comme inclus dans une job (timestamp).
    if fuuids_list.len() > 0 {
        let fichiers_inclus: Vec<&str> = fuuids_list.iter().map(|f| f.fuuid.as_str()).collect();
        let filtre_jobs = doc! {"fuuid": {"$in": fichiers_inclus}};
        let ops = doc! {"$currentDate": {FIELD_JOB_PICKED_UP: true}};
        collection_transfers.update_many(filtre_jobs, ops).await?;
    }

    let reponse = CommandBatchTransfersResponse {
        ok: true,
        destination_filehost_id: commande.destination_filehost_id,
        fuuids: Some(fuuids_list),
    };
    outbound.respond(wrapper.delivery_info, reponse).await
}

#[derive(Serialize)]
struct CommandBatchTransfersResponseFuuid {
    fuuid: String,
    source_filehost_ids: Vec<String>,
}

async fn parse_filehost_visits<M>(
    mongo: &M,
    mut curseur: Cursor<FilehostTransfer>
) -> Result<Vec<CommandBatchTransfersResponseFuuid>, CommonError> where M: MongoDaoTyped {
    let collection_fuuids =
        mongo.get_collection_typed::<RowFilehostFuuid>(NOM_COLLECTION_FILEHOSTING_FUUIDS)?;

    let mut fuuids_list = Vec::new();

    while curseur.advance().await? {
        let row = curseur.deserialize_current()?;
        let fuuid = row.fuuid;
        let filtre_fuuid = doc! {"fuuid": &fuuid};
        if let Some(fuuid_info) = collection_fuuids.find_one(filtre_fuuid).await? {
            if let Some(visits) = fuuid_info.filehost {
                let source_filehost_ids = visits.into_keys().collect();
                let fuuid_response = CommandBatchTransfersResponseFuuid { fuuid, source_filehost_ids };
                fuuids_list.push(fuuid_response);
            }
        }
    }

    Ok(fuuids_list)
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
        TRANSACTION_SET_FILEHOST_FOR_INSTANCE => transaction_sample(mongo, pki, outbound, transaction, wrapper).await,
        TRANSACTION_FILEHOST_DEFAULT => todo!(),
        TRANSACTION_DELETE_DOMAIN => todo!(),
        TRANSACTION_FILEHOST_ADD_V2 => todo!(),
        TRANSACTION_FILEHOST_UPDATE => todo!(),
        TRANSACTION_FILEHOST_DELETE => todo!(),
        _ => {
            info!("Unknown action {} for process_transaction, skipping", action);
            Ok(())
        }
    }
}

async fn transaction_sample<M>(
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
