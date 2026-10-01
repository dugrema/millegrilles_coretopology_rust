use crate::constants::DOMAIN_NAME;
use crate::external::mongo::*;
use crate::external::mq::*;
use crate::flow::filecontroler::{add_missing_file_transfers, check_primary_filecontroler, entretien_transfert_fichiers};
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
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::serde_json::Value;
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::tracing::{debug, error, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use std::collections::{HashMap, HashSet};
use millegrilles_common_rust::v3::ChiffrageService;

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

#[derive(Deserialize)]
struct RequeteGetVisitesFuuids {
    fuuids: Vec<String>,
}

#[derive(Serialize)]
pub struct ResponseGetVisitesFuuids {
    pub ok: bool,
    pub visits: Vec<FuuidVisitResponseItem>,
    pub unknown: Vec<String>,
    pub done: Option<bool>
}

async fn claim_filehost_visits_for_fuuids<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    if ! wrapper.certificate.verifier_exchanges(vec![Securite::L3Protege])? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    let estampille_date = wrapper.message.estampille.clone();
    let requete: RequeteGetVisitesFuuids = wrapper.message.deserialize()?;

    let mut fuuids_set = HashSet::new();
    fuuids_set.extend(requete.fuuids.iter());
    // let mut response_fuuids: HashMap<String, RowFuuidVisitResponse> = HashMap::new();
    let mut response_fuuids: Vec<FuuidVisitResponseItem> = Vec::new();
    let mut new_claims_fuuids: Vec<RowFilehostFuuid> = Vec::new();

    let filtre = doc! {"fuuid": {"$in": &requete.fuuids}};
    let collection = mongo.get_collection_typed::<RowFilehostFuuid>(COLLECTION_FILEHOSTING_FUUIDS)?;
    let mut curseur = collection.find(filtre).await?;
    while let Some(row) = curseur.next().await {
        let row = row?;

        // Keep as new claim if claim date is null. Triggers the transfer when appropriate
        if row.last_claim_date.is_none() {
            new_claims_fuuids.push(row.clone());
        }

        fuuids_set.remove(&row.fuuid);
        response_fuuids.push(row.into());
    }

    // Dedupe fuuids
    let mut fuuids_requis = HashSet::new();
    for f in &requete.fuuids {
        fuuids_requis.insert(f);
    }

    // Save in the claims aggregation table
    {
        let now = Utc::now();
        let mut batch = Vec::new();
        let extensions = wrapper.certificate.extensions()?;
        let domains = extensions.domaines;
        if ! fuuids_requis.is_empty() {
            for fuuid in &fuuids_requis {
                batch.push(doc! {"fuuid": *fuuid, "claim_date": &now, "domains": &domains})
            }
            let collection_agg_claim = mongo.get_collection(COLLECTION_FILEHOSTING_CLAIMS)?;
            collection_agg_claim.insert_many(batch).await?;
        }
    }

    // Conserver les reclamations.
    let collection_claims = mongo.get_collection_typed::<RowFilehostFuuid>(COLLECTION_FILEHOSTING_FUUIDS)?;
    let filtre_reclamations = doc!{ "fuuid": {"$in": &requete.fuuids} };
    let ops_reclamations = doc! {"$currentDate": {FIELD_LAST_CLAIM_DATE: true}};
    let update_result = collection_claims.update_many(filtre_reclamations.clone(), ops_reclamations).await?;
    if update_result.matched_count as usize != fuuids_requis.len() {
        info!("Mismatch updates {} et claims {}. Inserer nouveaux claims.", requete.fuuids.len(), update_result.matched_count);
        let mut curseur = collection_claims
            .find(filtre_reclamations)
            .projection(doc!{"fuuid": 1})
            .await?;
        while curseur.advance().await? {
            let row = curseur.deserialize_current()?;
            fuuids_requis.remove(&row.fuuid);
        }

        if ! fuuids_requis.is_empty() {
            let mut rows = Vec::new();
            for f in fuuids_requis {
                debug!("Ajouter nouveau fuuid reclame {}", f);
                let row = RowFilehostFuuid { fuuid: f.to_owned(), last_claim_date: Some(estampille_date.to_owned()), filehost: Some(HashMap::new()) };
                rows.push(row);
            }
            let collection_insert_claims =
                mongo.get_collection_typed::<RowFilehostFuuid>(COLLECTION_FILEHOSTING_FUUIDS)?;
            collection_insert_claims.insert_many(rows).await?;
        }
    }

    let response = ResponseGetVisitesFuuids {
        ok: true,
        visits: response_fuuids,
        unknown: Vec::from_iter(fuuids_set.into_iter().map(|f|f.to_string())),
        done: None,  // Not batching
    };

    // Mettre a jour tous les transferts de fichier
    let mut session = mongo.get_session().await?;
    session.start_transaction().await?;
    add_missing_file_transfers(mongo, outbound, &mut session, new_claims_fuuids).await?;

    outbound.respond(wrapper.delivery_info, response).await
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
        mongo.get_collection_typed::<RowFilehostFuuid>(COLLECTION_FILEHOSTING_FUUIDS)?;
    let collection_transfers =
        mongo.get_collection_typed::<RowFilehostFuuid>(COLLECTION_FILEHOSTING_TRANSFERS)?;

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
        mongo.get_collection_typed::<RowFilehostFuuid>(COLLECTION_FILEHOSTING_TRANSFERS)?;
    let filtre = doc!{"job_picked_up": {"$exists":true}};
    let ops = doc! {"$unset": {"job_picked_up": true}, "$currentDate": {"modified": true}};
    collection_transfers.update_many(filtre, ops).await?;

    // Reverifie chaque transfert, enleve ceux qui ne s'appliquent plus et cree les nouveaux
    entretien_transfert_fichiers(mongo, outbound).await?;

    outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
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
        let collection_claims = mongo.get_collection(COLLECTION_FILEHOSTING_CLAIMS)?;
        collection_claims.insert_many(batch).await?;
    }

    if request.done == Some(true) {
        // Put flag to indicate this domain has sent all its claims successfully
        let collection_files_status = mongo.get_collection(COLLECTION_FILEHOSTING_SYNC_STATUS)?;
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
        let collection_visits = mongo.get_collection_typed::<FilehostingVisitRow>(COLLECTION_FILEHOSTING_VISITS)?;
        collection_visits.insert_many(batch).await?;
    }

    if commande.done == Some(true) {
        // Put flag to indicate this filehost_id has sent all its visits successfully
        let collection_files_status = mongo.get_collection(COLLECTION_FILEHOSTING_SYNC_STATUS)?;
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
        mongo.get_collection_typed::<FilehostTransfer>(COLLECTION_FILEHOSTING_TRANSFERS)?;

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
        mongo.get_collection_typed::<RowFilehostFuuid>(COLLECTION_FILEHOSTING_FUUIDS)?;

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
    outbound: &MessageOutboundFacade,
    chiffrage: &dyn ChiffrageService,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in transaction")).await
    };
    match action {
        TRANSACTION_SET_FILEHOST_FOR_INSTANCE => set_filehost_for_instance(outbound, transaction, wrapper).await,
        TRANSACTION_FILEHOST_DEFAULT => set_filehost_default(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_DELETE_DOMAIN => delete_domain(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_FILEHOST_ADD_V2 => add_filehost_v2(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_FILEHOST_UPDATE => update_filehost(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_FILEHOST_DELETE => delete_filehost(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_CONFIGURATION_CREATE_FILE => configuration_create_file(mongo, outbound, chiffrage, transaction, wrapper).await,
        TRANSACTION_CONFIGURATION_UPDATE_FILE => configuration_update_file(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_CONFIGURATION_DELETE_FILE => configuration_delete_file(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_CONFIGURATION_SET_PROPERTY => configuration_set_property(mongo, outbound, transaction, wrapper).await,
        TRANSACTION_CONFIGURATION_DELETE_PROPERTY => configuration_delete_property(mongo, outbound, transaction, wrapper).await,
        _ => {
            info!("Unknown action {} for process_transaction, skipping", action);
            Ok(())
        }
    }
}

async fn set_filehost_for_instance(
    outbound: &MessageOutboundFacade,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    // Verifier autorisation
    if ! wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    // Validate command structure
    let _transaction_value: TransactionSetFilehostInstance = wrapper.message.deserialize()?;

    // Process transaction
    let delivery_info = wrapper.delivery_info.clone();
    if let Err(e) = transaction.process_transaction(wrapper.into(), None).await {
        error!("Error processing transaction {:?}", e);
        return outbound.respond(delivery_info, ErrorMessage::err_code(500, "Error processing transaction")).await
    }

    // Emit filehost update event
    let routage = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE,
        EVENEMENT_FILEHOSTING_UPDATE,
        vec![Securite::L1Public]
    ).build();
    outbound.emit_event(routage, ErrorMessage::ok()).await?;

    // Respond OK
    outbound.respond(delivery_info, ErrorMessage::ok()).await
}

async fn set_filehost_default<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    if ! wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    let transaction_value: TransactionFilehostSetDefault = wrapper.message.deserialize()?;

    // Verifier que la valeur n'est pas la meme
    let collection_config =
        mongo.get_collection_typed::<FilehostingCongurationRow>(COLLECTION_FILEHOSTINGCONFIGURATION)?;
    let filtre = doc!{"name": FIELD_CONFIGURATION_FILEHOST_DEFAULT};
    if let Some(entry) = collection_config.find_one(filtre).await? {
        if entry.value.as_str() == transaction_value.filehost_id.as_str() {
            // Already done, send back ok
            return outbound.respond(wrapper.delivery_info, ErrorMessage::ok()).await
        }
    }

    // Process transaction
    let delivery_info = wrapper.delivery_info.clone();
    if let Err(e) = transaction.process_transaction(wrapper.into(), None).await {
        error!("Error processing transaction {:?}", e);
        return outbound.respond(delivery_info, ErrorMessage::err_code(500, "Error processing transaction")).await
    }

    // Emit filehost update event
    let routage = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE,
        EVENEMENT_FILEHOSTING_UPDATE,
        vec![Securite::L1Public]
    ).build();
    outbound.emit_event(routage, ErrorMessage::ok()).await?;

    // Respond OK
    outbound.respond(delivery_info, ErrorMessage::ok()).await
}

async fn delete_domain<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    if ! wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    let transaction_value: TransactionDeleteDomain = wrapper.message.deserialize()?;

    // Verifier que la valeur n'est pas la meme
    let collection_domains =
        mongo.get_collection_typed::<DomainRow>(COLLECTION_DOMAINS)?;
    let filtre = doc!{CHAMP_DOMAINE: &transaction_value.domain_name};
    if ! collection_domains.find_one(filtre).await?.is_some() {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, format!("Unknown domain: {}", transaction_value.domain_name).as_str())).await
    }

    // Process transaction
    let delivery_info = wrapper.delivery_info.clone();
    if let Err(e) = transaction.process_transaction(wrapper.into(), None).await {
        error!("Error processing transaction {:?}", e);
        return outbound.respond(delivery_info, ErrorMessage::err_code(500, "Error processing transaction")).await
    }

    // Emit filehost update event
    let routage = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, EVENEMENT_FILEHOSTING_UPDATE, vec![Securite::L1Public])
        .build();
    outbound.emit_event(routage, ErrorMessage::ok()).await?;

    // Respond
    outbound.respond(delivery_info, ErrorMessage::ok()).await
}

#[derive(Serialize)]
struct HostfileAddTransactionResponse {
    ok: bool,
    filehost_id: String
}

async fn add_filehost_v2<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let transaction_value: FilehostAddTransactionV2 = wrapper.message.deserialize()?;
    let message_id = wrapper.message.id.clone();
    let certificat = wrapper.certificate.as_ref();

    if certificat.verifier_roles_string(vec!["filecontroler".to_string()])? && certificat.verifier_exchanges(vec![Securite::L1Public])?{
        if let Some(instance_id) = transaction_value.instance_id.as_ref() {
            // This is a file controler trying to automatically add a local file host.
            // Ensure that no file host exists (including deleted ones) for the instance_id that is being used.
            let collection = mongo.get_collection_typed::<FilehostServerRow>(COLLECTION_FILEHOSTS)?;
            let filtre = doc!{"instance_id": instance_id};
            match collection.find_one(filtre).await? {
                Some(filehost_row) => {
                    // Exists, check if restore (when deleted) or conflict
                    let response = check_restore_existing_filehost(mongo, transaction, outbound, message_id.as_str(), filehost_row).await?;
                    return outbound.respond(wrapper.delivery_info, response).await
                },
                None => ()  // Ok, this is a new filehost
            }
        } else {
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
        }
    } else if certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        if let Some(url_external) = transaction_value.url_external.as_ref() {
            // Admin adding an external file host.
            // Ensure no file host exists for this url.
            let collection = mongo.get_collection_typed::<FilehostServerRow>(COLLECTION_FILEHOSTS)?;
            let filtre = doc!{"url_external": url_external};
            match collection.find_one(filtre).await? {
                Some(filehost_row) => {
                    // Exists, check if restore (when deleted) or conflict
                    let response = check_restore_existing_filehost(mongo, transaction, outbound, message_id.as_str(), filehost_row).await?;
                    return outbound.respond(wrapper.delivery_info, response).await
                }
                None => ()  // Ok, this is a new filehost
            }
        } else {
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
        }
    } else {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    // Process transaction
    let delivery_info = wrapper.delivery_info.clone();
    if let Err(e) = transaction.process_transaction(wrapper.into(), None).await {
        error!("Error processing transaction {:?}", e);
        return outbound.respond(delivery_info, ErrorMessage::err_code(500, "Error processing transaction")).await
    }

    // Check if we have a default filehost. If not, set this new filehost as default.
    check_default_filehost(mongo, message_id.as_str()).await?;

    // Load the new filehost, emit as event
    let filtre = doc!{"filehost_id": &message_id};
    let collection = mongo.get_collection_typed::<FilehostServerRow>(COLLECTION_FILEHOSTS)?;
    match collection.find_one(filtre).await? {
        Some(inner) => {
            let routing = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, "filehostAdd", vec![Securite::L1Public])
                .build();
            let filehost_item: RequeteFilehostItem = inner.into();
            outbound.emit_event(routing, filehost_item).await?;
            emit_filehost_event(outbound, &message_id, EVENEMENT_FILEHOST_EVENTNEW).await?;  // Simple event
        }
        None => {
            warn!("command_filehost_add Transaction successful but no item in database for {}", message_id);
        }
    }

    let response = HostfileAddTransactionResponse {ok: true, filehost_id: message_id.to_string()};
    outbound.respond(delivery_info, response).await
}

async fn check_restore_existing_filehost<M>(
    mongo: &M,
    transaction: &TopologyTransactionService,
    outbound: &MessageOutboundFacade,
    message_id: &str,
    row: FilehostServerRow,
) -> Result<Value, CommonError> where M: MongoDaoTyped {
    // Check if deleted (this would be a restore)
    if row.deleted {
        info!("command_filehost_add Restoring filehost, rewriting add as update delete=false");
        let filehost_update = FilehostRestoreTransaction { filehost_id: row.filehost_id.clone() };
        transaction.process_value(DOMAINE_TOPOLOGIE, TRANSACTION_FILEHOST_RESTORE, serde_json::to_value(&filehost_update)?, None).await?;

        check_default_filehost(mongo, row.filehost_id.as_str()).await?;

        // Load the new filehost, emit as event
        let filtre = doc! {"filehost_id": &row.filehost_id};
        let collection = mongo.get_collection_typed::<FilehostServerRow>(COLLECTION_FILEHOSTS)?;
        match collection.find_one(filtre).await? {
            Some(inner) => {
                let filehost_item: RequeteFilehostItem = inner.into();
                // Emit new event
                emit_filehost_event(outbound, filehost_item.filehost_id.as_str(), EVENEMENT_FILEHOST_EVENTNEW).await?;  // Simple event
                // Also emit restore event
                let routing = RoutageMessageAction::builder(
                    DOMAINE_TOPOLOGIE,
                    "filehostRestore",
                    vec![Securite::L1Public]
                ).build();
                outbound.emit_event(routing, filehost_item).await?;
            }
            None => {
                warn!("command_filehost_add Transaction successful but no item in database for {}", message_id);
            }
        }

        let response = HostfileAddTransactionResponse {ok: true, filehost_id: row.filehost_id};
        Ok(serde_json::to_value(response)?)
    } else {
        // Conflict, already exists and not deleted
        Ok(serde_json::to_value(ErrorMessage::err_code(409, "Url exists"))?)
    }
}

async fn check_default_filehost<M>(mongo: &M, filehost_id: &str) -> Result<(), CommonError>
where M: MongoDaoTyped
{
    let filtre = doc!{"name": FIELD_CONFIGURATION_FILEHOST_DEFAULT};
    let collection = mongo.get_collection_typed::<FilehostingCongurationRow>(COLLECTION_FILEHOSTINGCONFIGURATION)?;
    let result = collection.find_one(filtre).await?;
    if result.is_none() {
        info!("Initialize default filehost to {}", filehost_id);
        // Initialize in a volatile way. User can override manually later.
        let row = FilehostingCongurationRow {
            name: FIELD_CONFIGURATION_FILEHOST_DEFAULT.into(),
            value: filehost_id.to_string()
        };
        collection.insert_one(row).await?;
    }
    Ok(())
}

async fn emit_filehost_event(
    outbound: &MessageOutboundFacade,
    filehost_id: &str,
    event_str: &str,
) -> Result<(), CommonError> {
    let event = EventFilehost { filehost_id: filehost_id.to_string(), event: event_str.to_string() };
    let routage = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, EVENEMENT_FILEHOST_EVENT, vec![Securite::L1Public])
        .build();
    outbound.emit_event(routage, &event).await?;
    Ok(())
}

async fn update_filehost<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let doc_transaction: FilehostUpdateTransaction = wrapper.message.deserialize()?;

    let certificat = wrapper.certificate.as_ref();
    if certificat.verifier_roles_string(vec!["filecontroler".to_string()])? && certificat.verifier_exchanges(vec![Securite::L1Public])?{
        // File controler
    } else if certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Admin
    } else {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    let collection = mongo.get_collection_typed::<FilehostServerRow>(COLLECTION_FILEHOSTS)?;
    let filtre = doc! {"filehost_id": doc_transaction.filehost_id};

    // Check that the message exists
    let current_version = match collection.find_one(filtre).await? {
        Some(inner) => inner,
        None => {
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "No match")).await
        }
    };

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

    if set_ops.len() == 0 {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(400, "No changes")).await
    }

    // Process transaction
    let delivery_info = wrapper.delivery_info.clone();
    if let Err(e) = transaction.process_transaction(wrapper.into(), None).await {
        error!("Error processing transaction {:?}", e);
        return outbound.respond(delivery_info, ErrorMessage::err_code(500, "Error processing transaction")).await
    }

    // Emit events
    let event_str = match current_version.deleted {
        true => EVENEMENT_FILEHOST_EVENTDELETE,  // Consider this a delete event
        false => EVENEMENT_FILEHOST_EVENTUPDATE,
    };
    emit_filehost_event(outbound, &current_version.filehost_id, event_str).await?;  // Simple event

    let routing = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE,
        "filehostUpdate",
        vec![Securite::L1Public]
    ).build();
    let filehost_item: RequeteFilehostItem = current_version.into();
    outbound.emit_event(routing, filehost_item).await?;

    // Respond
    outbound.respond(delivery_info, ErrorMessage::ok()).await
}

#[derive(Serialize)]
struct EventFilehostDeleted { filehost_id: String }

async fn delete_filehost<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let mut transaction_value: FilehostDeleteTransaction = wrapper.message.deserialize()?;
    let certificat = wrapper.certificate.as_ref();
    if certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok, admin removing file host.
    } else {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    let filehost_id = transaction_value.filehost_id.clone();
    // Check that filehost exists and is not deleted (flag).
    let collection = mongo.get_collection(COLLECTION_FILEHOSTS)?;
    let filtre = doc!{"filehost_id": &filehost_id, "deleted": false};
    let result = collection.find_one(filtre).await?;
    if result.is_none() {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Filehost does not exist or is already deleted")).await
    }

    let delivery_info = wrapper.delivery_info.clone();

    // Process transaction, check to delete default filehost configuration item if matches filehost_id
    let collection_configuration = mongo.get_collection_typed::<FilehostingCongurationRow>(COLLECTION_FILEHOSTINGCONFIGURATION)?;
    let filtre_configuration = doc!{"name": FIELD_CONFIGURATION_FILEHOST_DEFAULT, "value": &filehost_id};
    match collection_configuration.find_one(filtre_configuration).await? {
        Some(_config) => {
            // This is the default filehost, amend and re-sign the transaction to toggle the reset default flag
            transaction_value.reset_default = Some(true);
            if let Err(e) = transaction.process_value(
                DOMAIN_NAME,
                TRANSACTION_FILEHOST_DELETE,
                serde_json::to_value(&transaction_value)?,
                None
            ).await {
                error!("Error processing transaction {:?}", e);
                return outbound.respond(delivery_info, ErrorMessage::err_code(500, "Error processing transaction")).await
            }
        },
        None => {
            // This is not the default filehost, process transaction as received
            if let Err(e) = transaction.process_transaction(wrapper.into(), None).await {
                error!("Error processing transaction {:?}", e);
                return outbound.respond(delivery_info, ErrorMessage::err_code(500, "Error processing transaction")).await
            }
        }
    }

    let event = EventFilehostDeleted { filehost_id: filehost_id.to_string() };
    let routing = RoutageMessageAction::builder(
        DOMAINE_TOPOLOGIE,
        "filehostDelete",
        vec![Securite::L1Public]
    ).build();
    outbound.emit_event(routing, event).await?;

    emit_filehost_event(outbound, filehost_id.as_str(), EVENEMENT_FILEHOST_EVENTDELETE).await?;  // Simple event

    // Respond
    outbound.respond(delivery_info, ErrorMessage::ok()).await
}

#[derive(Serialize)]
struct ResponseConfigurationCreateFile {
    file_id: String,
    key_id: String,
}

async fn configuration_create_file<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    chiffrage: &dyn ChiffrageService,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let command: CommandCreateConfigurationFile = wrapper.message.deserialize()?;

    if ! wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Access denied")).await
    }

    // Check if the configuration file exists, by name.
    let collection = mongo.get_collection(COLLECTION_CONFIGURATION_FILES)?;
    let result = collection
        .find_one(doc!{"filename": &command.filename})
        .projection(doc!{"filename": true})
        .await?;
    if result.is_some() {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(409, "File already exists")).await
    }

    // The command does not include an encryption key. Create one, save it with the keymaster
    // and create a transaction to process.
    let new_key = chiffrage.generate_new_key(&vec![DOMAIN_NAME.to_string()]).await?;
    let key_id = new_key.key_id.clone();
    debug!("Saving new key {}", key_id);
    outbound.save_keys(&vec![&new_key], Some(5_000)).await?;

    let transaction_value = TransactionCreateConfigurationFile {
        filename: command.filename,
        roles: command.roles,
        domains: command.domains,
        key_id: new_key.key_id,
        requestor_fingerprint: wrapper.certificate.fingerprint()?,
    };

    let file_id = transaction.process_value(
        DOMAIN_NAME,
        TRANSACTION_CONFIGURATION_CREATE_FILE,
        serde_json::to_value(transaction_value)?,
        None
    ).await?;

    let response = ResponseConfigurationCreateFile { file_id, key_id };
    outbound.respond(wrapper.delivery_info, response).await
}

async fn configuration_update_file<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let transaction_value: TransactionUpdateConfigurationFile = wrapper.message.deserialize()?;

    if ! wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Access denied")).await
    }

    // Check if there are changes in the transaction
    if transaction_value.domains.is_none() &&
        transaction_value.filename.is_none() &&
        transaction_value.roles.is_none()
    {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(400, "No changes detected in transaction")).await
    }

    // Check if the configuration file exists, by name.
    let collection = mongo.get_collection(COLLECTION_CONFIGURATION_FILES)?;
    let result = collection
        .find_one(doc!{"file_id": &transaction_value.file_id})
        .projection(doc!{"file_id": true})
        .await?;
    if result.is_none() {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "File not found")).await
    }

    let delivery_info = wrapper.delivery_info.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    outbound.respond(delivery_info, ErrorMessage::ok()).await
}

async fn configuration_delete_file<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let transaction_value: TransactionDeleteConfigurationFile = wrapper.message.deserialize()?;

    if ! wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Access denied")).await
    }

    // Check if the configuration file exists, by name.
    let collection = mongo.get_collection(COLLECTION_CONFIGURATION_FILES)?;
    let result = collection
        .find_one(doc!{"file_id": &transaction_value.file_id})
        .projection(doc!{"file_id": true})
        .await?;
    if result.is_none() {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "File not found")).await
    }

    let delivery_info = wrapper.delivery_info.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    outbound.respond(delivery_info, ErrorMessage::ok()).await
}

async fn configuration_set_property<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let transaction_value: TransactionSetFileProperty = wrapper.message.deserialize()?;

    if ! wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Access denied")).await
    }

    // Check if the configuration file exists, by id. Do not set property for non-existant file.
    let collection = mongo.get_collection(COLLECTION_CONFIGURATION_FILES)?;
    let result = collection
        .find_one(doc!{"file_id": &transaction_value.file_id})
        .projection(doc!{"file_id": true})
        .await?;
    if result.is_none() {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "File not found")).await
    }

    let delivery_info = wrapper.delivery_info.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    outbound.respond(delivery_info, ErrorMessage::ok()).await
}

async fn configuration_delete_property<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    transaction: &TopologyTransactionService,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let transaction_value: TransactionDeleteFileProperty = wrapper.message.deserialize()?;

    if ! wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401, "Access denied")).await
    }

    let collection = mongo.get_collection(COLLECTION_CONFIGURATION_PROPERTIES)?;
    let result = collection
        .find_one(doc!{"file_id": &transaction_value.file_id, "key": &transaction_value.key})
        .projection(doc!{"_id": true})
        .await?;
    if result.is_none() {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "File not found")).await
    }

    let delivery_info = wrapper.delivery_info.clone();
    transaction.process_transaction(wrapper.into(), None).await?;

    outbound.respond(delivery_info, ErrorMessage::ok()).await
}
