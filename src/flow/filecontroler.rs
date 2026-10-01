use crate::external::mongo::*;
use crate::external::mq::*;
use crate::models::*;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::bson::oid::ObjectId;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{DateTime, Duration, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::mongo_dao::{ChampIndex, IndexOptions, MongoDaoTyped};
use millegrilles_common_rust::mongo_serde::option_chrono_04_datetime;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::mongodb::options::Hint;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tracing::{debug, error, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use std::collections::{HashMap, HashSet};

pub async fn process_filecontroler_events<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return Err(CommonError::Str("No action provided in event message"))
    };
    match action {
        EVENEMENT_FILEHOST_USAGE => filehost_usage(mongo, wrapper).await,
        EVENEMENT_FILEHOST_NEWFUUID => filehost_newfuuid(mongo, outbound, wrapper).await,
        _ => {
            info!("Unknown action {} for process_command, skipping", action);
            Ok(())
        }
    }

}

async fn filehost_usage<M>(
    mongo: &M,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    if ! wrapper.certificate.verifier_roles_string(vec!["filecontroler".to_string()])? {
        debug!("traiter_evenement_filehost_usage Wrong certificate for event - DROPPED");
        return Ok(())
    }

    let commande: EventFilehostUsage = wrapper.message.deserialize()?;
    let filtre = doc! {"filehost_id": &commande.filehost_id};
    let ops = doc!{
        "$set": {
            "stats_updated": &commande.date,
            "fuuid": bson::serialize_to_document(&commande.fuuid)?,
        },
        "$currentDate": {"modified": true}
    };
    let collection = mongo.get_collection(COLLECTION_FILEHOSTS)?;
    let result = collection.update_one(filtre, ops).await?;

    if result.matched_count == 0 {
        warn!("traiter_evenement_filehost_usage Received event for unknown filehost_id {}", commande.filehost_id);
    }

    Ok(())
}

#[derive(Deserialize)]
pub struct EventNewFuuid {
    pub filehost_id: String,
    pub fuuid: String,
}

async fn filehost_newfuuid<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    if ! wrapper.certificate.verifier_roles_string(vec!["filecontroler".to_string()])? {
        debug!("traiter_evenement_filehost_newfuuid Wrong certificate for event - DROPPED");
        return Ok(())
    }

    let command: EventNewFuuid = wrapper.message.deserialize()?;

    // Add filehost_id/fuuid to the visit aggregation table
    let collection_visits = mongo.get_collection_typed::<FilehostingVisitRow>(NOM_COLLECTION_FILEHOSTING_VISITS)?;
    let row = FilehostingVisitRow {
        fuuid: command.fuuid,
        filehost_id: command.filehost_id,
        visit_time: wrapper.message.estampille
    };
    collection_visits.insert_one(&row).await?;

    let filtre = doc! {"fuuid": &row.fuuid};
    let ops = doc! {
        "$set": {
            format!("filehost.{}", &row.filehost_id): &row.visit_time,
        }
    };
    let collection = mongo.get_collection(COLLECTION_FILEHOSTING_FUUIDS)?;
    collection
        .update_one(filtre, ops)
        .upsert(true)
        .await?;

    process_transfers(mongo, outbound, row.filehost_id.as_str(), row.fuuid.as_str()).await?;

    Ok(())
}

#[derive(Serialize)]
struct EvenementPrimaryFilecontroler {
    filecontroler_id: String
}

pub async fn check_primary_filecontroler<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    instance_id: &str
) -> Result<(), CommonError> where M: MongoDaoTyped {
    // Check if a primary filecontroler exists
    let filtre = doc!{"name": FIELD_CONFIGURATION_FILECONTROLER_PRIMARY};
    let collection = mongo.get_collection_typed::<FilehostingCongurationRow>(NOM_COLLECTION_FILEHOSTINGCONFIGURATION)?;
    let result = collection
        .find_one(filtre)
        .await?;

    if result.is_none() {
        info!("Initialize primary filecontroler instance_id to {}", instance_id);
        // Initialize in a volatile way. User can override manually later.
        let row = FilehostingCongurationRow {name: FIELD_CONFIGURATION_FILECONTROLER_PRIMARY.into(), value: instance_id.to_string()};
        collection.insert_one(row).await?;

        // Emettre evenement de changement de filecontroler primary
        let routage = RoutageMessageAction::builder(TOPOLOGIE_NOM_DOMAINE, "primaryFilecontroler", vec![Securite::L1Public])
            .build();
        let event = EvenementPrimaryFilecontroler { filecontroler_id: instance_id.into() };
        outbound.emit_event(routage, event).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
pub struct RowFilehostId { pub filehost_id: String }

async fn process_transfers<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    filehost_id: &str,
    fuuid: &str
) -> Result<(), CommonError> where M: MongoDaoTyped {
    // Supprimer le transfert vers ce filehost (si applicable)
    let filtre_transfer = doc!{"fuuid": fuuid, "destination_filehost_id": filehost_id};
    let collection_transfers = mongo.get_collection(COLLECTION_FILEHOSTING_TRANSFERS)?;
    collection_transfers.delete_one(filtre_transfer).await?;

    // Creer les transferts vers filehosts sans ce fuuid

    // Recuperer liste de filehost_ids actifs
    let collection_filehosts = mongo.get_collection_typed::<RowFilehostId>(COLLECTION_FILEHOSTS)?;
    let filtre = doc! { "deleted": false, "sync_active": true };
    let mut curseur = collection_filehosts
        .find(filtre)
        .projection(doc!{"filehost_id": 1})
        .await?;
    let mut filehost_ids = HashSet::new();
    while curseur.advance().await? {
        let row = curseur.deserialize_current()?;
        filehost_ids.insert(row.filehost_id);
    }

    let collection_fuuids = mongo.get_collection_typed::<RowFilehostFuuid>(COLLECTION_FILEHOSTING_FUUIDS)?;
    let fuuid_info = collection_fuuids.find_one(doc!{"fuuid": fuuid}).await?;
    if let Some(row) = fuuid_info {
        if let Some(visits) = row.filehost {
            let mut filehost_ids_visits: HashSet<String> = visits.into_iter().map(|(k,_)| k).collect();
            // Ajouter le filehost_id qui vient d'emettre l'evenement newFuuid (meme s'il devrait deja etre dans la liste).
            filehost_ids_visits.insert(filehost_id.to_owned());

            let missing_from = filehost_ids.difference(&filehost_ids_visits);
            debug!("entretien_transfert_fichiers File {} missing from {:?}", row.fuuid, missing_from);
            let ops = doc! {
                "$setOnInsert": {"created": Utc::now()},
                "$currentDate": {"modified": true},
            };
            for missing_from_filehost_id in missing_from {
                let filtre = doc! {
                    "destination_filehost_id": &missing_from_filehost_id,
                    "fuuid": &row.fuuid,
                };
                collection_transfers
                    .update_one(filtre, ops.clone())
                    .upsert(true)
                    .await?;
            }
        }
    }

    emit_filehost_transfersupdated_event(outbound).await?;

    Ok(())
}

async fn emit_filehost_transfersupdated_event(outbound: &MessageOutboundFacade) -> Result<(), CommonError> {
    let event = ErrorMessage::ok();

    let routage = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, EVENEMENT_FILEHOST_TRANSFERSUPDATED, vec![Securite::L1Public])
        .build();
    outbound.emit_event(routage, &event).await?;

    // Emettre evenement de mise a jour de filehosts. Va declencher une verification des transferts.
    let routage = RoutageMessageAction::builder(DOMAINE_TOPOLOGIE, EVENEMENT_FILEHOSTING_UPDATE, vec![Securite::L1Public])
        .build();
    outbound.emit_event(routage, &event).await?;

    Ok(())
}

#[derive(Deserialize)]
struct FuuidFilehostRow {
    #[serde(rename="_id")]
    id: ObjectId,
    #[allow(dead_code)]
    fuuid: String,
    #[allow(dead_code)]
    destination_filehost_id: String,
}

/// Genere les transferts de fichiers manquants et supprime ceux qui ne s'appliquent plus.
pub async fn entretien_transfert_fichiers<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    debug!("entretien_transfert_fichiers Debut");

    let (filehosts_active, filehosts_inactive) = {
        let collection_filehosts =
            mongo.get_collection_typed::<FilehostServerRow>(COLLECTION_FILEHOSTS)?;
        let filtre = doc!{};
        let mut cursor = collection_filehosts.find(filtre).await?;

        let mut filehosts_active = HashMap::new();
        let mut filehosts_inactive = HashMap::new();
        while cursor.advance().await? {
            let row = cursor.deserialize_current()?;
            let active = row.sync_active && !row.deleted;
            match active {
                true => { filehosts_active.insert(row.filehost_id.clone(), row); }
                false => { filehosts_inactive.insert(row.filehost_id.clone(), row); }
            }
        }
        (filehosts_active, filehosts_inactive)
    };

    // Remove all transfers going to currently inactive filehosts
    let collection_transfers =
        mongo.get_collection_typed::<FilehostTransfer>(COLLECTION_FILEHOSTING_TRANSFERS)?;
    if filehosts_inactive.len() > 0 {
        debug!("entretien_transfert_fichiers {} filehosts inactifs", filehosts_inactive.len());
        let filehost_ids: Vec<&String> = filehosts_inactive.keys().into_iter().collect();
        let filtre = doc!{"destination_filehost_id": {"$in": filehost_ids}};
        collection_transfers.delete_many(filtre).await?;
    }

    // Consider claims of more than 3 days ago as expired
    let claim_expiration = Utc::now() - Duration::days(3);

    // Check each transfer to ensure it is still required
    let active_transfer_pipeline = vec![
        doc!{"$lookup": {
            "from": COLLECTION_FILEHOSTING_FUUIDS,
            "localField": "fuuid",
            "foreignField": "fuuid",
            "as": "visits",
        }},

        // Turn the filehost document into an array
        doc!{"$addFields": {"visit_entry": {"$arrayElemAt": ["$visits", 0]}}},
        doc!{"$addFields": {"visit_list": {"$objectToArray": "$visit_entry.filehost"}}},

        // Extract entry with visit_list[].k == destination_filehost_id
        doc!{"$addFields": {"last_visit": {"$filter": {
            "input": "$visit_list",
            "as": "visit",
            "cond": {"$eq": ["$$visit.k", "$destination_filehost_id"]}
        }}}},

        // Keep entry (for removal) if file is already present on destination or not claimed/expired
        // If a valid file is missing on destination => exists false, we want the transfer to happen.
        doc!{"$match":
            {"$or": [
                {"last_visit.0": {"$exists": true}},
                // Keep files with expired or missing claim field - the transfer must not happen
                {"last_claim_date": null},
                {"last_claim_date": {"$lte": claim_expiration}},
            ]}
        },

        doc!{"$project": {"_id": "$_id", "fuuid": 1, "destination_filehost_id": 1}},
        // doc!{"$out":{"db": middleware.get_database()?.name(), "coll": "CoreTopologie/test",}},
    ];
    debug!("Cleanup expired active transfers START");
    // collection_transfers.aggregate(active_transfer_pipeline, None).await?;
    let mut transfers_expired = 0;
    let mut cursor = collection_transfers.aggregate(active_transfer_pipeline).await?;
    const BATCH_SIZE: usize = 100;
    let mut batch_to_delete = Vec::new();
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        let row: FuuidFilehostRow = bson::deserialize_from_document(row)?;
        batch_to_delete.push(row.id);
        transfers_expired += 1;

        if batch_to_delete.len() >= BATCH_SIZE {
            let filtre_delete = doc!{"_id": {"$in": &batch_to_delete}};
            collection_transfers.delete_many(filtre_delete).await?;
            batch_to_delete.clear();
        }
    }
    if batch_to_delete.len() > 0 {
        let filtre_delete = doc!{"_id": {"$in": batch_to_delete}};
        collection_transfers.delete_many(filtre_delete).await?;
    }
    if transfers_expired > 0 {
        warn!("Cleanup {} expired active transfers DONE", transfers_expired);
    } else {
        debug!("Cleanup expired active transfers DONE");
    }

    // Create missing file transfers
    if filehosts_active.len() > 0 {
        // Make a list of active filehosts. Require that the visit be recent.
        let mut filehost_list = Vec::new();
        for (filehost_id, _) in &filehosts_active {
            filehost_list.push(doc!{format!("filehost.{}", filehost_id): {"$gte": claim_expiration}});
        }

        // Filter out entries without a recent claim or that don't exist anywhere
        // Only rely on filehosts with recent visits on the file.
        let match_filehosts = doc!{
            "last_claim_date": {"$gte": claim_expiration},
            "$or": filehost_list,
        };

        let mut filehost_doc = doc!{};
        for (filehost_id, _) in &filehosts_active {
            filehost_doc.insert(filehost_id.to_string(), false);
        }
        let fuuids_pipeline = vec![
            // Filter out entries without a recent claim or that don't exist anywhere
            doc!{"$match": match_filehosts},
            // Pad all filehost entries with active filehosts. Will result in false if no visit date exists.
            doc!{"$addFields": {"filehost_padded": {"$mergeObjects": [filehost_doc, "$filehost"]}}},
            doc!{"$addFields": {"filehost_elem": {"$objectToArray": "$filehost_padded"}}},
            doc!{"$unwind": {"path": "$filehost_elem"}},

            // Retain entries with filehost value of false, means there is no entry (no date).
            doc!{"$match": {"filehost_elem.v": false}},
            doc!{"$addFields": {"destination_filehost_id": "$filehost_elem.k", "created": "$$NOW", "modified": "$$NOW"}},
            doc!{"$project": {"fuuid": 1, "destination_filehost_id": 1, "created": 1, "modified": 1}},

            doc!{"$unset": "_id"},
            // doc!{"$out": {"db": middleware.get_database()?.name(), "coll": "CoreTopologie/transfer_test"}},
            doc!{"$merge": {
                "into": COLLECTION_FILEHOSTING_TRANSFERS,
                "on": ["destination_filehost_id", "fuuid"],
                "whenMatched": "keepExisting",
                "whenNotMatched": "insert",
            }}
        ];
        let collection_transfers =
            mongo.get_collection(COLLECTION_FILEHOSTING_FUUIDS)?;
        debug!("Creating missing transfer items START");
        collection_transfers.aggregate(fuuids_pipeline).await?;
        debug!("Creating missing transfer items DONE");
    }

    emit_filehost_transfersupdated_event(outbound).await?;

    debug!("entretien_transfert_fichiers Fin");
    Ok(())
}

pub async fn add_missing_file_transfers<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    session: &mut ClientSession,
    new_claims: Vec<RowFilehostFuuid>
) -> Result<(), CommonError> where M: MongoDaoTyped {
    // Get active filehosts
    let filehosts_active = {
        let collection_filehosts =
            mongo.get_collection_typed::<FilehostServerRow>(COLLECTION_FILEHOSTS)?;
        let filtre = doc!{"sync_active": true, "deleted": false};
        let mut cursor = collection_filehosts.find(filtre).await?;

        let mut filehosts_active = HashSet::new();
        while cursor.advance().await? {
            let row = cursor.deserialize_current()?;
            filehosts_active.insert(row.filehost_id.clone());
        }
        filehosts_active
    };

    for claim in new_claims {
        let mut missing_from = Vec::new();
        // Find all filehost_ids this file is missing from
        match claim.filehost {
            Some(visits) => {
                for filehost in &filehosts_active {
                    if visits.get(filehost).is_none() {
                        missing_from.push(filehost.clone());
                    }
                }
            }
            None => {
                for filehost in &filehosts_active {
                    missing_from.push(filehost.clone());
                }
            }
        };

        let mut transfers_to_add = Vec::new();
        for filehost_id in missing_from {
            debug!("Create missing file transfer for fuuid:{} on filehost_id:{}", claim.fuuid, filehost_id);
            let transfer = FilehostTransfer {
                destination_filehost_id: filehost_id,
                fuuid: claim.fuuid.clone(),
                created: Utc::now(),
                modified: Utc::now(),
                job_picked_up: None,
            };
            transfers_to_add.push(transfer);
        }
        if ! transfers_to_add.is_empty() {
            let collection_transfers =
                mongo.get_collection_typed::<FilehostTransfer>(COLLECTION_FILEHOSTING_TRANSFERS)?;
            collection_transfers.insert_many(transfers_to_add).session(&mut *session).await?;
        }
    }

    // Tell filecontroler that new transfers are available
    emit_filehost_transfersupdated_event(outbound).await?;

    Ok(())
}

/// Regenerates the filehosting_fuuids table from claims and visits when ready.
/// Data is regularly provided by claimants at their discretion. Claims and visits are
/// processed independently.
pub async fn regenerate_filehosting_fuuids<M>(mongo: &M, outbound: &MessageOutboundFacade) -> Result<(), CommonError> where M: MongoDaoTyped {
    merge_filehosting_fuuids_claims(mongo, outbound).await?;
    merge_filehosting_fuuids_visits(mongo).await?;
    Ok(())
}

#[derive(Deserialize)]
struct ClaimVisitsRow {
    #[serde(rename="_id")]
    id: String,
    visits: Option<Vec<RowFilehostFuuid>>
}

/// Regenerates the filehosting_fuuids table from claims and visits
async fn merge_filehosting_fuuids_claims<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
) -> Result<(), CommonError> where M: MongoDaoTyped
{
    // Ensure that all claimer components have sent their data
    let claimer_domains = {
        let mut count = 0;
        let mut claimer_domains = Vec::new();

        let collection_status = mongo.get_collection_typed::<SyncStatusRow>(COLLECTION_FILEHOSTING_SYNC_STATUS)?;
        let claimers_filtre = doc!{"claimer_type": "domain"};
        let mut cursor = collection_status.find(claimers_filtre.clone()).await?;

        while cursor.advance().await? {
            let row = cursor.deserialize_current()?;
            if row.date_ready.is_some() {
                claimer_domains.push(row.claimer);
                count += 1;
            } else {
                info!("merge_filehosting_fuuids_claims At least one previous claimer is not ready, cancel regeneration of claims");
                return Ok(())
            }
        }

        if count == 0 {
            info!("merge_filehosting_fuuids_claims No claimer in status list, cancel regeneration of claims");
            return Ok(())
        }

        // Reset the sync status
        let ops = doc!{"$set": {"date_ready": None::<&str>}};
        collection_status.update_many(claimers_filtre, ops).await?;

        claimer_domains
    };

    // Rename the collections
    // If any WORK tables exist, drop them
    let claims_work_name = format!("{}_WORK", NOM_COLLECTION_FILEHOSTING_CLAIMS);
    mongo.rename_collection(NOM_COLLECTION_FILEHOSTING_CLAIMS, &claims_work_name, true).await?;

    // Prepare the collection indexes by fuuid
    let options_index = IndexOptions { nom_index: Some(String::from("fuuids")), unique: false};
    let champs_index_claims = vec!(ChampIndex { nom_champ: String::from("fuuid"), direction: 1 });
    mongo.create_index(claims_work_name.as_str(), champs_index_claims, Some(options_index)).await?;

    // Merge claims into the filehosting fuuids table
    let claim_pipeline = vec![
        doc!{"$sort": {"fuuid": 1}},
        doc!{"$group": {"_id": "$fuuid", "last_claim_date": {"$max": "$claim_date"}}},
        doc!{"$set": {"fuuid": "$_id"}},  // Copy field claim_date to last_claim_date (merge value)
        doc!{"$unset": ["_id"]},          // Remove _id field for merge
        doc!{"$merge": {
            "into": COLLECTION_FILEHOSTING_FUUIDS,
            "on": "fuuid",
            "whenNotMatched": "insert",
        }}
    ];
    info!("regenerate_filehosting_fuuids Merging claims START");
    let claims_work_collection = mongo.get_collection(&claims_work_name)?;
    claims_work_collection
        .aggregate(claim_pipeline.clone())
        .hint(Hint::Name("fuuids".to_string()))
        .await?;
    info!("regenerate_filehosting_fuuids Merging claims DONE");

    // Respond to claims by domain.
    respond_to_file_claims(mongo, outbound, claims_work_name.as_str(), &claimer_domains).await?;

    // All values processed. Cleanup.
    claims_work_collection.drop().await?;

    Ok(())
}

#[derive(Serialize)]
pub struct RequeteGetVisitesFuuidsResponse {
    pub ok: bool,
    pub visits: Vec<FuuidVisitResponseItem>,
    pub unknown: Vec<String>,
    pub done: Option<bool>
}

async fn respond_to_file_claims<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    work_collection_name: &str,
    claimer_domains: &Vec<String>
) -> Result<(), CommonError> where M: MongoDaoTyped {
    const BATCH_SIZE: usize = 500;
    let claims_work_collection = mongo.get_collection(work_collection_name)?;

    for domain in claimer_domains {
        debug!("response_to_file_claims Sending response to claims from {}", domain);
        let claim_pipeline = vec![
            doc!{"$sort": {"fuuid": 1}},
            doc!{"$match": {"domains": domain}},
            doc!{"$group": {"_id": "$fuuid"}},
            doc!{"$lookup": {
                // Lookup the rep table to get the user ids.
                "from": COLLECTION_FILEHOSTING_FUUIDS,
                "localField": "_id",
                "foreignField": "fuuid",
                "as": "visits",
            }},
        ];

        // Prepare a response to receive the content
        let mut reponse = RequeteGetVisitesFuuidsResponse {
            ok: true,
            visits: Vec::with_capacity(BATCH_SIZE),
            unknown: Vec::new(),
            done: Some(false),
        };
        // Response routing for this domain
        let routage = RoutageMessageAction::builder(domain, "visits", vec![Securite::L3Protege])
            .build();

        let mut cursor = claims_work_collection
            .aggregate(claim_pipeline)
            .hint(Hint::Name("fuuids".to_string()))
            .await?;
        while cursor.advance().await? {
            let row = cursor.deserialize_current()?;
            let row: ClaimVisitsRow = bson::deserialize_from_document(row)?;
            if let Some(visits) = row.visits {
                if let Some(visit) = visits.get(0) {
                    // debug!("Fuuid {} filehost visits: {:?}", row.id, visit.filehost);
                    let mut visit_map = HashMap::new();
                    if let Some(inner) = visit.filehost.as_ref() {
                        for (k,v) in inner {
                            if let Some(visit_date) = v {
                                visit_map.insert(k.to_owned(), visit_date.timestamp());
                            }
                        }
                    };

                    let visit_entry = FuuidVisitResponseItem {fuuid: row.id, visits: visit_map};
                    reponse.visits.push(visit_entry);
                } else {
                    reponse.unknown.push(row.id);
                }
            } else {
                reponse.unknown.push(row.id);
            }

            if reponse.visits.len() >= BATCH_SIZE || reponse.unknown.len() >= BATCH_SIZE {
                // Emit batch to domain
                match outbound.send_command(routage.clone(), &reponse).await {
                    Ok(Some(response)) => {
                        if let (true, value) = response.is_err()? {
                            warn!("Error sending file visits to claimant, response is err: {:?}", value);
                            break;  // Abort for this domain
                        }
                    },  // Ok
                    Err(e) => {
                        warn!("response_to_file_claims Error sending file visits to claimant domain {}: {:?}", domain, e);
                        break;  // Abort for this domain
                    },
                    _ =>  {
                        warn!("response_to_file_claims Error sending file visits to claimant domain {}, wrong response type", domain);
                        break;  // Abort for this domain
                    }
                }

                // Reset response for next batch
                reponse = RequeteGetVisitesFuuidsResponse {
                    ok: true,
                    visits: Vec::with_capacity(BATCH_SIZE),
                    unknown: Vec::new(),
                    done: Some(false),
                }
            }
        }

        reponse.done = Some(true);
        if let Err(e) = outbound.send_command(routage.clone(), &reponse).await {
            warn!("response_to_file_claims Error sending last batch of file visits to claimant domain {}: {:?}", domain, e);
        }
    }
    debug!("response_to_file_claims Sending response to claims - DONE");

    Ok(())
}

async fn merge_filehosting_fuuids_visits<M>(mongo: &M) -> Result<(), CommonError> where M: MongoDaoTyped {
    // Make a list of active fileshosts. Ignore deleted/no sync filehosts.
    let mut active_filehost_ids = HashSet::new();
    let collection_filehosts = mongo.get_collection_typed::<FilehostServerRow>(COLLECTION_FILEHOSTS)?;
    let filtre = doc!{"deleted": false, "sync_active": true};
    let mut cursor = collection_filehosts.find(filtre).await?;
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        active_filehost_ids.insert(row.filehost_id);
    }

    // Ensure that all claimer components have sent their data
    let collection_status = mongo.get_collection_typed::<SyncStatusRow>(COLLECTION_FILEHOSTING_SYNC_STATUS)?;
    let claimers_filtre = doc! {"claimer_type": "filehost"};
    let mut count = 0;
    let mut cursor = collection_status.find(claimers_filtre.clone()).await?;
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        let filehost_id = row.claimer;
        if active_filehost_ids.contains(&filehost_id) {  // Check if the filehost is active
            // if row.date_ready.is_none() {
            //     info!("merge_filehosting_fuuids_visits At least one previous active claimer is not ready, cancel regeneration of visits");
            //     return Ok(())
            // }
            if row.date_ready.is_some() {
                count += 1;
            }
        }
    }

    if count == 0 {
        info!("merge_filehosting_fuuids_visits No claimer in status list, cancel regeneration of visits");
        return Ok(())
    }

    let ops = doc!{"$set": {"date_ready": None::<&str>}};
    collection_status.update_many(claimers_filtre, ops).await?;

    // Rename the collections
    // If any WORK tables exist, drop them
    let visits_work_name = format!("{}_WORK", NOM_COLLECTION_FILEHOSTING_VISITS);
    mongo.rename_collection(NOM_COLLECTION_FILEHOSTING_VISITS, &visits_work_name, true).await?;

    // Prepare the collection indexes by fuuid
    let options_index = IndexOptions { nom_index: Some(String::from("fuuids")), unique: false};
    let champs_index_claims = vec!(ChampIndex { nom_champ: String::from("fuuid"), direction: 1 });
    mongo.create_index(visits_work_name.as_str(), champs_index_claims, Some(options_index)).await?;

    // Merge claims into the filehosting fuuids table
    let visits_pipeline = vec![
        doc!{"$sort": {"fuuid": 1}},

        // Group rows for the same fuuid into a single row with filehost visit times
        doc!{"$addFields": {"obj": {"k": "$filehost_id", "v": "$visit_time"}}},
        doc!{"$group": {"_id": "$fuuid", "items": {"$push": "$obj"}}},
        doc!{"$addFields": {"fuuid": "$_id", "filehost_updated": {"$arrayToObject": "$items"} }},

        // Lookup existing visits to keep information from filehosts not being updated
        doc!{"$lookup": {
            "from": COLLECTION_FILEHOSTING_FUUIDS,
            "localField": "fuuid",
            "foreignField": "fuuid",
            "as": "visits",
        }},
        doc!{"$addFields": {"visit_entry": {"$arrayElemAt": ["$visits", 0]}}},
        doc!{"$addFields": {"filehost": {"$mergeObjects": ["$visit_entry.filehost", "$filehost_updated"]}}},

        // Merge filehost element using the fuuid
        doc!{"$unset": ["_id", "items", "visits", "visit_entry", "filehost_updated"]},
        doc!{"$merge": {
            // "into": NOM_COLLECTION_FILEHOSTING_FUUIDS_WORK,
            "into": COLLECTION_FILEHOSTING_FUUIDS,
            "on": "fuuid",
            "whenNotMatched": "insert",
        }}
    ];
    info!("merge_filehosting_fuuids_visits Merging visits START");
    let visits_work_collection = mongo.get_collection(visits_work_name.as_str())?;
    visits_work_collection
        .aggregate(visits_pipeline.clone())
        .hint(Hint::Name("fuuids".to_string()))
        .await?;
    info!("merge_filehosting_fuuids_visits Merging visits DONE");

    // All values processed
    visits_work_collection.drop().await?;

    Ok(())
}


#[derive(Serialize)]
struct RequestDeleteFiles {
    /// List of fuuids to delete with an optional list of filehost_ids from which the file must be deleted.
    fuuids: HashMap<String, Option<Vec<String>>>,
}

#[derive(Deserialize)]
struct ResponseDeleteFiles {
    ok: Option<bool>,
    err: Option<String>,
    /// Map of deleted fuids with the list of filehost_ids from which the file was
    /// acknownleged as being just deleted or already not present.
    fuuids: Option<HashMap<String, Option<Vec<String>>>>,
}

pub async fn maintain_unclaimed_fuuids<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade
) -> Result<(), CommonError> where M: MongoDaoTyped {
    info!("maintain_unclaimed_fuuids START");

    let collection_fuuids =
        mongo.get_collection_typed::<RowFilehostFuuid>(COLLECTION_FILEHOSTING_FUUIDS)?;

    // Set the unclaim_check timestamp to expired claims
    let now = Utc::now();
    let claim_expired = now - Duration::days(7);
    let filtre = doc!{
        "$or": [
            {"last_claim_date": null},
            {"last_claim_date": {"$lt": &claim_expired}},
        ],
        "unclaim_check": null,
    };
    let ops = doc!{ "$currentDate": {"unclaim_check": true} };
    collection_fuuids.update_many(filtre, ops).await?;

    // Unset the unclaim_check for claims that are current
    let filtre = doc!{
        "last_claim_date": {"$gte": &claim_expired},
        "unclaim_check": {"$exists": true},
    };
    let ops = doc!{ "$unset": {"unclaim_check": true} };
    collection_fuuids.update_many(filtre, ops).await?;

    // Identify unclaim_check that are old enough to get triggered
    let unclaim_ready = now - Duration::days(21);
    // let unclaim_ready = now - Duration::from_secs(120);
    let filtre = doc!{"unclaim_check": {"$lt": &unclaim_ready}};
    let mut cursor = collection_fuuids.find(filtre.clone()).await?;
    while cursor.advance().await? {
        let row = match cursor.deserialize_current() {
            Ok(inner) => inner,
            Err(e) => {
                warn!("Error deserializing collection fuuids entry: {:?}", e);
                continue
            }
        };
        info!("Ready to remove fuuid {} from all filehosts: {:?}", row.fuuid, row.filehost);
        let mut ready_to_delete = false;
        if let Some(visits) = row.filehost {
            if visits.is_empty() {
                // The file is not knwon to be on any filehost. The entry can be deleted.
                ready_to_delete = true;
            } else {
                let present_on_filehosts: Vec<String> = visits.keys().into_iter().map(|s| s.to_string()).collect();
                let mut map = HashMap::new();
                map.insert(row.fuuid.clone(), Some(present_on_filehosts));
                let request = RequestDeleteFiles {
                    fuuids: map,
                };
                let routage = RoutageMessageAction::builder("filecontroler", "deleteFiles", vec![Securite::L1Public])
                    .build();

                match outbound.send_command(routage, &request).await {
                    Ok(Some(response)) => {
                        let response: ResponseDeleteFiles = response.message.deserialize()?;
                        if response.ok == Some(true) {
                            info!("maintain_unclaimed_fuuids File {} deleted from: {:?}", row.fuuid, response.fuuids);
                            let present_on_filehosts: HashSet<&String> = HashSet::from_iter(visits.keys().into_iter());
                            if let Some(fuuids) = response.fuuids {
                                if let Some(Some(filehost_ids)) = fuuids.get(&row.fuuid) {
                                    let confirmed_deleted: HashSet<&String> = HashSet::from_iter(filehost_ids.into_iter());
                                    if confirmed_deleted.is_superset(&present_on_filehosts) {
                                        info!("maintain_unclaimed_fuuids File {} deleted from all known filehosts", row.fuuid);
                                        ready_to_delete = true;
                                    } else {
                                        if ! confirmed_deleted.is_empty() {
                                            // Update the fuuids database with the partial deletion information.
                                            let mut unsets = doc! {};
                                            for filehost_id in confirmed_deleted {
                                                unsets.insert(format!("filehost.{}", filehost_id), true);
                                            }
                                            let filtre = doc! {"fuuid": &row.fuuid};
                                            let ops = doc! {"$unset": unsets};
                                            debug!("maintain_unclaimed_fuuids Unset filtre: {:?}, ops: {:?}", filtre, ops);
                                            collection_fuuids.update_one(filtre, ops).await?;
                                        }
                                    }
                                }
                            }
                        } else {
                            error!("maintain_unclaimed_fuuids Error deleting file {}: {:?}", row.fuuid, response.err);
                        }
                    },
                    Err(e) => {
                        error!("maintain_unclaimed_fuuids Error deleting file: {:?}", e);
                    },
                    _ => {
                        error!("maintain_unclaimed_fuuids Error deleting file, invalid response message type");
                    }
                }
            }
        } else {
            // The file is not known to have ever been present on any filehosts. The entry can be deleted.
            ready_to_delete = true;
        }

        if ready_to_delete {
            info!("Deleting of fuuid {} complete from all filehosts, deleting from collection", row.fuuid);
            let filtre = doc!{"fuuid": &row.fuuid};
            collection_fuuids.delete_one(filtre.clone()).await?;
        }
    }

    info!("maintain_unclaimed_fuuids DONE");
    Ok(())
}


#[derive(Deserialize)]
struct ObjectToArrayKeyStringValueDate {
    k: String,
    #[allow(dead_code)]
    #[serde(default, with = "option_chrono_04_datetime")]
    v: Option<DateTime<Utc>>
}

#[derive(Deserialize)]
struct FilehostFuuidRow {
    fuuid: String,
    filehost_elem: ObjectToArrayKeyStringValueDate
}

/// Remove all filehost visit dates that are expired. Consider files on those filehosts as no
/// longer available.
pub async fn maintain_expired_filehost_visits<M>(
    mongo: &M
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let expired_visit = Utc::now() - Duration::days(3);
    // let expired_visit = Utc::now() - Duration::from_secs(60);

    let pipeline = vec![
        doc!{"$addFields": {"filehost_elem": {"$objectToArray": "$filehost"}}},
        doc!{"$unwind": {"path": "$filehost_elem"}},
        doc!{"$match": {"filehost_elem.v": {"$lt": expired_visit}}},
    ];
    let collection = mongo.get_collection(COLLECTION_FILEHOSTING_FUUIDS)?;
    let mut cursor = collection.aggregate(pipeline).await?;
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        let row: FilehostFuuidRow = bson::deserialize_from_document(row)?;

        let filtre = doc!{"fuuid": row.fuuid};
        let ops = doc!{
            "$unset": {format!("filehost.{}", row.filehost_elem.k): true},
        };
        collection.update_one(filtre, ops).await?;
    }

    Ok(())
}
