use crate::external::mongo::*;
use crate::external::mq::*;
use crate::models::*;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{Duration, Utc};
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tracing::{debug, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use std::collections::{HashMap, HashSet};
use millegrilles_common_rust::bson::oid::ObjectId;
use millegrilles_common_rust::mongodb::ClientSession;

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
    let collection = mongo.get_collection(NOM_COLLECTION_FILEHOSTS)?;
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
    let collection = mongo.get_collection(NOM_COLLECTION_FILEHOSTING_FUUIDS)?;
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
    let collection_transfers = mongo.get_collection(NOM_COLLECTION_FILEHOSTING_TRANSFERS)?;
    collection_transfers.delete_one(filtre_transfer).await?;

    // Creer les transferts vers filehosts sans ce fuuid

    // Recuperer liste de filehost_ids actifs
    let collection_filehosts = mongo.get_collection_typed::<RowFilehostId>(NOM_COLLECTION_FILEHOSTS)?;
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

    let collection_fuuids = mongo.get_collection_typed::<RowFilehostFuuid>(NOM_COLLECTION_FILEHOSTING_FUUIDS)?;
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
#[allow(dead_code)]
struct FuuidFilehostRow {
    #[serde(rename="_id")]
    id: ObjectId,
    fuuid: String,
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
            mongo.get_collection_typed::<FilehostServerRow>(NOM_COLLECTION_FILEHOSTS)?;
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
        mongo.get_collection_typed::<FilehostTransfer>(NOM_COLLECTION_FILEHOSTING_TRANSFERS)?;
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
            "from": NOM_COLLECTION_FILEHOSTING_FUUIDS,
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
                "into": NOM_COLLECTION_FILEHOSTING_TRANSFERS,
                "on": ["destination_filehost_id", "fuuid"],
                "whenMatched": "keepExisting",
                "whenNotMatched": "insert",
            }}
        ];
        let collection_transfers =
            mongo.get_collection(NOM_COLLECTION_FILEHOSTING_FUUIDS)?;
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
            mongo.get_collection_typed::<FilehostServerRow>(NOM_COLLECTION_FILEHOSTS)?;
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
                mongo.get_collection_typed::<FilehostTransfer>(NOM_COLLECTION_FILEHOSTING_TRANSFERS)?;
            collection_transfers.insert_many(transfers_to_add).session(&mut *session).await?;
        }
    }

    // Tell filecontroler that new transfers are available
    emit_filehost_transfersupdated_event(outbound).await?;

    Ok(())
}
