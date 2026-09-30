use crate::external::mongo::*;
use crate::external::mq::*;
use crate::models::*;
use millegrilles_common_rust::bson;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::serde::{Deserialize, Serialize};
use millegrilles_common_rust::tracing::{debug, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use std::collections::HashSet;

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
