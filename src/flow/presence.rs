use crate::external::mongo::*;
use crate::external::mq::*;
use crate::models::*;
use millegrilles_common_rust::{bson, serde_json};
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDao;
use millegrilles_common_rust::serde::Deserialize;
use millegrilles_common_rust::tracing::{debug, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use std::collections::HashMap;

pub async fn process_presence_event(
    mongo: &dyn MongoDao,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return Err(CommonError::Str("No action provided in event message"))
    };
    match action {
        EVENEMENT_PRESENCE_DOMAINE => event_presence_domain(mongo, wrapper).await,
        EVENEMENT_PRESENCE_INSTANCE_V2 => event_presence_instance(mongo, wrapper).await,
        EVENEMENT_PRESENCE_INSTANCE_APPLICATIONS_V2 => event_presence_applications(mongo, wrapper).await,
        _ => {
            info!("Unknown action {} for process_command, skipping", action);
            Ok(())
        }
    }
}

async fn event_presence_domain(
    mongo: &dyn MongoDao,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let event: PresenceDomaine = wrapper.message.deserialize()?;

    let domain = match event.domaine.as_ref() {
        Some(d) => d,
        None => return Ok(())  // nothing do to
    };

    let certificate = wrapper.certificate.as_ref();
    if ! certificate.verifier_domaines(vec![domain.to_owned()])? {
        return Err(CommonError::String(format!("core_topologie.traiter_presence_domaine Erreur domaine message ({}) mismatch certificat ", domain)))
    }
    let instance_id = certificate.get_common_name()?;
    let filtre = doc! {"domaine": domain};
    let mut set_doc = doc! {
        "instance_id": instance_id,
    };
    if let Some(reclame_fuuids) = event.reclame_fuuids {
        set_doc.insert("reclame_fuuids", reclame_fuuids);
    }
    let ops = doc! {
        "$set": set_doc,
        "$setOnInsert": {
            "domaine": domain,
            CHAMP_CREATION: Utc::now(),
            "dirty": true
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    debug!("Document instance a sauvegarder : {:?}", ops);

    let collection = mongo.get_collection(COLLECTION_DOMAINS)?;
    if let Err(e) = collection.update_one(filtre, ops).upsert(true).await {
        Err(CommonError::String(format!("Error with update_one on domaine presence event update : {:?}", e)))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
struct PresenceInstanceEventV2 {
    system_state: SystemState,
    securite: Option<String>,
    certissuer: Option<CertissuerState>,
}

async fn event_presence_instance(
    mongo: &dyn MongoDao,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    // debug!("event_presence_instance\n{}", serde_json::to_string(&wrapper.message)?);
    let event: PresenceInstanceEventV2 = wrapper.message.deserialize()?;
    if ! wrapper.certificate.verifier_roles(vec![RolesCertificats::Instance])? {
        warn!("process_presence_instance_v2 Rejecting message not from an instance manager");
        return Ok(())
    }

    let instance_id = wrapper.certificate.get_common_name()?;

    let mut securite = match wrapper.certificate.extensions() {
        Ok(e) => {
            match e.exchanges {
                Some(e) => match e.get(0) {
                    Some(e) => e.clone(),
                    None => {
                        warn!("process_presence_instance_v2 Rejecting message from instance with no configured exchanges (empty list) in certificate");
                        return Ok(());
                    }
                },
                None => {
                    warn!("process_presence_instance_v2 Rejecting message from instance with no configured exchanges in certificate");
                    return Ok(());
                }
            }
        }
        Err(e) => {
            warn!("process_presence_instance_v2 Rejecting message from instance with no configured extensions in certificate (error: {})", e);
            return Ok(());
        }
    };

    if let Some(event_securite) = event.securite {
        if event_securite.as_str() == Securite::L4Secure.get_str() && securite.as_str() == Securite::L3Protege.get_str() {
            // Special case for 4.secure type manager, its certificate is still 3.protege.
            // Bump reported security up to 4.secure
            securite = event_securite;
        }
    }

    let filter = doc! {"instance_id": instance_id.clone()};
    let row_content = ManagerStatusV2 {
        instance_id,
        system_state: event.system_state,
        securite,
        certissuer: event.certissuer,
        supprime: false,
        timestamp: wrapper.message.estampille,
    };

    // Override the content of the table with the received event information
    let set_ops = bson::ser::serialize_to_document(&row_content)?;

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {
            CHAMP_CREATION: &row_content.timestamp,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };

    let collection = mongo.get_collection(COLLECTION_INSTANCE_STATUS_V2)?;
    collection.update_one(filter, ops).upsert(true).await?;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct InstalledApplicationV2 {
    applications: HashMap<String, ApplicationInfo>
}

async fn event_presence_applications(
    mongo: &dyn MongoDao,
    wrapper: MessageValidated,
) -> Result<(), CommonError> {
    let event: InstalledApplicationV2 = wrapper.message.deserialize()?;

    if ! wrapper.certificate.verifier_roles(vec![RolesCertificats::Instance])? {
        info!("process_presence_instance Rejecting message not from an instance");
        return Ok(())
    }

    let instance_id = wrapper.certificate.get_common_name()?;

    let securite = match wrapper.certificate.extensions() {
        Ok(e) => {
            match e.exchanges {
                Some(e) => match e.get(0) {
                    Some(e) => e.clone(),
                    None => {
                        warn!("process_presence_instance_v2 Rejecting message from instance with no configured exchanges (empty list) in certificate");
                        return Ok(());
                    }
                },
                None => {
                    warn!("process_presence_instance_v2 Rejecting message from instance with no configured exchanges in certificate");
                    return Ok(());
                }
            }
        }
        Err(e) => {
            warn!("process_presence_instance_v2 Rejecting message from instance with no configured extensions in certificate (error: {})", e);
            return Ok(());
        }
    };

    let filter = doc! {"instance_id": instance_id.clone()};
    let collection = mongo.get_collection(COLLECTION_CONFIGURED_APPLICATIONS_V2)?;
    let row_content = ApplicationStatusV2 {
        instance_id,
        applications: event.applications,
        securite,
        supprime: false,
        timestamp: wrapper.message.estampille,
    };

    // Override the content of the table with the received event information
    let set_ops = bson::serialize_to_document(&row_content)?;

    let ops = doc! {
        "$set": set_ops,
        "$setOnInsert": {
            CHAMP_CREATION: &row_content.timestamp,
        },
        "$currentDate": {CHAMP_MODIFICATION: true}
    };
    collection.update_one(filter, ops).upsert(true).await?;

    Ok(())
}
