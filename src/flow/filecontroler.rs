use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::mongo_dao::{MongoDao, MongoDaoTyped};
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::mongodb::ClientSession;
use millegrilles_common_rust::tracing::info;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::serde::{Serialize, Deserialize};
use crate::external::mongo::{FIELD_CONFIGURATION_FILECONTROLER_PRIMARY, NOM_COLLECTION_FILEHOSTINGCONFIGURATION};
use crate::external::mq::*;
use crate::models::{FilehostingCongurationRow, RowFilehostFuuid};

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
        EVENEMENT_FILEHOST_USAGE => filehost_usage(mongo, outbound, wrapper).await,
        EVENEMENT_FILEHOST_NEWFUUID => filehost_newfuuid(mongo, outbound, wrapper).await,
        _ => {
            info!("Unknown action {} for process_command, skipping", action);
            Ok(())
        }
    }

}

async fn filehost_usage<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!()
}

async fn filehost_newfuuid<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    todo!()
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
