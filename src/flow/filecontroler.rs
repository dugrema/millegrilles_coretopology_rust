use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::tracing::info;
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use crate::external::mq::*;

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
