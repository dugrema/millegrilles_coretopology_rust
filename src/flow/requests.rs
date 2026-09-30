use std::collections::HashMap;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use crate::external::mq::*;
use crate::external::mongo::*;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::tracing::{info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::serde::{Serialize, Deserialize};
use millegrilles_common_rust::tokio_stream::StreamExt;
use crate::models::{ApplicationStatusV2, DomainItemResponse, DomainRow, WebItem};

pub async fn process_request<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where
    M: MongoDaoTyped,
{
    let action = match wrapper.get_routing_action() {
        Some(action) => action,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err("No action provided in transaction")).await
    };
    match action {
        REQUEST_DOMAIN_LIST => request_domain_list(mongo, outbound, wrapper).await,
        REQUEST_SERVER_INSTANCES_V2 => request_deployed_userapps_v2(mongo, outbound, wrapper).await,
        REQUEST_SERVER_INSTANCE_APPLICATIONS => todo!(),
        REQUEST_SERVER_INSTANCE_CONFIGURATION => todo!(),
        REQUETE_GET_CLEID_BACKUP_DOMAINE => todo!(),
        REQUETE_CONFIGURATION_FILEHOSTS => todo!(),
        REQUEST_FILEHOSTS_FOR_FUUIDS => todo!(),
        REQUETE_USERAPPS_DEPLOYEES_V2 => todo!(),
        REQUETE_FICHE_MILLEGRILLE => todo!(),
        REQUETE_GET_FILEHOSTS => todo!(),
        REQUETE_GET_FILECONTROLERS => todo!(),
        REQUETE_GET_FILEHOST_FOR_INSTANCE => todo!(),
        REQUETE_GET_FILEHOST_FOR_EXTERNAL => todo!(),
        REQUETE_GET_DOMAINS_BACKUP_VERSIONS => todo!(),

        _ => {
            info!("Unknown action {} for process_requests, skipping", action);
            Ok(())
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequestDomainList {
    reclame_fuuids: Option<bool>,
}

#[derive(Serialize)]
struct ResponseDomainList {
    ok: bool,
    resultats: Vec<DomainItemResponse>,
}

async fn request_domain_list<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    if !wrapper.certificate.verifier_exchanges(vec!(Securite::L2Prive, Securite::L3Protege, Securite::L4Secure))? {
        if wrapper.certificate.get_user_id()?.is_some() && !wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(401,"Access denied")).await;
        }
    }

    let request: RequestDomainList = wrapper.message.deserialize()?;

    let collection = mongo.get_collection_typed::<DomainRow>(COLLECTION_DOMAINS)?;
    let mut filter = doc!{};
    if request.reclame_fuuids.is_some() {
        filter.insert("reclame_fuuids", request.reclame_fuuids);
    }

    let mut domain_list: Vec<DomainItemResponse> = vec![];
    let mut cursor = collection.find(filter).await?;
    while let Some(row) = cursor.next().await {
        match row {
            Ok(document) => domain_list.push(document.into()),
            Err(err) => {
                warn!("Error parsing domain from collection, ignoring: {:?}", err);
            }
        }
    }

    let response = ResponseDomainList { ok: true, resultats: domain_list };
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Serialize)]
struct ResponseDeployedApplicationsV2 {
    ok: bool,
    results: Vec<ApplicationStatusV2>,
}

async fn request_deployed_userapps_v2<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let certificate = wrapper.certificate.as_ref();
    let user_name = certificate.get_common_name()?;
    let extensions = certificate.extensions()?;
    let exchanges = extensions.exchanges.as_ref();

    let is_admin = if certificate.verifier_exchanges(vec![Securite::L3Protege])? {
        true
    } else if certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        true
    } else if certificate.verifier_exchanges(vec![Securite::L2Prive])? {
        false
    } else if certificate.verifier_roles(vec![RolesCertificats::ComptePrive])? {
        false
    } else {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Acces refuse")).await
    };

    let collection = mongo.get_collection_typed::<ApplicationStatusV2>(COLLECTION_CONFIGURED_APPLICATIONS_V2)?;
    let mut application_list = vec![];
    let mut cursor = collection.find(doc!{"supprime": false}).await?;
    while let Some(application_row) = cursor.next().await {
        let mut application_row = match application_row {
            Ok(application_row) => application_row,
            Err(err) => {
                warn!("Error parsing application from collection, ignoring: {:?}", err);
                continue
            }
        };
        filter_applications_by_access(&mut application_row, is_admin)?;
        if ! application_row.applications.is_empty() {
            application_list.push(application_row);
        }
    }

    let response = ResponseDeployedApplicationsV2 { ok: true, results: application_list };
    outbound.respond(wrapper.delivery_info, response).await
}

fn filter_applications_by_access(row: &mut ApplicationStatusV2, is_admin: bool) -> Result<(), CommonError> {
    let mut new_app_map = HashMap::new();
    for (nom_app, mut value) in row.applications.drain() {
        let web = match value.web {
            Some(web) => web,
            None => continue,  // No web component, skip
        };
        if ! is_admin {
            let web: Vec<WebItem> = web.into_iter().filter(|w| ! w.admin.unwrap_or(false)).collect();
            value.web = Some(web);
        } else {
            // Admin, keep everyting
            value.web = Some(web);  // Put back as is
        }
        new_app_map.insert(nom_app, value);
    }

    // Re-assign filtered map
    row.applications = new_app_map;

    Ok(())
}
