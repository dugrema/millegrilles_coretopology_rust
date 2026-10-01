use std::collections::HashMap;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use crate::external::mq::*;
use crate::external::mongo::*;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::tracing::{debug, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::models::ErrorMessage;
use millegrilles_common_rust::serde::{Serialize, Deserialize};
use millegrilles_common_rust::{millegrilles_cryptographie, serde_json};
use millegrilles_common_rust::generateur_messages::{RoutageMessageAction, RoutageMessageReponse};
use millegrilles_common_rust::tokio_stream::StreamExt;
use millegrilles_common_rust::v3::{ChiffrageService, ConfigService, FormatService, MessagingService};
use crate::constants::DOMAIN_NAME;
use crate::fiche::generer_contenu_fiche_publique;
use crate::models::*;

pub async fn process_request<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    config: &dyn ConfigService,
    chiffrage: &dyn ChiffrageService,
    format: &dyn FormatService,
    messaging: &dyn MessagingService,
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
        REQUEST_SERVER_INSTANCES_V2 => request_server_instances(mongo, outbound, wrapper).await,
        REQUEST_SERVER_INSTANCE_CONFIGURATION => request_server_configuration(mongo, outbound, wrapper).await,
        REQUETE_GET_CLEID_BACKUP_DOMAINE => request_get_domain_backup_keyid(mongo, outbound, wrapper).await,
        REQUETE_CONFIGURATION_FILEHOSTS => request_filehost_configuration(mongo, outbound, wrapper).await,
        REQUEST_FILEHOSTS_FOR_FUUIDS => request_filehosts_for_fuuid(mongo, outbound, wrapper).await,
        REQUETE_USERAPPS_DEPLOYEES_V2 => request_deployed_userapps_v2(mongo, outbound, wrapper).await,
        REQUETE_FICHE_MILLEGRILLE => request_millegrille_fiche(mongo, config, chiffrage, format, messaging, outbound, wrapper).await,
        REQUETE_GET_FILEHOSTS => request_filehosts(mongo, outbound, wrapper).await,
        REQUETE_GET_FILECONTROLERS => request_filecontrolers(mongo, outbound, wrapper).await,
        REQUETE_GET_FILEHOST_FOR_INSTANCE => request_filehost_for_instance(mongo, outbound, wrapper).await,
        REQUETE_GET_DOMAINS_BACKUP_VERSIONS => request_domains_backup_versions(mongo, outbound, wrapper).await,

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
    results: Vec<ApplicationStatusV2Response>,
}

async fn request_deployed_userapps_v2<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let certificate = wrapper.certificate.as_ref();
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

    let collection = mongo.get_collection_typed::<ApplicationStatusV2Row>(COLLECTION_CONFIGURED_APPLICATIONS_V2)?;
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

    let response = ResponseDeployedApplicationsV2 {
        ok: true,
        results: application_list.into_iter().map(|a| a.into()).collect()
    };
    outbound.respond(wrapper.delivery_info, response).await
}

fn filter_applications_by_access(row: &mut ApplicationStatusV2Row, is_admin: bool) -> Result<(), CommonError> {
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

#[derive(Deserialize)]
struct RequestServerInstanceConfiguration { instance_id: String }

#[derive(Serialize)]
struct ResponseServerInstanceConfiguration {
    ok: bool,
    instance_id: String,
    configuration: HashMap<String, String>,
}

async fn request_server_configuration<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    if wrapper.certificate.verifier_exchanges(vec!(Securite::L3Protege))? {
        // Ok
    } else if wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access refused")).await
    }

    let request: RequestServerInstanceConfiguration = wrapper.message.deserialize()?;

    let collection = mongo.get_collection_typed::<ServerInstanceConfigurationRow>(COLLECTION_INSTANCE_CONFIGURATION)?;

    let filtre = doc!{ "instance_id": &request.instance_id };
    let mut cursor = collection.find(filtre).await?;
    let mut configuration_items = HashMap::new();
    while let Some(row) = cursor.next().await {
        let row = row?;
        configuration_items.insert(row.name, row.value);
    }

    let response = ResponseServerInstanceConfiguration {
        ok: true,
        instance_id: request.instance_id,
        configuration: configuration_items
    };
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Deserialize)]
struct RequeteGetCleidBackupDomaine {
    domaine: String,
}

#[derive(Serialize)]
struct ResponseGetCleidBackupDomaine {
    ok: bool,
    cle_id: String,
}

async fn request_get_domain_backup_keyid<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let requete: RequeteGetCleidBackupDomaine = wrapper.message.deserialize()?;
    let domain = requete.domaine;

    if !wrapper.certificate.verifier_exchanges(vec![Securite::L3Protege])? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "The process needs at least security level 3.protege")).await
    } else if !wrapper.certificate.verifier_domaines(vec![domain.clone()])? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "The process to have a certificate of the same domain as requested")).await
    }

    let collection = mongo.get_collection_typed::<DomainRow>(COLLECTION_DOMAINS)?;
    let domain_row = match collection.find_one(doc!{"domaine": &domain}).await? {
        Some(domain_row) => domain_row,
        None => return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "Unknown domain")).await
    };

    let cle_id = match domain_row.cle_id_backup {
        Some(cle_id_backup) => cle_id_backup,
        None => {
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "No backup key for domain")).await
        }
    };

    let response = ResponseGetCleidBackupDomaine { ok: true, cle_id };
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Serialize)]
struct ResponseConfigurationFilehosts {
    ok: bool,
    configuration: HashMap<String, String>,
}

async fn request_filehost_configuration<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    if !wrapper.certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    let collection_config = mongo.get_collection_typed::<FilehostingCongurationRow>(COLLECTION_FILEHOSTINGCONFIGURATION)?;
    let mut curseur = collection_config.find(doc!{}).await?;

    let mut configuration = HashMap::new();
    while let Some(row) =curseur.next().await {
        let row = row?;
        configuration.insert(row.name, row.value);
    }

    let response = ResponseConfigurationFilehosts { ok: true, configuration };
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Deserialize)]
struct RequestFilehostsForFuuids { fuuids: Vec<String> }

#[derive(Serialize)]
struct ResponseFilehostsForFuuids { fuuids: Vec<FuuidVisitResponseItem> }

async fn request_filehosts_for_fuuid<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    if wrapper.certificate.verifier_exchanges(vec!(Securite::L3Protege))? {
        // Ok
    } else {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    let request: RequestFilehostsForFuuids = wrapper.message.deserialize()?;
    let collection =
        mongo.get_collection_typed::<RowFilehostFuuid>(COLLECTION_FILEHOSTING_FUUIDS)?;
    let filtre = doc!{"fuuid": {"$in": &request.fuuids}};
    let mut cursor = collection.find(filtre).await?;
    let mut response_list = Vec::new();
    while let Some(row) = cursor.next().await {
        let row = row?;
        if row.filehost.is_some() {
            let result: FuuidVisitResponseItem = row.into();
            response_list.push(result);
        }
    }

    let response = ResponseFilehostsForFuuids { fuuids: response_list };
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Clone, Deserialize)]
struct MessageInstanceId {
    instance_id: Option<String>
}

#[derive(Serialize)]
struct ResponseServerInstancesV2 {
    ok: bool,
    results: Vec<ManagerStatusV2Response>,
}


async fn request_server_instances<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let certificate = wrapper.certificate.as_ref();
    if certificate.verifier_exchanges(vec!(Securite::L3Protege))? {
        // Ok
    } else if certificate.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    }

    let message_instance_id: MessageInstanceId = wrapper.message.deserialize()?;
    let filtre = match message_instance_id.instance_id.as_ref() {
        Some(inner) => doc!{"instance_id": inner},
        None => doc!{}
    };
    let collection = mongo.get_collection_typed::<ManagerStatusV2Row>(COLLECTION_INSTANCE_STATUS_V2)?;
    let mut results = vec![];
    let mut cursor = collection.find(filtre).await?;
    while let Some(row) = cursor.next().await {
        results.push(row?);
    }

    let response = ResponseServerInstancesV2 {
        ok: true,
        results: results.into_iter().map(|v| v.into()).collect()
    };
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteFicheMillegrille {
    pub idmg: Option<String>,
}

async fn request_millegrille_fiche<M>(
    mongo: &M,
    config: &dyn ConfigService,
    chiffrage: &dyn ChiffrageService,
    format: &dyn FormatService,
    messaging: &dyn MessagingService,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let requete: RequeteFicheMillegrille = wrapper.message.deserialize()?;
    let idmg = config.get_configuration_pki().get_enveloppe_privee().enveloppe_pub.idmg()?;
    if requete.idmg.is_some() && requete.idmg.as_ref() != Some(&idmg) {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(400, "Only local millegrille is supported")).await
    }

    // Todo: repondre avec message sous forme de commande, Action=fichePublique
    let response = generer_contenu_fiche_publique(mongo, config, chiffrage).await?;

    let routing = RoutageMessageAction::builder(
        DOMAIN_NAME,
        "fichePublique",
        vec![]
    ).build();
    let (signed_command, _id) = format.build_action_message(
        millegrilles_cryptographie::messages_structs::MessageKind::Commande,
        &routing,
        serde_json::to_value(response)?
    )?;
    let basic_properties = &wrapper.delivery_info.properties;
    let (reply_to, correlation_id) = match (basic_properties.reply_to(), basic_properties.correlation_id()) {
        (Some(reply_to), Some(correlation_id)) => (reply_to.to_string(), correlation_id.to_string()),
        _ => return Err(CommonError::Str("Missing reply_to/correlation_id properties on fiche request"))
    };
    let response_routing = RoutageMessageReponse::new(reply_to, correlation_id);
    messaging.respond(signed_command, response_routing).await?;

    Ok(())
}

#[derive(Deserialize)]
struct RequestFilehostList {
    filehost_id: Option<String>,
}

#[derive(Serialize)]
struct ResponseFilehostList {
    ok: bool,
    list: Vec<RequeteFilehostItem>,
}

async fn request_filehosts<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let requete: RequestFilehostList = wrapper.message.deserialize()?;
    let collection = mongo.get_collection_typed::<FilehostServerRow>(COLLECTION_FILEHOSTS)?;

    let filtre = match requete.filehost_id {
        Some(inner) => doc!{"filehost_id": inner},
        None => doc!{"deleted": false}
    };

    let mut cursor = collection.find(filtre).await?;
    let mut list = Vec::new();
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        let item: RequeteFilehostItem = row.into();
        list.push(item);
    }

    let response = ResponseFilehostList { ok: true, list };
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Deserialize)]
struct RequestFilecontrolersList {
    instance_id: Option<String>,
}

#[derive(Serialize)]
struct RequeteFilecontrolersListResponse {
    ok: bool,
    list: Vec<RequeteFilehostItem>,
    filecontroler_primary: Option<String>,
}

async fn request_filecontrolers<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let requete: RequestFilecontrolersList = wrapper.message.deserialize()?;
    let collection = mongo.get_collection_typed::<FilehostServerRow>(COLLECTION_FILECONTROLERS)?;
    let filtre = match requete.instance_id {
        Some(inner) => doc!{"instance_id": inner},
        None => doc!{"deleted": false}
    };
    let mut list = Vec::new();
    let mut cursor = collection.find(filtre).await?;
    while cursor.advance().await? {
        let row = cursor.deserialize_current()?;
        let item: RequeteFilehostItem = row.into();
        list.push(item);
    }
    let collection_config = mongo.get_collection_typed::<FilehostingCongurationRow>(COLLECTION_FILEHOSTINGCONFIGURATION)?;
    let filtre = doc!{"name": FIELD_CONFIGURATION_FILECONTROLER_PRIMARY};
    let filecontroler_primary = match collection_config.find_one(filtre).await? {
        Some(inner) => Some(inner.value),
        None => None
    };

    let response = RequeteFilecontrolersListResponse { ok: true, list, filecontroler_primary };
    outbound.respond(wrapper.delivery_info, response).await
}

#[derive(Serialize, Deserialize)]
struct FilehostForInstanceRequest {
    instance_id: Option<String>,
    filehost_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RequestFilehostForInstanceResponse {
    ok: bool,
    filehost: RequeteFilehostItem,
}

async fn request_filehost_for_instance<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let requete: FilehostForInstanceRequest = wrapper.message.deserialize()?;

    let certificat = wrapper.certificate.as_ref();
    let certificate_instance_id = if certificat.verifier_exchanges(vec![Securite::L1Public, Securite::L2Prive, Securite::L3Protege, Securite::L4Secure])? {
        // Back-end component, use common name (instance_id)
        certificat.get_common_name()?
    } else {
        return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
    };

    let instance_id = requete.instance_id.unwrap_or_else(|| certificate_instance_id);

    let collection_filehosts = mongo.get_collection_typed::<FilehostServerRow>(COLLECTION_FILEHOSTS)?;

    // Identify the filehost_id from the instance_id if possible
    let filehost_id = match requete.filehost_id {
        Some(inner) => Some(inner),  // Filehost provided
        None => {
            // Check if configuration overrides with filehost_id
            let collection_instances =
                mongo.get_collection_typed::<ServerInstanceConfigurationRow>(COLLECTION_INSTANCE_CONFIGURATION)?;
            let filtre = doc! {"instance_id": &instance_id, "name": "filehost_id"};
            debug!("Filehost loading filter (from instance_id): {:?}", filtre);
            match collection_instances.find_one(filtre).await? {
                Some(inner) => Some(inner.value),
                None => {
                    // Check if there is a filehost directly on this instance
                    let filtre_filehosts = doc! {"instance_id": &instance_id, "deleted": false};
                    debug!("Filehost loading from configured id: {:?}", filtre_filehosts);
                    match collection_filehosts.find_one(filtre_filehosts).await? {
                        Some(inner) => {
                            return outbound.respond(wrapper.delivery_info, RequestFilehostForInstanceResponse { ok: true, filehost: inner.into() }).await
                        },
                        None => {
                            // Load the default filehost_id
                            let collection_configuration = mongo.get_collection_typed::<FilehostingCongurationRow>(COLLECTION_FILEHOSTINGCONFIGURATION)?;
                            let filtre = doc!{"name": FIELD_CONFIGURATION_FILEHOST_DEFAULT};
                            match collection_configuration.find_one(filtre).await? {
                                Some(inner) => Some(inner.value),
                                None => None
                            }
                        }
                    }
                }
            }
        }
    };

    let filtre = match filehost_id.as_ref() {
        Some(inner) => doc!{"filehost_id": inner, "deleted": false},
        None => doc!{"deleted": false, "external_url": {"$exists": true}}  // Pick random with external_url if any available
    };

    debug!("Filehost loading filter: {:?}", filtre);
    match collection_filehosts.find_one(filtre).await? {
        Some(inner) => {
            let filehost: RequeteFilehostItem = inner.into();
            outbound.respond(wrapper.delivery_info, RequestFilehostForInstanceResponse { ok: true, filehost }).await
        }
        None => {
            outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(404, "No filehost available")).await
        }
    }
}

#[derive(Serialize)]
struct RequestDomainsBackupVersionItem {
    domain: String,
    version: Option<String>,
}

#[derive(Serialize)]
struct ResponseDomainsBackupVersion {
    ok: bool,
    domains: Vec<RequestDomainsBackupVersionItem>
}

async fn request_domains_backup_versions<M>(
    mongo: &M,
    outbound: &MessageOutboundFacade,
    wrapper: MessageValidated,
) -> Result<(), CommonError> where M: MongoDaoTyped {
    let certificat = wrapper.certificate.as_ref();
    if certificat.verifier_delegation_globale(DELEGATION_GLOBALE_PROPRIETAIRE)? {
        // Ok
    } else {
        if !certificat.verifier_exchanges(vec![Securite::L1Public])? {
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
        }
        if !certificat.verifier_roles_string(vec!["filecontroler".to_string()])? {
            return outbound.respond(wrapper.delivery_info, ErrorMessage::err_code(403, "Access denied")).await
        }
    }

    let collection = mongo.get_collection_typed::<DomainRow>(COLLECTION_DOMAINS)?;
    let mut cursor = collection.find(doc!{}).await?;
    let mut list = Vec::new();
    while let Some(row) = cursor.next().await {
        let row = row?;
        list.push(RequestDomainsBackupVersionItem {domain: row.domaine, version: row.backup_version});
    }

    let response = ResponseDomainsBackupVersion {ok: true, domains: list};
    outbound.respond(wrapper.delivery_info, response).await
}
