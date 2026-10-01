use crate::external::mongo::*;
use crate::models::*;
use millegrilles_common_rust::bson::doc;
use millegrilles_common_rust::chrono::Utc;
use millegrilles_common_rust::constantes::*;
use millegrilles_common_rust::error::Error;
use millegrilles_common_rust::fiche_systeme::{ApplicationsV2, FichePublique, InformationApplicationInstance, InformationInstance};
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::serde_json;
use millegrilles_common_rust::tracing::debug;
use millegrilles_common_rust::v3::{ChiffrageService, ConfigService};
use std::collections::HashMap;
use std::time::Duration;
use millegrilles_common_rust::generateur_messages::RoutageMessageAction;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use crate::constants::DOMAIN_NAME;
use crate::external::mq::*;

pub async fn produire_fiche_publique<M>(
    mongo: &M,
    config: &dyn ConfigService,
    chiffrage: &dyn ChiffrageService,
    outbound: &MessageOutboundFacade,
) -> Result<(), Error> where M: MongoDaoTyped {
    debug!("produire_fiche_publique");

    let fiche = generer_contenu_fiche_publique(mongo, config, chiffrage).await?;

    let routage = RoutageMessageAction::builder(
        DOMAIN_NAME, EVENEMENT_FICHE_PUBLIQUE, vec![Securite::L1Public])
        .ajouter_ca(true)
        .build();

    outbound.emit_event(routage, &fiche).await?;

    Ok(())
}

pub async fn generer_contenu_fiche_publique<M>(mongo: &M, config: &dyn ConfigService, chiffrage: &dyn ChiffrageService) -> Result<FichePublique, Error>
where
    M: MongoDaoTyped,
{
    // Extraire chaines pem de certificats de chiffrage
    let chiffrage_enveloppes = chiffrage.get_encryption_publickeys();
    let mut chiffrage = Vec::new();
    for cert in chiffrage_enveloppes {
        let chaine_pem = cert.chaine_pem()?;
        chiffrage.push(chaine_pem)
    }

    let default_map_ports = {
        let mut map_ports: HashMap<String, u16> = HashMap::new();
        map_ports.insert("http".to_string(), 80);
        map_ports.insert("https".to_string(), 443);
        map_ports.insert("wss".to_string(), 443);
        map_ports.insert("https_mtls".to_string(), 444);
        map_ports.insert("wss_mtls".to_string(), 444);
        map_ports
    };

    let presence_expiree = Utc::now() - Duration::from_secs(3600);

    // Fetch and Map Instances (ManagerStatusV2)
    let instance_collection = mongo.get_collection_typed::<ManagerStatusV2Row>(COLLECTION_INSTANCE_STATUS_V2)?;
    let instance_filter = doc!{
        "securite": {"$ne": Securite::L4Secure.get_str()},
        CHAMP_MODIFICATION: {"$gte": presence_expiree},
        "supprime": false,
    };
    let mut instance_cursor = instance_collection.find(instance_filter).await?;

    let instances = {
        let mut instances: HashMap<String, InformationInstance> = HashMap::new();
        while instance_cursor.advance().await? {
            let status = instance_cursor.deserialize_current()?;

            // Done in filter
            // if status.supprime || status.securite == "4.secure" {
            //     continue;
            // }

            // In the DB, timestamp is a string so we test here. Also, the CHAMP_MODICIATION may be
            // recent but the timestamp is about when the manager produced the last update.
            if status.timestamp < presence_expiree {
                continue;
            }

            let (hostname, ports) = match status.system_state.host {
                Some(host) => (host.hostname.clone(), host.ports.clone()),
                None => ("hostname".to_string(), default_map_ports.clone()),
            };
            let info_instance = InformationInstance {
                ports,
                onion: None,
                securite: status.securite,
                domaines: Some(vec![hostname]),
            };
            instances.insert(status.instance_id, info_instance);
        }
        instances
    };

    // Fetch and Map Applications (ApplicationStatusV2)
    let app_collection = mongo.get_collection_typed::<ApplicationStatusV2>(COLLECTION_CONFIGURED_APPLICATIONS_V2)?;
    let mut app_cursor = app_collection.find(doc!{}).await?;

    let mut applications_v2: HashMap<String, ApplicationsV2> = HashMap::new();
    while app_cursor.advance().await? {
        let app_status = app_cursor.deserialize_current()?;
        if ! instances.contains_key(&app_status.instance_id) {
            continue  // Instance is not active, ignore the associated applications
        }

        for (app_name, app_info) in app_status.applications {
            // Replace the app_name with the alias when present
            let app_name = match app_info.alias.as_ref() {
                Some(alias) => alias.to_owned(),
                None => app_name,
            };

            // Web application filtering (remove back-end and admin apps)
            let web_apps: Vec<WebItem> = match app_info.web {
                Some(web_apps) => {
                    let mut non_admin_web_apps = Vec::new();
                    for web_app in web_apps {
                        // Keep non-admin apps only (this is a public card)
                        if ! web_app.admin.unwrap_or(false) {
                            non_admin_web_apps.push(web_app);
                        }
                    }
                    non_admin_web_apps
                }
                None => {
                    continue;  // Not a web exposed application
                }
            };

            if web_apps.is_empty() {
                continue;  // No remaining exposed endpoints
            }

            let is_api = web_apps.iter().any(|item| item.api == Some(true));
            let securite = app_info.securite.unwrap_or_else(||SECURITE_2_PRIVE.to_string());  // Default to 2.prive

            // let supporte_usager = if app_info.portal.is_some() { Some(true) } else { None };
            let app_v2 = applications_v2.entry(app_name.clone()).or_insert_with(|| ApplicationsV2 {
                instances: HashMap::new(),
                name: Some(app_info.labels.clone()),
                securite,
                supporte_usager: Some(!is_api),
            });

            let pathname = match app_info.path.as_ref() {
                Some(app_path) => app_path.to_owned(),
                None =>  match web_apps.get(0) {
                    Some(web) => match web.path.as_ref() {
                        Some(web_path) => web_path.to_owned(),
                        None => format!("/{}", app_name),
                    },
                    None => format!("/{}", app_name)
                }
            };

            let appv2_info = InformationApplicationInstance {
                pathname,
                // port: app_info.web.and_then(|p| p.first().and_then(|i| i.port)),
                port: web_apps.first().and_then(|i| i.port),
                version: app_info.version,
            };

            app_v2.instances.insert(app_status.instance_id.clone(), appv2_info);
        }
    }

    let enveloppe = config.get_configuration_pki().get_enveloppe_privee();
    let idmg = enveloppe.enveloppe_pub.idmg()?;
    let ca_pem = enveloppe.enveloppe_ca.chaine_pem()?.remove(0);

    let fiche = FichePublique {
        applications_v2,
        chiffrage: Some(chiffrage),
        ca: Some(ca_pem),
        idmg,
        instances,
    };

    debug!("New fiche: {}", serde_json::to_string(&fiche)?);

    Ok(fiche)
}
