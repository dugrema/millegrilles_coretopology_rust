use crate::constants::*;
use crate::external::mongo::COLLECTION_NAME_REDOLOG;
use millegrilles_common_rust::certificats::VerificateurPermissions;
use millegrilles_common_rust::chrono::{Datelike, Duration, Timelike, Utc, Weekday};
use millegrilles_common_rust::common_messages::BackupEvent;
use millegrilles_common_rust::error::Error as CommonError;
use millegrilles_common_rust::messages_generiques::MessageCedule;
use millegrilles_common_rust::mongo_dao::MongoDaoTyped;
use millegrilles_common_rust::tracing::{debug, error, info, warn};
use millegrilles_common_rust::v3::facades::message_inbound::MessageValidated;
use millegrilles_common_rust::v3::facades::message_outbound::MessageOutboundFacade;
use millegrilles_common_rust::v3::{BackupService, ChiffrageService, ConfigService, PresenceService};
use crate::fiche::produire_fiche_publique;
use crate::flow::filecontroler::{entretien_transfert_fichiers, maintain_expired_filehost_visits, maintain_unclaimed_fuuids, regenerate_filehosting_fuuids};

pub async fn process_ticker_job<M>(
    mongo: &M,
    config: &dyn ConfigService,
    chiffrage: &dyn ChiffrageService,
    outbound: &MessageOutboundFacade,
    backup: &dyn BackupService,
    trigger: MessageValidated
) -> Result<(), CommonError> where M: MongoDaoTyped {
    // Ensure this is an authorized module
    if let Err(e) = validate_ticker(&trigger).await {
        error!("Invalid ticker message, rejecting: {}", e);
        return Ok(());
    }

    let trigger_value: MessageCedule = trigger.message.deserialize()?;

    let hour = trigger_value.get_date().hour();
    let minute = trigger_value.get_date().minute();
    let day = trigger_value.get_date().weekday();

    debug!("ticker_job_ca for h:{} m:{}",hour,minute);

    // Emit domain presence
    if let Err(e) = outbound.emit_domain_presence(DOMAIN_NAME, None).await {
        warn!("Error emitting domain presence: {}", e);
    }

    if minute % 5 == 1
    {
        debug!("CoreTopology Produire fiche publique");
        if let Err(e) = produire_fiche_publique(mongo, config, chiffrage, outbound).await {
            error!("core_topoologie.produire_fiche_publique Erreur production fiche publique initiale : {:?}", e);
        }
    }


    // Check every 3 minutes if claims/visits can be processed (low impact if no work).
    if minute % 3 == 2
    {
        debug!("CoreTopology regenerate_filehosting_fuuids");
        if let Err(e) = regenerate_filehosting_fuuids(mongo, outbound).await {
            error!("core_topoologie.regenerate_filehosting_fuuids Error in maintenance of files claims and visits : {:?}", e);
        }
    }

    // Maintain file transfers between filehosts
    if minute % 15 == 6
    {
        debug!("CoreTopology entretien_transfert_fichiers");
        if let Err(e) = entretien_transfert_fichiers(mongo, outbound).await {
            error!("core_topologie.entretien_transfert_fichiers Erreur entretien transferts fichiers : {:?}", e);
        }
    }

    if hour % 8 == 0 && minute == 29
    // if minutes == 29
    {
        debug!("CoreTopology maintain_unclaimed_fuuids");
        if let Err(e) = maintain_unclaimed_fuuids(mongo, outbound).await {
            error!("core_topologie.maintain_unclaimed_fuuids Error maintaining unclaimed fuuids : {:?}", e);
        }

        debug!("CoreTopology maintain_expired_filehost_visits");
        if let Err(e) = maintain_expired_filehost_visits(mongo).await {
            error!("core_topologie.maintain_unclaimed_fuuids Error maintaining expired filehost visits : {:?}", e);
        }
    }

    if minute % 30 == 4 {
        // {
        // Run complete backup once a week on Sunday at 7:04 UTC.
        // This concatenates all incremental files and rotates backup files. May produce final file.
        let complete = minute == 4 && hour == 7 && day == Weekday::Sun;
        // let complete = true;

        match backup.backup_domain(
            DOMAIN_NAME,
            COLLECTION_NAME_REDOLOG,
            ! complete,  // Invert, the bool is for incremental backups (true == incremental)
        ).await {
            Ok(result) => {
                info!("Backup task completed");
                match backup.transfer_backup_files_to_filehost(DOMAIN_NAME).await {
                    Ok(()) => {
                        info!("Backup files uploaded to filehost");
                        // Emit the backup done event. This tells the filecontroler to sync backup files
                        // across all filehosts.
                        let version = match result { Some(result) => result.version, None => None };
                        outbound.emit_backup_event(BackupEvent::new_done(DOMAIN_NAME, version)).await.ok();
                    },
                    Err(e) => error!("Error uploading backup files to filehost: {}", e)
                }
            },
            Err(e) => {
                error!("Error backing up domain: {}", e);
            }
        }
    }

    // Additional file upload task in case backups keep failing.
    if minute == 13 && hour % 8 == 1 {
        // {
        if let Err(e) = backup.transfer_backup_files_to_filehost(DOMAIN_NAME).await {
            error!("Error uploading backup files to filehost: {}", e);
        }
    }

    Ok(())
}

pub const ROLE_TICKER: &str = "ceduleur";

pub async fn validate_ticker(trigger: &MessageValidated) -> Result<(), CommonError> {
    if let Ok(true) = trigger.certificate.verifier_roles_string(vec![ROLE_TICKER.to_string()]) {
        // Ok
    } else {
        return Err(CommonError::Str("Ticker message without ticker (ceduleur) role, ignoring"));
    }
    if trigger.message.estampille < Utc::now() - Duration::seconds(45) {
        debug!("Expired Ticker message, ignoring");
        return Err(CommonError::Str("Ticker message without ticker (ceduleur) role, ignoring"));
    }
    Ok(())
}
