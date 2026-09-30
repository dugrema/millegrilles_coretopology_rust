use std::collections::HashMap;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::serde::{Serialize, Deserialize};
use millegrilles_common_rust::mongo_serde::option_chrono_04_datetime;
use millegrilles_common_rust::chrono::serde::ts_seconds_option;

#[derive(Serialize, Deserialize)]
pub struct DomainRow {
    pub instance_id: String,
    pub domaine: String,
    #[serde(default, rename(deserialize="_mg-creation"), with = "option_chrono_04_datetime")]
    pub creation: Option<DateTime<Utc>>,
    #[serde(default, rename(deserialize="_mg-derniere-modification"), with="option_chrono_04_datetime")]
    pub presence: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dirty: Option<bool>,
    pub reclame_fuuids: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_version: Option<String>,
    pub cle_id_backup: Option<String>,
}

#[derive(Serialize)]
pub struct DomainItemResponse {
    pub instance_id: String,
    pub domaine: String,
    #[serde(default, rename(deserialize="_mg-creation"), with = "ts_seconds_option")]
    pub creation: Option<DateTime<Utc>>,
    #[serde(default, rename(deserialize="_mg-derniere-modification"), with="ts_seconds_option")]
    pub presence: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dirty: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reclame_fuuids: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cle_id_backup: Option<String>,
}

impl From<DomainRow> for DomainItemResponse {
    fn from(row: DomainRow) -> Self {
        Self {
            instance_id: row.instance_id,
            domaine: row.domaine,
            creation: row.creation,
            presence: row.presence,
            dirty: row.dirty,
            reclame_fuuids: row.reclame_fuuids,
            backup_version: row.backup_version,
            cle_id_backup: row.cle_id_backup,
        }
    }
}


type ApplicationLabels = HashMap<String, String>;

#[derive(Debug, Serialize, Deserialize)]
pub struct WebItem {
    pub admin: Option<bool>,
    pub port: Option<u16>,
    pub path: Option<String>,
    pub labels: Option<ApplicationLabels>,
    pub api: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApplicationInfo {
    pub name: String,
    pub alias: Option<String>,
    pub version: String,
    pub securite: Option<String>,
    pub labels: ApplicationLabels,
    pub path: Option<String>,
    pub web: Option<Vec<WebItem>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApplicationStatusV2 {
    pub instance_id: String,
    pub applications: HashMap<String, ApplicationInfo>,
    pub securite: String,
    pub supprime: bool,
    pub timestamp: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct ServerInstanceConfigurationRow {
    pub instance_id: String,
    pub name: String,
    pub value: String,
}
