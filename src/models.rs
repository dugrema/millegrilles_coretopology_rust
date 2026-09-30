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
    pub backup_version: Option<String>
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
    pub reclame_fuuids: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_version: Option<String>
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
        }
    }
}
