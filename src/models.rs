use std::collections::HashMap;
use millegrilles_common_rust::chrono::{DateTime, Utc};
use millegrilles_common_rust::serde::{Serialize, Deserialize};
use millegrilles_common_rust::bson::serde_helpers::datetime::FromChrono04DateTime;
use millegrilles_common_rust::mongo_serde::option_chrono_04_datetime;
use millegrilles_common_rust::chrono::serde::{ts_seconds, ts_milliseconds, ts_seconds_option};
use millegrilles_common_rust::millegrilles_cryptographie::chiffrage_docs::EncryptedDocument;
use millegrilles_common_rust::mongo_serde::map_opt_chrono_datetime_as_bson_datetime;
use millegrilles_common_rust::serde_json::Value;

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
pub struct ApplicationStatusV2Row {
    pub instance_id: String,
    pub applications: HashMap<String, ApplicationInfo>,
    pub securite: String,
    pub supprime: bool,
    #[serde(with="FromChrono04DateTime")]
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApplicationStatusV2Response {
    pub instance_id: String,
    pub applications: HashMap<String, ApplicationInfo>,
    pub securite: String,
    pub supprime: bool,
    #[serde(with="ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
}

impl From<ApplicationStatusV2Row> for ApplicationStatusV2Response {
    fn from(row: ApplicationStatusV2Row) -> Self {
        Self {
            instance_id: row.instance_id,
            applications: row.applications,
            securite: row.securite,
            supprime: row.supprime,
            timestamp: row.timestamp,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ServerInstanceConfigurationRow {
    pub instance_id: String,
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct FilehostingCongurationRow {
    pub name: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct RowFilehostFuuid {
    pub fuuid: String,
    #[serde(default, with="option_chrono_04_datetime")]
    pub last_claim_date: Option<DateTime<Utc>>,
    #[serde(default, with="map_opt_chrono_datetime_as_bson_datetime")]
    pub filehost: Option<HashMap<String, Option<DateTime<Utc>>>>,
}

#[derive(Serialize)]
pub struct FuuidVisitResponseItem {
    pub fuuid: String,
    /// Epoch seconds
    pub visits: HashMap<String, i64>,
}

impl From<RowFilehostFuuid> for FuuidVisitResponseItem {
    fn from(row_filehost_fuuid: RowFilehostFuuid) -> Self {

        let mut visits = HashMap::new();
        if let Some(filehost) = row_filehost_fuuid.filehost {
            for (key, value) in filehost {
                if let Some(value) = value {
                    visits.insert(key, value.timestamp());
                }
            }
        }

        Self {
            fuuid: row_filehost_fuuid.fuuid,
            visits,
        }
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub ip_addresses: Vec<String>,
    pub ports: HashMap<String, u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionUsageItem {
    pub mountpoint: String,
    pub free: u64,
    pub used: u64,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total: u64,
    pub available: u64,
    pub percent: f64,
    pub used: u64,
    pub free: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapInfo {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    pub percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub errin: u64,
    pub errout: u64,
    pub dropin: u64,
    pub dropout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskIOInfo {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_count: u64,
    pub write_count: u64,
    pub read_time: f64,
    pub write_time: f64,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertissuerStateRow {
    #[serde(default, with="option_chrono_04_datetime")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, with="option_chrono_04_datetime")]
    pub not_after: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertissuerStateResponse {
    #[serde(default, with="ts_seconds_option")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, with="ts_seconds_option")]
    pub not_after: Option<DateTime<Utc>>,
}

impl Into<CertissuerStateRow> for CertissuerStateResponse {
    fn into(self) -> CertissuerStateRow {
        CertissuerStateRow {
            not_before: self.not_before,
            not_after: self.not_after,
        }
    }
}

impl From<CertissuerStateRow> for CertissuerStateResponse {
    fn from(row: CertissuerStateRow) -> Self {
        Self {
            not_before: row.not_before,
            not_after: row.not_after,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemState {
    pub host: Option<HostInfo>,
    pub disk: Vec<PartitionUsageItem>,
    pub load_average: Vec<f64>,
    pub memory: MemoryInfo,
    pub swap: SwapInfo,
    pub cpu_count: i32,
    pub cpu_usage_percent: f64,
    pub network: NetworkInfo,
    pub disk_io: Option<DiskIOInfo>,
    pub uptime_seconds: f64,
    pub system_temperature: Option<Value>,
    pub system_fans: Option<Value>,
    pub system_battery: Option<Value>,
    pub apc: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerStatusV2Row {
    pub instance_id: String,
    pub system_state: SystemState,
    pub securite: String,
    pub supprime: bool,
    #[serde(with="FromChrono04DateTime")]
    pub timestamp: DateTime<Utc>,
    pub certissuer: Option<CertissuerStateRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagerStatusV2Response {
    pub instance_id: String,
    pub system_state: SystemState,
    pub securite: String,
    pub supprime: bool,
    #[serde(with="ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
    pub certissuer: Option<CertissuerStateResponse>,
}

impl From<ManagerStatusV2Row> for ManagerStatusV2Response {
    fn from(manager: ManagerStatusV2Row) -> Self {
        Self {
            instance_id: manager.instance_id,
            system_state: manager.system_state,
            securite: manager.securite,
            supprime: manager.supprime,
            timestamp: manager.timestamp,
            certissuer: match manager.certissuer { Some(value) => Some(value.into()), None => None },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileUsageMongo {
    // Note: using f64 rather than usize/u64 because of random bug loading large values with mongo client 2.8.1
    pub count: Option<f64>,
    pub size: Option<f64>,
}

impl Into<FileUsage> for FileUsageMongo {
    fn into(self) -> FileUsage {
        FileUsage {
            count: Some(self.count.unwrap_or(0f64) as usize),
            size: Some(self.size.unwrap_or(0f64) as usize),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct FilehostServerRow {
    pub filehost_id: String,
    pub instance_id: Option<String>,
    pub url_internal: Option<String>,
    pub url_external: Option<String>,
    pub tls_external: Option<String>,
    pub deleted: bool,
    pub sync_active: bool,
    #[serde(with = "FromChrono04DateTime")]
    pub created: DateTime<Utc>,
    #[serde(with = "FromChrono04DateTime")]
    pub modified: DateTime<Utc>,
    pub fuuid: Option<FileUsageMongo>,  // Workaround in f64 to handle mapping issue, NOT SERIALIZABLE
}

impl Into<RequeteFilehostItem> for FilehostServerRow {
    fn into(self) -> RequeteFilehostItem {
        RequeteFilehostItem {
            filehost_id: self.filehost_id,
            instance_id: self.instance_id,
            url_internal: self.url_internal,
            url_external: self.url_external,
            tls_external: self.tls_external,
            deleted: self.deleted,
            sync_active: self.sync_active,
            created: self.created,
            modified: self.modified,
            fuuid: match self.fuuid {Some (inner) => Some(inner.into()), None => None},
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileUsage {
    pub count: Option<usize>,
    pub size: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequeteFilehostItem {
    pub filehost_id: String,
    pub instance_id: Option<String>,
    pub url_internal: Option<String>,
    pub url_external: Option<String>,
    pub tls_external: Option<String>,
    pub deleted: bool,
    pub sync_active: bool,
    #[serde(with = "ts_seconds")]
    pub created: DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub modified: DateTime<Utc>,
    pub fuuid: Option<FileUsage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PresenceDomaine {
    pub domaine: Option<String>,
    pub instance_id: Option<String>,
    pub reclame_fuuids: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilehostingVisitRow {
    pub fuuid: String,
    pub filehost_id: String,
    #[serde(with = "FromChrono04DateTime")]
    pub visit_time: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct FilehostTransfer {
    pub destination_filehost_id: String,
    pub fuuid: String,
    #[serde(with = "FromChrono04DateTime")]
    pub created: DateTime<Utc>,
    #[serde(with = "FromChrono04DateTime")]
    pub modified: DateTime<Utc>,
    #[serde(default, with="option_chrono_04_datetime")]
    pub job_picked_up: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize)]
pub struct FileStorageInfo {
    pub count: i64,
    pub size: i64,
}

#[derive(Serialize, Deserialize)]
pub struct EventFilehostUsage {
    pub filehost_id: String,
    #[serde(with="ts_seconds")]
    pub date: DateTime<Utc>,
    pub fuuid: Option<FileStorageInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionSetFilehostInstance {
    pub instance_id: String,
    pub filehost_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionFilehostSetDefault {
    pub filehost_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionDeleteDomain {
    pub domain_name: String,
}

#[derive(Deserialize)]
pub struct FilehostAddTransaction {
    pub tls_external: Option<String>,
    pub url_external: Option<String>,
    pub url_internal: Option<String>,
}

#[derive(Deserialize)]
pub struct FilehostAddTransactionV2 {
    pub instance_id: Option<String>,
    pub tls_external: Option<String>,
    pub url_external: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventFilehost {
    pub filehost_id: String,
    pub event: String,
}

#[derive(Serialize, Deserialize)]
pub struct FilehostRestoreTransaction {
    pub filehost_id: String,
}

#[derive(Deserialize)]
pub struct FilehostUpdateTransaction {
    pub filehost_id: String,
    pub instance_id: Option<String>,
    pub sync_active: Option<bool>,
    pub tls_external: Option<String>,
    pub url_external: Option<String>,
    pub url_internal: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct FilehostDeleteTransaction {
    pub filehost_id: String,
    pub reset_default: Option<bool>,
}

#[derive(Deserialize)]
pub struct SyncStatusRow {
    pub claimer: String,
    #[allow(dead_code)]
    pub claimer_type: String,
    #[serde(default, with = "option_chrono_04_datetime")]
    pub date_ready: Option<DateTime<Utc>>,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigurationFileRow {
    pub file_id: String,
    /// Name of this collection of properties
    pub filename: String,
    /// Roles allowed to request the decrypted values
    pub roles: Option<Vec<String>>,
    /// Domains allowed to request the decryptee values
    pub domains: Option<Vec<String>>,
    #[serde(with="FromChrono04DateTime")]
    pub last_modified: DateTime<Utc>,
    /// Id to get decrypted key back from KeyMaster
    pub key_id: String,
    /// Cached value of the decryption key - encrypted using current signing key,
    /// invalid upon certificate rotation.
    pub encrypted_file_key: Option<String>,
}

#[derive(Serialize)]
pub struct ConfigurationFileResponse {
    pub file_id: String,
    pub filename: String,
    pub roles: Option<Vec<String>>,
    pub domains: Option<Vec<String>>,
    #[serde(with="ts_milliseconds")]
    pub last_modified: DateTime<Utc>,
    pub key_id: String,
}

impl From<ConfigurationFileRow> for ConfigurationFileResponse {
    fn from(row: ConfigurationFileRow) -> Self {
        Self {
            file_id: row.file_id,
            filename: row.filename,
            roles: row.roles,
            domains: row.domains,
            last_modified: row.last_modified,
            key_id: row.key_id,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ConfigurationPropertyRow {
    pub file_id: String,
    /// Name of this property
    pub key: String,
    /// Encrypted values
    pub value: EncryptedDocument,
    #[serde(with="FromChrono04DateTime")]
    pub last_modified: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigurationPropertyDecrypted {
    pub file_id: String,
    /// Name of this property
    pub key: String,
    /// Encrypted values
    pub value: ConfigurationValue,
    #[serde(with="ts_milliseconds")]
    pub last_modified: DateTime<Utc>,
}

/// Decrypted content of the configuration property value field.
#[derive(Serialize, Deserialize)]
pub struct ConfigurationValue {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inumber: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fnumber: Option<f64>,
}

#[derive(Deserialize)]
pub struct CommandCreateConfigurationFile {
    pub filename: String,
    pub roles: Option<Vec<String>>,
    pub domains: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionCreateConfigurationFile {
    /// Name of this collection of properties
    pub filename: String,
    /// Roles allowed to request the decrypted values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    /// Domains allowed to request the decrypted values
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,
    /// Id to get decrypted key back from KeyMaster
    pub key_id: String,
    /// Since this transaction is created by the domain, keep track of requesting party
    pub requestor_fingerprint: String,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionUpdateConfigurationFile {
    pub file_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub roles: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domains: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionDeleteConfigurationFile {
    pub file_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionSetFileProperty {
    pub file_id: String,
    pub key: String,
    pub value: EncryptedDocument,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionDeleteFileProperty {
    pub file_id: String,
    pub key: String,
}

#[derive(Serialize)]
pub struct ConfigurationFileEvent {
    pub file_id: String,
    pub filename: String,
    pub event: Option<String>,
}
