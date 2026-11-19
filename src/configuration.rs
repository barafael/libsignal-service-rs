use core::fmt;
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use crate::{content::ServiceError, utils::BASE64_RELAXED};
use base64::prelude::*;
use libsignal_core::{DeviceId, E164};
use libsignal_protocol::PublicKey;
use serde::{Deserialize, Serialize};
use url::Url;
use zkgroup::ServerPublicParams;

use crate::push_service::{HttpAuth, DEFAULT_DEVICE_ID};

/// Where the servers are and what they are trusted with.
///
/// Serializes as its wire form: URLs as strings, the CDN map keyed by the CDN number as a
/// string, trust roots and the zkgroup parameters as base64. For example, in TOML:
///
/// ```toml
/// service_url = "https://127.0.0.1:4443"
/// storage_url = "https://127.0.0.1:4444"
/// certificate_authority = """
/// -----BEGIN CERTIFICATE-----
/// ...
/// -----END CERTIFICATE-----
/// """
/// unidentified_sender_trust_roots = ["BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF"]
/// zkgroup_server_public_params = "AMhf5ywV..."
///
/// [cdn_urls]
/// 0 = "https://127.0.0.1:4445"
/// 2 = "https://127.0.0.1:4445"
/// 3 = "https://127.0.0.1:4445"
/// ```
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    try_from = "ServiceConfigurationRepr",
    into = "ServiceConfigurationRepr"
)]
pub struct ServiceConfiguration {
    service_url: Url,
    storage_url: Url,
    cdn_urls: HashMap<u32, Url>,
    pub certificate_authority: String,
    pub unidentified_sender_trust_roots: Vec<PublicKey>,
    pub zkgroup_server_public_params: ServerPublicParams,
}

impl ServiceConfiguration {
    /// A configuration for servers other than Signal's, such as a test server.
    pub fn new(
        service_url: Url,
        storage_url: Url,
        cdn_urls: HashMap<u32, Url>,
        certificate_authority: String,
        unidentified_sender_trust_roots: Vec<PublicKey>,
        zkgroup_server_public_params: ServerPublicParams,
    ) -> Self {
        Self {
            service_url,
            storage_url,
            cdn_urls,
            certificate_authority,
            unidentified_sender_trust_roots,
            zkgroup_server_public_params,
        }
    }

    /// The chat server: accounts, keys, messages, provisioning.
    pub fn service_url(&self) -> &Url {
        &self.service_url
    }

    /// The storage service: the settings manifest and groups.
    pub fn storage_url(&self) -> &Url {
        &self.storage_url
    }

    /// The CDNs by number: attachments, avatars, stickers.
    pub fn cdn_urls(&self) -> &HashMap<u32, Url> {
        &self.cdn_urls
    }
}

impl fmt::Debug for ServiceConfiguration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceConfiguration")
            .field("service_url", &self.service_url.as_str())
            .field("storage_url", &self.storage_url.as_str())
            .field("cdn_urls", &self.cdn_urls)
            .finish_non_exhaustive()
    }
}

impl PartialEq for ServiceConfiguration {
    fn eq(&self, other: &Self) -> bool {
        ServiceConfigurationRepr::from(self.clone())
            == ServiceConfigurationRepr::from(other.clone())
    }
}

impl Eq for ServiceConfiguration {}

/// The serialized form of a [`ServiceConfiguration`].
#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct ServiceConfigurationRepr {
    service_url: Url,
    storage_url: Url,
    cdn_urls: BTreeMap<String, Url>,
    certificate_authority: String,
    unidentified_sender_trust_roots: Vec<String>,
    zkgroup_server_public_params: String,
}

impl From<ServiceConfiguration> for ServiceConfigurationRepr {
    fn from(cfg: ServiceConfiguration) -> Self {
        Self {
            service_url: cfg.service_url,
            storage_url: cfg.storage_url,
            cdn_urls: cfg
                .cdn_urls
                .into_iter()
                .map(|(id, url)| (id.to_string(), url))
                .collect(),
            certificate_authority: cfg.certificate_authority,
            unidentified_sender_trust_roots: cfg
                .unidentified_sender_trust_roots
                .iter()
                .map(|key| BASE64_STANDARD.encode(key.serialize()))
                .collect(),
            zkgroup_server_public_params: BASE64_STANDARD.encode(
                bincode::serialize(&cfg.zkgroup_server_public_params)
                    .expect("server public params serialize"),
            ),
        }
    }
}

/// What is wrong with a serialized [`ServiceConfiguration`].
#[derive(Debug, thiserror::Error)]
pub enum ServiceConfigurationError {
    #[error("CDN number {0:?} is not a number")]
    CdnNumber(String),
    #[error("unidentified sender trust root: {0}")]
    TrustRoot(String),
    #[error("zkgroup server public params: {0}")]
    ZkGroupServerPublicParams(String),
}

impl TryFrom<ServiceConfigurationRepr> for ServiceConfiguration {
    type Error = ServiceConfigurationError;

    fn try_from(repr: ServiceConfigurationRepr) -> Result<Self, Self::Error> {
        let cdn_urls = repr
            .cdn_urls
            .into_iter()
            .map(|(id, url)| {
                id.parse::<u32>()
                    .map(|id| (id, url))
                    .map_err(|_| ServiceConfigurationError::CdnNumber(id))
            })
            .collect::<Result<_, _>>()?;
        let unidentified_sender_trust_roots = repr
            .unidentified_sender_trust_roots
            .iter()
            .map(|key| {
                let bytes = BASE64_RELAXED.decode(key).map_err(|e| {
                    ServiceConfigurationError::TrustRoot(e.to_string())
                })?;
                PublicKey::deserialize(&bytes).map_err(|e| {
                    ServiceConfigurationError::TrustRoot(e.to_string())
                })
            })
            .collect::<Result<_, _>>()?;
        let zkgroup_server_public_params = BASE64_RELAXED
            .decode(&repr.zkgroup_server_public_params)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                bincode::deserialize(&bytes).map_err(|e| e.to_string())
            })
            .map_err(ServiceConfigurationError::ZkGroupServerPublicParams)?;
        Ok(Self {
            service_url: repr.service_url,
            storage_url: repr.storage_url,
            cdn_urls,
            certificate_authority: repr.certificate_authority,
            unidentified_sender_trust_roots,
            zkgroup_server_public_params,
        })
    }
}

#[derive(Clone)]
pub struct ServiceCredentials {
    pub aci: Option<uuid::Uuid>,
    pub pni: Option<uuid::Uuid>,
    pub phonenumber: E164,
    pub password: Option<String>,
    pub device_id: Option<DeviceId>,
}

impl ServiceCredentials {
    pub fn authorization(&self) -> Option<HttpAuth> {
        self.password.as_ref().map(|password| HttpAuth {
            username: self.login(),
            password: password.clone(),
        })
    }

    pub fn e164(&self) -> String {
        self.phonenumber.to_string()
    }

    pub fn login(&self) -> String {
        let identifier = {
            if let Some(uuid) = self.aci.as_ref() {
                uuid.to_string()
            } else {
                self.e164()
            }
        };

        match self.device_id {
            None => identifier,
            Some(device_id) if device_id == *DEFAULT_DEVICE_ID => identifier,
            Some(id) => format!("{}.{}", identifier, id),
        }
    }
}

/// Which servers to talk to: Signal's, or some of our own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalServers {
    Staging,
    Production,
    /// Servers other than Signal's, such as a test server, described in full.
    Custom(Box<ServiceConfiguration>),
}

#[cfg(feature = "cdsi")]
impl TryFrom<&SignalServers> for libsignal_net::env::Env<'static> {
    type Error = ServiceError;

    /// Contact discovery runs in Signal's enclaves, so there is none for custom servers.
    fn try_from(servers: &SignalServers) -> Result<Self, Self::Error> {
        match servers {
            SignalServers::Staging => Ok(libsignal_net::env::STAGING),
            SignalServers::Production => Ok(libsignal_net::env::PROD),
            SignalServers::Custom(_) => {
                Err(ServiceError::ContactDiscoveryUnavailable)
            },
        }
    }
}

#[derive(Debug)]
pub enum Endpoint<'a> {
    Absolute(Url),
    Service {
        path: Cow<'a, str>,
    },
    Storage {
        path: Cow<'a, str>,
    },
    Cdn {
        cdn_id: u32,
        path: Cow<'a, str>,
        query: Option<Cow<'a, str>>,
    },
}

impl fmt::Display for Endpoint<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Absolute(url) => write!(f, "absolute URL {url}"),
            Endpoint::Service { path } => {
                write!(f, "service API call to {path}")
            },
            Endpoint::Storage { path } => {
                write!(f, "storage API call to {path}")
            },
            Endpoint::Cdn { cdn_id, path, .. } => {
                write!(f, "CDN{cdn_id} call to {path}")
            },
        }
    }
}

impl<'a> Endpoint<'a> {
    pub fn service(path: impl Into<Cow<'a, str>>) -> Self {
        Self::Service { path: path.into() }
    }

    pub fn cdn(cdn_id: u32, path: impl Into<Cow<'a, str>>) -> Self {
        Self::Cdn {
            cdn_id,
            path: path.into(),
            query: None,
        }
    }

    pub fn cdn_url(cdn_id: u32, url: &'a Url) -> Self {
        Self::Cdn {
            cdn_id,
            path: url.path().into(),
            query: url.query().map(Into::into),
        }
    }

    pub fn storage(path: impl Into<Cow<'a, str>>) -> Self {
        Self::Storage { path: path.into() }
    }

    pub fn into_url(
        self,
        service_configuration: &ServiceConfiguration,
    ) -> Result<Url, ServiceError> {
        match self {
            Endpoint::Service { path } => {
                Ok(service_configuration.service_url.join(&path)?)
            },
            Endpoint::Storage { path } => {
                Ok(service_configuration.storage_url.join(&path)?)
            },
            Endpoint::Cdn {
                cdn_id,
                path,
                query,
            } => {
                let Some(mut url) =
                    service_configuration.cdn_urls.get(&cdn_id).cloned()
                else {
                    tracing::warn!(%cdn_id, "Unknown CDN");
                    return Err(ServiceError::UnknownCdnVersion(cdn_id));
                };
                url.set_path(&path);
                url.set_query(query.as_deref());
                Ok(url)
            },
            Endpoint::Absolute(url) => Ok(url),
        }
    }
}

impl FromStr for SignalServers {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use std::io::ErrorKind;
        match s {
            "staging" => Ok(Self::Staging),
            "production" => Ok(Self::Production),
            _ => Err(Self::Err::new(
                ErrorKind::InvalidInput,
                "invalid signal servers, can be either: staging or production",
            )),
        }
    }
}

impl fmt::Display for SignalServers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Staging => f.write_str("staging"),
            Self::Production => f.write_str("production"),
            Self::Custom(cfg) => write!(f, "custom ({})", cfg.service_url),
        }
    }
}

impl From<SignalServers> for ServiceConfiguration {
    fn from(val: SignalServers) -> Self {
        ServiceConfiguration::from(&val)
    }
}

impl From<&SignalServers> for ServiceConfiguration {
    fn from(val: &SignalServers) -> Self {
        // base configuration from https://github.com/signalapp/Signal-Desktop/blob/development/config/default.json
        match val {
            SignalServers::Custom(cfg) => (**cfg).clone(),
            // configuration with the Signal API staging endpoints
            // see: https://github.com/signalapp/Signal-Desktop/blob/master/config/default.json
            SignalServers::Staging => ServiceConfiguration {
                service_url: "https://chat.staging.signal.org".parse().unwrap(),
                storage_url:"https://storage-staging.signal.org".parse().unwrap(),
                cdn_urls: {
                    let mut map = HashMap::new();
                    map.insert(0, "https://cdn-staging.signal.org".parse().unwrap());
                    map.insert(2, "https://cdn2-staging.signal.org".parse().unwrap());
                    map.insert(3, "https://cdn3-staging.signal.org".parse().unwrap());
                    map
                },
                certificate_authority: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/staging-root-ca.pem")).to_string(),
                unidentified_sender_trust_roots: vec![
                    PublicKey::deserialize(&BASE64_RELAXED.decode("BbqY1DzohE4NUZoVF+L18oUPrK3kILllLEJh2UnPSsEx").unwrap()).unwrap(),
                    PublicKey::deserialize(&BASE64_RELAXED.decode("BYhU6tPjqP46KGZEzRs1OL4U39V5dlPJ/X09ha4rErkm").unwrap()).unwrap(),
                ],
                zkgroup_server_public_params: bincode::deserialize(&BASE64_RELAXED.decode("ABSY21VckQcbSXVNCGRYJcfWHiAMZmpTtTELcDmxgdFbtp/bWsSxZdMKzfCp8rvIs8ocCU3B37fT3r4Mi5qAemeGeR2X+/YmOGR5ofui7tD5mDQfstAI9i+4WpMtIe8KC3wU5w3Inq3uNWVmoGtpKndsNfwJrCg0Hd9zmObhypUnSkfYn2ooMOOnBpfdanRtrvetZUayDMSC5iSRcXKpdlukrpzzsCIvEwjwQlJYVPOQPj4V0F4UXXBdHSLK05uoPBCQG8G9rYIGedYsClJXnbrgGYG3eMTG5hnx4X4ntARBgELuMWWUEEfSK0mjXg+/2lPmWcTZWR9nkqgQQP0tbzuiPm74H2wMO4u1Wafe+UwyIlIT9L7KLS19Aw8r4sPrXZSSsOZ6s7M1+rTJN0bI5CKY2PX29y5Ok3jSWufIKcgKOnWoP67d5b2du2ZVJjpjfibNIHbT/cegy/sBLoFwtHogVYUewANUAXIaMPyCLRArsKhfJ5wBtTminG/PAvuBdJ70Z/bXVPf8TVsR292zQ65xwvWTejROW6AZX6aqucUjlENAErBme1YHmOSpU6tr6doJ66dPzVAWIanmO/5mgjNEDeK7DDqQdB1xd03HT2Qs2TxY3kCK8aAb/0iM0HQiXjxZ9HIgYhbtvGEnDKW5ILSUydqH/KBhW4Pb0jZWnqN/YgbWDKeJxnDbYcUob5ZY5Lt5ZCMKuaGUvCJRrCtuugSMaqjowCGRempsDdJEt+cMaalhZ6gczklJB/IbdwENW9KeVFPoFNFzhxWUIS5ML9riVYhAtE6JE5jX0xiHNVIIPthb458cfA8daR0nYfYAUKogQArm0iBezOO+mPk5vCNWI+wwkyFCqNDXz/qxl1gAntuCJtSfq9OC3NkdhQlgYQ==").unwrap()).unwrap(),
            },
            // configuration with the Signal API production endpoints
            // https://github.com/signalapp/Signal-Desktop/blob/master/config/production.json
            SignalServers::Production => ServiceConfiguration {
                service_url:
                    "https://chat.signal.org".parse().unwrap(),
                storage_url: "https://storage.signal.org".parse().unwrap(),
                cdn_urls: {
                    let mut map = HashMap::new();
                    map.insert(0, "https://cdn.signal.org".parse().unwrap());
                    map.insert(2, "https://cdn2.signal.org".parse().unwrap());
                    map.insert(3, "https://cdn3.signal.org".parse().unwrap());
                    map
                },
                certificate_authority: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/production-root-ca.pem")).to_string(),
                unidentified_sender_trust_roots: vec![
                    PublicKey::deserialize(&BASE64_RELAXED.decode("BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF").unwrap()).unwrap(),
                    PublicKey::deserialize(&BASE64_RELAXED.decode("BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6").unwrap()).unwrap(),
                ],
                zkgroup_server_public_params: bincode::deserialize(
                    &BASE64_RELAXED.decode("AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0dqCnImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzizUe5e8XyGOy9fplzhw3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P+NameAZYOD12qRkxosQQP5uux6B2nRyZ7sAV54DgFyLiRcq1FvwKw2EPQdk4HDoePrO/RNUbyNddnM/mMgj4FW65xCoT1LmjrIjsv/Ggdlx46ueczhMgtBunx1/w8k8V+l8LVZ8gAT6wkU5J+DPQalQguMg12Jzug3q4TbdHiGCmD9EunCwOmsLuLJkz6EcSYXtrlDEnAM+hicw7iergYLLlMXpfTdGxJCWJmP4zqUFeTTmsmhsjGBt7NiEB/9pFFEB3pSbf4iiUukw63Eo8Aqnf4iwob6X1QviCWuc8t0LUlT9vALgh/f2DPVOOmR0RW6bgRvc7DSF20V/omg+YBw==").unwrap()).unwrap(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_round_trips_through_serde() {
        let production = ServiceConfiguration::from(SignalServers::Production);
        let json = serde_json::to_string(&production).unwrap();
        let back: ServiceConfiguration = serde_json::from_str(&json).unwrap();
        assert_eq!(back, production);
        assert_eq!(back.service_url().as_str(), "https://chat.signal.org/");
        assert_eq!(back.cdn_urls().len(), 3);
        assert_eq!(back.unidentified_sender_trust_roots.len(), 2);
    }

    #[test]
    fn servers_keep_their_old_serialized_form() {
        assert_eq!(
            serde_json::to_string(&SignalServers::Production).unwrap(),
            "\"Production\""
        );
        let custom = SignalServers::Custom(Box::new(
            ServiceConfiguration::from(SignalServers::Staging),
        ));
        let json = serde_json::to_string(&custom).unwrap();
        assert!(json.starts_with("{\"Custom\":{"));
        assert_eq!(
            serde_json::from_str::<SignalServers>(&json).unwrap(),
            custom
        );
    }

    #[test]
    fn bad_values_are_refused() {
        let mut repr = serde_json::to_value(ServiceConfiguration::from(
            SignalServers::Staging,
        ))
        .unwrap();
        repr["cdn_urls"] = serde_json::json!({ "zero": "https://x.test" });
        assert!(serde_json::from_value::<ServiceConfiguration>(repr.clone())
            .unwrap_err()
            .to_string()
            .contains("CDN number"));
        repr["cdn_urls"] = serde_json::json!({});
        repr["unidentified_sender_trust_roots"] = serde_json::json!(["AAAA"]);
        assert!(serde_json::from_value::<ServiceConfiguration>(repr)
            .unwrap_err()
            .to_string()
            .contains("trust root"));
    }
}
