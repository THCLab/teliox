use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

use keri::{
    event::SerializationFormats,
    event_message::serialization_info::SerializationInfo,
    prefix::{IdentifierPrefix, SelfAddressingPrefix},
};

use crate::{
    error::Error,
    state::{Event, State},
};

#[derive(Default, PartialEq)]
pub struct ManagerTelState {
    issuer: IdentifierPrefix,
    backers: Option<Vec<IdentifierPrefix>>,
}

impl State<ManagerTelEvent> for ManagerTelState {
    fn apply(&self, event: &ManagerTelEvent) -> Result<Self, Error>
    where
        Self: Sized,
    {
        event.apply_to(self)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ManagerTelEvent {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,

    // The Registry specific identifier will be self-certifying, self-addressing using its inception data for its derivation.
    // This requires a commitment to the anchor in the controlling KEL and necessitates the event location seal be included in
    // the event. The derived identifier is then set in the i field of the events in the management TEL.
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(flatten, rename = "t")]
    pub event_type: ManagerEventType,
}

impl Event for ManagerTelEvent {}

impl ManagerTelEvent {
    fn new(
        prefix: IdentifierPrefix,
        sn: u64,
        event_type: ManagerEventType,
        format: SerializationFormats,
    ) -> Result<Self, Error> {
        let size = Self {
            serialization_info: SerializationInfo::new(format, 0),
            prefix: prefix.clone(),
            sn,
            event_type: event_type.clone(),
        }
        .serialize()?
        .len();
        let serialization_info = SerializationInfo::new(format, size);
        Ok(Self {
            serialization_info,
            prefix,
            sn,
            event_type,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        self.serialization_info
            .kind
            .encode(self)
            .map_err(|e| Error::KeriError(e))
    }

    pub fn apply_to(&self, state: &ManagerTelState) -> Result<ManagerTelState, Error> {
        match self.event_type {
            ManagerEventType::Vcp(ref vcp) => {
                if state != &ManagerTelState::default() {
                    Err(Error::Generic("Improper manager state".into()))
                } else {
                    let backers = if vcp.config.contains(&String::from("NB")) {
                        None
                    } else {
                        Some(vcp.backers.clone())
                    };
                    Ok(ManagerTelState {
                        issuer: vcp.issuer_id.clone(),
                        backers,
                    })
                }
            }
            ManagerEventType::Vrt(ref vrt) => match state.backers {
                Some(ref backers) => {
                    let mut new_backers: Vec<IdentifierPrefix> = backers
                        .iter()
                        .filter(|backer| !backers.contains(backer))
                        .map(|x| x.to_owned())
                        .collect();
                    vrt.backers_to_add
                        .iter()
                        .for_each(|ba| new_backers.push(ba.to_owned()));
                    Ok(ManagerTelState {
                        backers: Some(new_backers),
                        issuer: state.issuer.clone(),
                    })
                }
                None => Err(Error::Generic(
                    "Trying to update backers of backerless state".into(),
                )),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ManagerIdentifier {}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum ManagerEventType {
    Vcp(Inc),
    Vrt(Rot),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Inc {
    #[serde(rename = "ii")]
    issuer_id: IdentifierPrefix,

    #[serde(rename = "c")]
    config: Vec<String>,

    #[serde(rename = "bt", with = "SerHex::<Compact>")]
    backer_threshold: u64,

    // list of backer identifiers for credentials associated with this registry
    #[serde(rename = "b")]
    backers: Vec<IdentifierPrefix>,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Rot {
    #[serde(rename = "p")]
    prev_event: SelfAddressingPrefix,
    #[serde(rename = "ba")]
    backers_to_add: Vec<IdentifierPrefix>,
    #[serde(rename = "br")]
    backers_to_remove: Vec<IdentifierPrefix>,
}

#[test]
fn test_serialization() -> Result<(), Error> {
    // Manager inception
    let vcp_raw = r#"{"v":"KERI10JSON0000ad_","i":"EjD_sFljMHXJCC3rEFL93MwHNGguKdC11mcMuQnZitcs","ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"vcp","c":["NB"],"bt":"0","b":[]}"#;
    let vcp: ManagerTelEvent = serde_json::from_str(vcp_raw).unwrap();
    assert_eq!(
        vcp.prefix,
        "EjD_sFljMHXJCC3rEFL93MwHNGguKdC11mcMuQnZitcs".parse()?
    );
    assert_eq!(vcp.sn, 0);
    let expected_event_type = ManagerEventType::Vcp(Inc {
        issuer_id: "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM".parse()?,
        config: vec!["NB".to_string()],
        backer_threshold: 0,
        backers: vec![],
    });
    assert_eq!(vcp.event_type, expected_event_type);

    let vcp_raw = r#"{"v":"KERI10JSON0000d7_","i":"EVohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s","ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"vcp","c":[],"bt":"1","b":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"]}"#;
    let vcp: ManagerTelEvent = serde_json::from_str(vcp_raw).unwrap();
    assert_eq!(
        vcp.prefix,
        "EVohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s".parse()?
    );
    assert_eq!(vcp.sn, 0);
    let expected_event_type = ManagerEventType::Vcp(Inc {
        issuer_id: "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM".parse()?,
        config: vec![],
        backer_threshold: 1,
        backers: vec!["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc".parse()?],
    });
    assert_eq!(vcp.event_type, expected_event_type);

    // Manager rotation
    let vrt_raw = r#"{"v":"KERI10JSON0000aa_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"3","t":"vrt","bt":"1","br":[],"ba":[]}"#;
    let vrt: ManagerTelEvent = serde_json::from_str(vrt_raw).unwrap();
    assert_eq!(
        vrt.prefix,
        "EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw".parse()?
    );
    assert_eq!(vrt.sn, 3);
    let expected_event_type = ManagerEventType::Vrt(Rot {
        prev_event: "EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg".parse()?,
        backers_to_add: vec![],
        backers_to_remove: vec![],
    });
    assert_eq!(vrt.event_type, expected_event_type);

    Ok(())
}

#[test]
fn test_apply_to() -> Result<(), Error> {
    Ok(())
}