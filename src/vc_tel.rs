use crate::{
    error::Error,
    state::{Event, State},
};
use keri::{
    event::sections::seal::EventSeal,
    event_message::serialization_info::SerializationInfo,
    prefix::{IdentifierPrefix, SelfAddressingPrefix},
};
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TelState {
    NotIsuued,
    Issued(EventSeal),
    Revoked,
}

impl State<VCEvent> for TelState {
    fn apply(&self, event: &VCEvent) -> Result<Self, Error> {
        match event.event_type.clone() {
            EventType::Bis(iss) => match self {
                TelState::NotIsuued => Ok(TelState::Issued(iss.registry_anchor.clone())),
                _ => Err(Error::Generic("Wrong state".into())),
            },
            EventType::Brt(_rev) => match self {
                TelState::Issued(_) => Ok(TelState::Revoked),
                _ => Err(Error::Generic("Wrong state".into())),
            },
            EventType::Iss(_iss) => match self {
                TelState::NotIsuued => Ok(TelState::Issued(EventSeal::default())),
                _ => Err(Error::Generic("Wrong state".into())),
            },
            EventType::Rev(_rev) => match self {
                TelState::Issued(_) => Ok(TelState::Revoked),
                _ => Err(Error::Generic("Wrong state".into())),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VCEvent {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,

    #[serde(rename = "i")]
    // VC specific identifier will be a digest hash of the serialized contents of the VC
    pub prefix: SelfAddressingPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(flatten)]
    pub event_type: EventType,
}

impl Event for VCEvent {}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Identifier {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum EventType {
    Iss(SimpleIssuance),
    Rev(Revocation),
    Bis(Issuance),
    Brt(Revocation),
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Issuance {
    #[serde(rename = "ra")]
    registry_anchor: EventSeal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimpleIssuance {
    // registry identifier from management TEL
    #[serde(rename = "ri")]
    registry_id: IdentifierPrefix,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Revocation {
    #[serde(rename = "p")]
    prev_event_hash: SelfAddressingPrefix,
    // registry anchor to management TEL
    #[serde(rename = "ra")]
    registry_anchor: Option<EventSeal>,
}

#[test]
fn test_event() -> Result<(), Error> {
    let example = r#"{"v":"KERI10JSON00011c_","i":"Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4","s":"0","t":"iss","ri":"ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A"}"#;

    let eventt: VCEvent = serde_json::from_str(example).unwrap();

    assert_eq!(eventt.serialization_info, "KERI10JSON00011c_".parse()?);
    assert_eq!(
        eventt.prefix,
        "Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4".parse()?
    );
    assert_eq!(eventt.sn, 0);
    assert_eq!(
        eventt.event_type,
        EventType::Iss(SimpleIssuance {
            registry_id: "ELh3eYC2W_Su1izlvm0xxw01n3XK8bdV2Zb09IqlXB7A".parse()?
        })
    );

    assert_eq!(serde_json::to_string(&eventt).unwrap(), example);
    Ok(())
}
