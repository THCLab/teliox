use crate::{error::Error, state::State};
use keri::{
    event::sections::seal::EventSeal, event_message::serialization_info::SerializationInfo,
    prefix::SelfAddressingPrefix, state::EventSemantics,
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
    fn apply(&self, event: VCEvent) -> Result<Self, Error> {
        match event.event_type {
            EventType::Issuance(iss) => match self {
                TelState::NotIsuued => Ok(TelState::Issued(iss.registry_anchor.clone())),
                _ => Err(Error::Generic("Wrong state".into())),
            },
            EventType::Revocation(rev) => match self {
                TelState::Issued(_) => Ok(TelState::Revoked),
                _ => Err(Error::Generic("Wrong state".into())),
            },
            EventType::SimpleIssuance(iss) => match self {
                TelState::NotIsuued => Ok(TelState::Issued(EventSeal::default())),
                _ => Err(Error::Generic("Wrong state".into())),
            },
            EventType::SimpleRevocation(rev) => match self {
                TelState::Issued(_) => Ok(TelState::Revoked),
                _ => Err(Error::Generic("Wrong state".into())),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct VCEvent {
    /// Serialization Information
    ///
    /// Encodes the version, size and serialization format of the event
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,

    #[serde(rename = "i")]
    pub prefix: Identifier,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(flatten)]
    pub event_type: EventType,
}

impl EventSemantics for VCEvent {}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Identifier {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EventType {
    SimpleIssuance(SimpleIssuance),
    SimpleRevocation(Revocation),
    Issuance(Issuance),
    Revocation(Revocation),
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Issuance {
    registry_anchor: EventSeal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SimpleIssuance {
    // registry identifier from management TEL
    registry_id: Identifier,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Revocation {
    prev_event_hash: SelfAddressingPrefix,
    // registry anchor to management TEL
    registry_anchor: Option<EventSeal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operation {
    Issue(EventSeal),
    Revoke(EventSeal),
}
