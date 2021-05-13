use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

use keri::{
    event_message::serialization_info::SerializationInfo,
    prefix::{IdentifierPrefix, SelfAddressingPrefix},
    state::EventSemantics,
};

use crate::{error::Error, state::State};

pub struct ManagerTelState {
    backers: Vec<IdentifierPrefix>,
}

impl State<ManagerTelEvent> for ManagerTelState {
    fn apply(&self, event: ManagerTelEvent) -> Result<Self, Error>
    where
        Self: Sized,
    {
        todo!()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ManagerTelEvent {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,

    #[serde(rename = "i")]
    pub prefix: ManagerIdentifier,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    // list of backer identifiers for credentials associated with this registry
    #[serde(rename = "b")]
    backers: Vec<IdentifierPrefix>,

    #[serde(flatten, rename = "t")]
    pub event_type: ManagerEventType,
}

impl EventSemantics for ManagerTelEvent {}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ManagerIdentifier {}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ManagerEventType {
    Inception(Inc),
    Rotation(Rot),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Inc {
    issuer_id: IdentifierPrefix,
    config: String,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Rot {
    prev_event: SelfAddressingPrefix,
}