use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

use keri::{
    event_message::serialization_info::SerializationInfo,
    prefix::{IdentifierPrefix, SelfAddressingPrefix},
};

use crate::{error::Error, state::{Event, State}};

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

impl Event for ManagerTelEvent {
}

impl ManagerTelEvent {
    pub fn apply_to(&self, state: &ManagerTelState) -> Result<ManagerTelState, Error> {
        match self.event_type {
            ManagerEventType::Inception(ref vcp) => {
                if state != &ManagerTelState::default() {
                    Err(Error::Generic("Improper manager state".into()))
                } else {
                    let backers = if vcp.backers.is_empty() {
                        None
                    } else {
                        Some(vcp.backers.clone())
                    };
                    Ok(ManagerTelState { issuer: vcp.issuer_id.clone(), backers })
                }
            }
            ManagerEventType::Rotation(ref vrt) => {
                match state.backers {
                    Some(ref backers) => {
                        let mut new_backers: Vec<IdentifierPrefix> = backers.iter().filter(|backer| !backers.contains(backer)).map(|x| x.to_owned()).collect();
                        vrt.backers_to_add.iter().for_each(|ba| new_backers.push(ba.to_owned()));
                        Ok(ManagerTelState {backers: Some(new_backers), issuer: state.issuer.clone()})
                    }
                    None => {Err(Error::Generic("Trying to update backers of backerless state".into()))}
                }
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ManagerIdentifier {}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum ManagerEventType {
    Inception(Inc),
    Rotation(Rot),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Inc {
    // list of backer identifiers for credentials associated with this registry
    #[serde(rename = "b")]
    backers: Vec<IdentifierPrefix>,

    #[serde(rename = "ii")]
    issuer_id: IdentifierPrefix,

    #[serde(rename = "c")]
    config: String,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Rot {
    #[serde(rename = "p")]
    prev_event: SelfAddressingPrefix,
    #[serde(rename = "ba")]
    backers_to_add: Vec<IdentifierPrefix>,
    #[serde(rename = "br")]
    backers_to_remove: Vec<IdentifierPrefix>
}