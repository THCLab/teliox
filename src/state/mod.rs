pub mod vc_state;

use keri::prefix::IdentifierPrefix;

use crate::{
    error::Error,
    event::{manager_event::ManagerTelEvent, Event},
};

pub trait State<E: Event> {
    fn apply(&self, event: &E) -> Result<Self, Error>
    where
        Self: Sized;
}

#[derive(Default, PartialEq)]
pub struct ManagerTelState {
    pub prefix: IdentifierPrefix,
    pub sn: u64,
    pub last: Vec<u8>,
    pub issuer: IdentifierPrefix,
    pub backers: Option<Vec<IdentifierPrefix>>,
}

impl State<ManagerTelEvent> for ManagerTelState {
    fn apply(&self, event: &ManagerTelEvent) -> Result<Self, Error>
    where
        Self: Sized,
    {
        event.apply_to(self)
    }
}
