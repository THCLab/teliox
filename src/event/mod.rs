use self::{manager_event::ManagerTelEvent, vc_event::VCEvent};
use serde::{Deserialize, Serialize};

pub mod manager_event;
pub mod vc_event;
pub mod verifiable_event;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Event {
    Management(ManagerTelEvent),
    Vc(VCEvent),
}
