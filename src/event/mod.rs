use self::{manager_event::ManagerTelEvent, vc_event::VCEvent};

pub mod manager_event;
pub mod vc_event;
pub mod verifiable_event;

#[derive(Clone)]
pub enum Event {
    Management(ManagerTelEvent),
    Vc(VCEvent),
}
