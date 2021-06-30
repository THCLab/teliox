use crate::{
    attached_seal::AttachedSourceSeal, error::Error, manager_tel::ManagerTelEvent,
    vc_event::VCEvent,
};

pub struct VerifiableTelEvent {
    event: VCEvent,
    seal: AttachedSourceSeal,
}

impl VerifiableTelEvent {
    pub fn new(event: VCEvent, seal: AttachedSourceSeal) -> Self {
        Self { event, seal }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let ser: Vec<u8> = [self.event.serialize()?, self.seal.serialize()?].join("-".as_bytes());
        Ok(ser)
    }
}

pub struct VerifiableManagementEvent {
    event: ManagerTelEvent,
    seal: AttachedSourceSeal,
}

impl VerifiableManagementEvent {
    pub fn get_event(&self) -> ManagerTelEvent {
        self.event.clone()
    }
    pub fn new(event: ManagerTelEvent, seal: AttachedSourceSeal) -> Self {
        Self { event, seal }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        let ser: Vec<u8> = [self.event.serialize()?, self.seal.serialize()?].join("-".as_bytes());
        Ok(ser)
    }
}
