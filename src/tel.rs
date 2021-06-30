use std::collections::HashMap;

use keri::{
    derivation::self_addressing::SelfAddressing,
    event::{sections::seal::EventSeal, SerializationFormats},
    prefix::{IdentifierPrefix, SelfAddressingPrefix},
};

use crate::{
    error::Error,
    event::manager_event::{Config, Inc, ManagerEventType, ManagerTelEvent, Rot},
    event::vc_event::{EventType, Issuance, Revocation, VCEvent},
    event::verifiable_event::VerifiableManagementEvent,
    state::{ManagerTelState, State},
};

pub struct Tel {
    // TODO
    serialization_format: SerializationFormats,
    derivation: SelfAddressing,
    management_tel: Vec<VerifiableManagementEvent>,
    tel_prefix: IdentifierPrefix,
    vc_tel: HashMap<SelfAddressingPrefix, Vec<VCEvent>>,
}

impl Tel {
    pub fn new(serialization_format: SerializationFormats, derivation: SelfAddressing) -> Self {
        Self {
            tel_prefix: IdentifierPrefix::default(),
            serialization_format,
            derivation,
            management_tel: vec![],
            vc_tel: HashMap::new(),
        }
    }

    fn last_management(&self) -> Result<Vec<u8>, Error> {
        self.management_tel
            .last()
            .map(|e| e.serialize().unwrap())
            .ok_or(Error::Generic("Management tel is empty".into()))
    }

    fn get_management_tel_state(&self) -> Result<ManagerTelState, Error> {
        Ok(self
            .management_tel
            .iter()
            .fold(ManagerTelState::default(), |state, ev| {
                state.apply(&ev.get_event()).unwrap()
            }))
    }

    pub fn make_inception_event(
        &self,
        issuer_prefix: IdentifierPrefix,
        config: Vec<Config>,
        backer_threshold: u64,
        backers: Vec<IdentifierPrefix>,
    ) -> Result<ManagerTelEvent, Error> {
        let event_type = Inc {
            issuer_id: issuer_prefix,
            config,
            backer_threshold,
            backers,
        };
        event_type.incept_self_addressing(&self.derivation, self.serialization_format)
    }

    pub fn make_rotation_event(
        &self,
        ba: Vec<IdentifierPrefix>,
        br: Vec<IdentifierPrefix>,
    ) -> Result<ManagerTelEvent, Error> {
        let rot_data = Rot {
            prev_event: self.derivation.derive(&self.last_management()?),
            backers_to_add: ba,
            backers_to_remove: br,
        };
        ManagerTelEvent::new(
            &self.tel_prefix,
            self.get_management_tel_state()?.sn,
            ManagerEventType::Vrt(rot_data),
            self.serialization_format,
        )
    }

    pub fn make_issuance_event(&self, vc: &str) -> Result<VCEvent, Error> {
        let managment_state = self.get_management_tel_state()?;
        let registry_anchor = EventSeal {
            prefix: managment_state.prefix,
            sn: managment_state.sn,
            event_digest: self.derivation.derive(&managment_state.last),
        };
        let iss = EventType::Bis(Issuance::new(registry_anchor));
        let vc_prefix =
            IdentifierPrefix::SelfAddressing(SelfAddressing::Blake3_256.derive(vc.as_bytes()));
        VCEvent::new(vc_prefix.clone(), 0, iss, self.serialization_format)
    }

    pub fn revoke(&self, vc: &str) -> Result<VCEvent, Error> {
        let managment_state = self.get_management_tel_state()?;
        let registry_anchor = EventSeal {
            prefix: managment_state.prefix,
            sn: managment_state.sn,
            event_digest: self.derivation.derive(&managment_state.last),
        };
        let rev = EventType::Brv(Revocation {
            prev_event_hash: self.derivation.derive(&managment_state.last),
            registry_anchor: Some(registry_anchor),
        });
        let vc_prefix =
            IdentifierPrefix::SelfAddressing(SelfAddressing::Blake3_256.derive(vc.as_bytes()));
        VCEvent::new(vc_prefix, 0, rev, self.serialization_format)
    }
}
#[cfg(test)]
mod tests {
    use std::fs;

    use keri::{
        database::sled::SledEventDatabase,
        derivation::self_addressing::SelfAddressing,
        event::{sections::seal::EventSeal, SerializationFormats},
        prefix::IdentifierPrefix,
        signer::CryptoBox,
    };

    use crate::{
        error::Error,
        event::manager_event::Config,
        event::verifiable_event::{VerifiableManagementEvent, VerifiableTelEvent},
        kerl::KERL,
        seal::EventSourceSeal,
        state::{vc_state::TelState, State},
        tel::Tel,
    };

    #[test]
    pub fn test_issuing() -> Result<(), Error> {
        use tempfile::Builder;
        // Create test db and key manager.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        fs::create_dir_all(root.path()).unwrap();
        let db = SledEventDatabase::new(root.path()).unwrap();
        let km = CryptoBox::new()?;

        let mut kerl = KERL::new(&db, IdentifierPrefix::default())?;
        kerl.incept(&km)?;

        let vc = "some vc";

        let issuer_prefix = kerl.get_state()?.unwrap().prefix;

        let tel = Tel::new(SerializationFormats::JSON, SelfAddressing::Blake3_256);
        let vcp = tel.make_inception_event(issuer_prefix, vec![Config::NoBackers], 0, vec![])?;

        let management_tel_prefix = vcp.clone().prefix;

        // create vcp seal which will be inserted into issuer kel (ixn event)
        let vcp_seal = EventSeal {
            prefix: management_tel_prefix.clone(),
            sn: vcp.sn,
            event_digest: SelfAddressing::Blake3_256.derive(&vcp.serialize()?),
        };

        let ixn = kerl.make_ixn_with_seal(vcp_seal, &km)?;

        let ixn_source_seal = EventSourceSeal {
            sn: ixn.event_message.event.sn,
            digest: SelfAddressing::Blake3_256.derive(&ixn.serialize()?),
        };

        // before applying vcp to management tel, insert anchor event seal to be able to verify that operation.
        let verifiable_vcp = VerifiableManagementEvent::new(vcp.clone(), ixn_source_seal.into());

        // now create tel event
        let vc_prefix =
            IdentifierPrefix::SelfAddressing(SelfAddressing::Blake3_256.derive(vc.as_bytes()));
        let iss_event = tel.make_issuance_event(vc)?;

        let iss_seal = EventSeal {
            prefix: vc_prefix,
            sn: iss_event.sn,
            event_digest: SelfAddressing::Blake3_256.derive(&iss_event.serialize()?),
        };

        let ixn = kerl.make_ixn_with_seal(iss_seal, &km)?;

        let ixn_source_seal = EventSourceSeal {
            sn: ixn.event_message.event.sn,
            digest: SelfAddressing::Blake3_256.derive(&ixn.serialize()?),
        };

        // before applying vcp to management tel, insert anchor event seal to be able to verify that operation.
        let verifiable_iss = VerifiableTelEvent::new(iss_event.clone(), ixn_source_seal.into());

        let vc_state = TelState::default().apply(&iss_event)?;
        // process management event.
        println!("{:?}", vc_state);

        Ok(())
    }
}
