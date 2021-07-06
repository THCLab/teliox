use crate::{
    database::EventDatabase,
    error::Error,
    event::manager_event::{Config, ManagerTelEvent},
    event::vc_event::VCEvent,
    event::verifiable_event::VerifiableEvent,
    processor::EventProcessor,
    state::{vc_state::TelState, ManagerTelState, State},
};
use keri::{
    derivation::self_addressing::SelfAddressing, event::SerializationFormats,
    prefix::IdentifierPrefix,
};

pub mod event_generator;

pub struct Tel<'d> {
    pub processor: EventProcessor<'d>,
    serialization_format: SerializationFormats,
    derivation: SelfAddressing,
    tel_prefix: IdentifierPrefix,
}

impl<'d> Tel<'d> {
    pub fn new(
        db: &'d EventDatabase,
        serialization_format: SerializationFormats,
        derivation: SelfAddressing,
    ) -> Self {
        Self {
            processor: EventProcessor::new(db),
            tel_prefix: IdentifierPrefix::default(),
            serialization_format,
            derivation,
        }
    }

    pub fn make_inception_event(
        &self,
        issuer_prefix: IdentifierPrefix,
        config: Vec<Config>,
        backer_threshold: u64,
        backers: Vec<IdentifierPrefix>,
    ) -> Result<ManagerTelEvent, Error> {
        event_generator::make_inception_event(
            issuer_prefix,
            config,
            backer_threshold,
            backers,
            &self.derivation,
            &self.serialization_format,
        )
    }

    pub fn make_rotation_event(
        &self,
        ba: Vec<IdentifierPrefix>,
        br: Vec<IdentifierPrefix>,
    ) -> Result<ManagerTelEvent, Error> {
        event_generator::make_rotation_event(
            &self.get_management_tel_state()?,
            ba,
            br,
            &self.derivation,
            &self.serialization_format,
        )
    }

    pub fn make_issuance_event(&self, vc: &str) -> Result<VCEvent, Error> {
        let vc_hash = SelfAddressing::Blake3_256.derive(vc.as_bytes());
        event_generator::make_issuance_event(
            &self.get_management_tel_state()?,
            vc_hash,
            &self.derivation,
            &self.serialization_format,
        )
    }

    pub fn make_revoke_event(&self, vc: &str) -> Result<VCEvent, Error> {
        let vc_state = self.get_vc_state(vc.as_bytes())?;
        let last = match vc_state {
            TelState::Issued(last) => self.derivation.derive(&last),
            _ => return Err(Error::Generic("Inproper vc state".into())),
        };
        event_generator::make_revoke_event(
            vc,
            last,
            &self.get_management_tel_state()?,
            &self.derivation,
            &self.serialization_format,
        )
    }

    // Process verifiable event. It doesn't check if source seal is correct. Just add event to tel.
    pub fn process(&mut self, event: VerifiableEvent) -> Result<State, Error> {
        let state = self.processor.process(event)?;
        // If tel prefix is not set yet, set it to first processed management event identifier prefix.
        if self.tel_prefix == IdentifierPrefix::default() {
            if let State::Management(ref man) = state {
                self.tel_prefix = man.prefix.to_owned()
            }
        }
        Ok(state)
    }

    pub fn get_vc_state(&self, vc: &[u8]) -> Result<TelState, Error> {
        let vc_prefix = IdentifierPrefix::SelfAddressing(self.derivation.derive(vc));
        self.processor.get_vc_state(&vc_prefix)
    }

    pub fn get_management_tel_state(&self) -> Result<ManagerTelState, Error> {
        self.processor.get_management_tel_state(&self.tel_prefix)
    }
}
#[cfg(test)]
mod tests {
    use std::fs;

    use keri::{
        database::sled::SledEventDatabase,
        derivation::self_addressing::SelfAddressing,
        event::{
            sections::seal::{EventSeal, Seal},
            SerializationFormats,
        },
        prefix::IdentifierPrefix,
        signer::CryptoBox,
    };

    use crate::{
        error::Error,
        event::{manager_event::Config, verifiable_event::VerifiableEvent, Event},
        kerl::KERL,
        seal::EventSourceSeal,
        state::vc_state::TelState,
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

        // Create kerl
        let mut kerl = KERL::new(&db, IdentifierPrefix::default())?;
        kerl.incept(&km)?;

        let message = "some vc";

        let issuer_prefix = kerl.get_state()?.unwrap().prefix;
        let tel_root = Builder::new().prefix("tel-test-db").tempdir().unwrap();
        fs::create_dir_all(tel_root.path()).unwrap();
        let tel_db = crate::database::EventDatabase::new(tel_root.path()).unwrap();

        // Create tel
        let mut tel = Tel::new(
            &tel_db,
            SerializationFormats::JSON,
            SelfAddressing::Blake3_256,
        );
        let vcp = tel.make_inception_event(issuer_prefix, vec![Config::NoBackers], 0, vec![])?;

        let management_tel_prefix = vcp.clone().prefix;

        // create vcp seal which will be inserted into issuer kel (ixn event)
        let vcp_seal = Seal::Event(EventSeal {
            prefix: management_tel_prefix.clone(),
            sn: vcp.sn,
            event_digest: SelfAddressing::Blake3_256.derive(&vcp.serialize()?),
        });

        let ixn = kerl.make_ixn_with_seal(&vec![vcp_seal], &km)?;

        let ixn_source_seal = EventSourceSeal {
            sn: ixn.event_message.event.sn,
            digest: SelfAddressing::Blake3_256.derive(&ixn.serialize()?),
        };

        // before applying vcp to management tel, insert anchor event seal to be able to verify that operation.
        let verifiable_vcp =
            VerifiableEvent::new(Event::Management(vcp.clone()), ixn_source_seal.into());
        tel.process(verifiable_vcp.clone())?;

        // Check management state.
        let st = tel.get_management_tel_state()?;
        assert_eq!(st.sn, 0);

        // check if vcp event is in db.
        let mana_ev = tel.processor.get_management_events(&tel.tel_prefix)?;
        assert!(mana_ev.is_some());
        assert_eq!(mana_ev.unwrap(), verifiable_vcp.serialize()?);

        // now create tel event
        let vc_prefix =
            IdentifierPrefix::SelfAddressing(SelfAddressing::Blake3_256.derive(message.as_bytes()));
        let iss_event = tel.make_issuance_event(message)?;

        // create iss seal which will be inserted into issuer kel (ixn event)
        let iss_seal = Seal::Event(EventSeal {
            prefix: vc_prefix.clone(),
            sn: iss_event.sn,
            event_digest: SelfAddressing::Blake3_256.derive(&iss_event.serialize()?),
        });

        let ixn = kerl.make_ixn_with_seal(&vec![iss_seal], &km)?;

        // Make source seal.
        let ixn_source_seal = EventSourceSeal {
            sn: ixn.event_message.event.sn,
            digest: SelfAddressing::Blake3_256.derive(&ixn.serialize()?),
        };

        // before applying iss to tel, insert anchor event seal to be able to verify that operation.
        let verifiable_iss =
            VerifiableEvent::new(Event::Vc(iss_event.clone()), ixn_source_seal.into());
        tel.process(verifiable_iss.clone())?;

        // Chcek if iss event is in db.
        let o = tel.processor.get_events(&vc_prefix)?;
        assert!(o.is_some());
        assert_eq!(o.unwrap(), verifiable_iss.serialize()?);

        let state = tel.get_vc_state(message.as_bytes())?;
        assert!(matches!(state, TelState::Issued(_)));

        let rev_event = tel.make_revoke_event(message)?;
        // create rev seal which will be inserted into issuer kel (ixn event)
        let rev_seal = Seal::Event(EventSeal {
            prefix: vc_prefix.clone(),
            sn: rev_event.sn,
            event_digest: SelfAddressing::Blake3_256.derive(&iss_event.serialize()?),
        });

        let ixn = kerl.make_ixn_with_seal(&vec![rev_seal], &km)?;

        // Make source seal.
        let ixn_source_seal = EventSourceSeal {
            sn: ixn.event_message.event.sn,
            digest: SelfAddressing::Blake3_256.derive(&ixn.serialize()?),
        };

        // before applying iss to tel, insert anchor event seal to be able to verify that operation.
        let verifiable_rev =
            VerifiableEvent::new(Event::Vc(rev_event.clone()), ixn_source_seal.into());

        tel.process(verifiable_rev.clone())?;
        let state = tel.get_vc_state(message.as_bytes())?;
        assert!(matches!(state, TelState::Revoked));

        Ok(())
    }
}
