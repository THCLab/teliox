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
    derivation::self_addressing::SelfAddressing,
    event::SerializationFormats,
    prefix::{IdentifierPrefix, SelfAddressingPrefix},
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
        ba: &[IdentifierPrefix],
        br: &[IdentifierPrefix],
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
        let vc_hash = self.derivation.derive(vc.as_bytes());
        event_generator::make_issuance_event(
            &self.get_management_tel_state()?,
            vc_hash,
            &self.derivation,
            &self.serialization_format,
        )
    }

    pub fn make_revoke_event(&self, vc: &SelfAddressingPrefix) -> Result<VCEvent, Error> {
        let vc_state = self.get_vc_state(vc)?;
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

    pub fn get_vc_state(&self, vc_hash: &SelfAddressingPrefix) -> Result<TelState, Error> {
        let vc_prefix = IdentifierPrefix::SelfAddressing(vc_hash.to_owned());
        self.processor.get_vc_state(&vc_prefix)
    }

    pub fn get_management_tel_state(&self) -> Result<ManagerTelState, Error> {
        self.processor.get_management_tel_state(&self.tel_prefix)
    }
}
#[cfg(test)]
mod tests {
    use std::fs;

    use keri::{derivation::self_addressing::SelfAddressing, event::SerializationFormats};

    use crate::{
        error::Error,
        event::{verifiable_event::VerifiableEvent, Event},
        seal::EventSourceSeal,
        state::State,
        tel::Tel,
    };

    #[test]
    pub fn test_management_tel() -> Result<(), Error> {
        use tempfile::Builder;

        let tel_root = Builder::new().prefix("tel-test-db").tempdir().unwrap();
        fs::create_dir_all(tel_root.path()).unwrap();
        let tel_db = crate::database::EventDatabase::new(tel_root.path()).unwrap();
        let issuer_prefix = "DpE03it33djytuVvXhSbZdEw0lx7Xa-olrlUUSH2Ykvc".parse()?;

        // Create tel
        let mut tel = Tel::new(
            &tel_db,
            SerializationFormats::JSON,
            SelfAddressing::Blake3_256,
        );
        let dummy_source_seal = EventSourceSeal {
            sn: 1,
            digest: "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8".parse()?,
        };

        let vcp = tel.make_inception_event(issuer_prefix, vec![], 0, vec![])?;
        let verifiable_vcp = VerifiableEvent::new(
            Event::Management(vcp.clone()),
            dummy_source_seal.clone().into(),
        );
        let processing_output = tel.process(verifiable_vcp.clone());
        assert!(processing_output.is_ok());

        let backers_to_add = vec!["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8".parse()?];
        let rcp = tel.make_rotation_event(&backers_to_add, &vec![])?;
        let verifiable_rcp =
            VerifiableEvent::new(Event::Management(rcp.clone()), dummy_source_seal.into());
        let processing_output = tel.process(verifiable_rcp.clone());
        assert!(processing_output.is_ok());
        if let State::Management(man) = processing_output.unwrap() {
            assert_eq!(man.backers, Some(backers_to_add))
        }

        Ok(())
    }
}
