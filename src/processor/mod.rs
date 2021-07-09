use keri::prefix::IdentifierPrefix;

use crate::{
    database::EventDatabase,
    error::Error,
    event::{verifiable_event::VerifiableEvent, Event},
    state::{vc_state::TelState, ManagerTelState, State},
};

pub struct EventProcessor<'d> {
    db: &'d EventDatabase,
}
impl<'d> EventProcessor<'d> {
    pub fn new(db: &'d EventDatabase) -> Self {
        Self { db }
    }

    pub fn get_management_tel_state(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<ManagerTelState, Error> {
        match self.db.get_management_events(id) {
            Some(events) => events.into_iter().fold(
                Ok(ManagerTelState::default()),
                |state: Result<ManagerTelState, Error>,
                 ev: VerifiableEvent|
                 -> Result<ManagerTelState, Error> {
                    match ev.event {
                        Event::Management(event) => state?.apply(&event),
                        Event::Vc(_) => Err(Error::Generic("Improper event type".into())),
                    }
                },
            ),
            None => Ok(ManagerTelState::default()),
        }
    }

    pub fn get_vc_state(&self, vc_id: &IdentifierPrefix) -> Result<TelState, Error> {
        match self.db.get_events(vc_id) {
            Some(events) => events.into_iter().fold(
                Ok(TelState::default()),
                |state, ev| -> Result<TelState, Error> {
                    match ev.event {
                        Event::Vc(event) => state?.apply(&event),
                        _ => state,
                    }
                },
            ),
            None => Ok(TelState::default()),
        }
    }

    // Process verifiable event. It doesn't check if source seal is correct. Just add event to tel.
    pub fn process(&self, event: VerifiableEvent) -> Result<State, Error> {
        match &event.event.clone() {
            Event::Management(ref man) => {
                self.db.add_new_management_event(event, &man.prefix)?;
                Ok(State::Management(
                    self.get_management_tel_state(&man.prefix)?,
                ))
            }
            Event::Vc(ref vc_ev) => {
                self.db.add_new_event(event, &vc_ev.prefix)?;
                Ok(State::Tel(self.get_vc_state(&vc_ev.prefix)?))
            }
        }
    }

    pub fn get_management_events(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        match self.db.get_management_events(id) {
            Some(events) => Ok(Some(
                events
                    .map(|event| event.serialize().unwrap_or_default())
                    .fold(vec![], |mut accum, serialized_event| {
                        accum.extend(serialized_event);
                        accum
                    }),
            )),
            None => Ok(None),
        }
    }

    pub fn get_events(&self, vc_id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        match self.db.get_events(vc_id) {
            Some(events) => Ok(Some(
                events
                    .map(|event| event.serialize().unwrap_or_default())
                    .fold(vec![], |mut accum, serialized_event| {
                        accum.extend(serialized_event);
                        accum
                    }),
            )),
            None => Ok(None),
        }
    }

    pub fn get_management_event_at_sn(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<VerifiableEvent>, Error> {
        match self.db.get_management_events(id) {
            Some(mut events) => Ok(events.find(|event| {
                if let Event::Management(man) = &event.event {
                    man.sn == sn
                } else {
                    false
                }
            })),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use keri::{
        derivation::self_addressing::SelfAddressing, event::SerializationFormats,
        prefix::IdentifierPrefix,
    };

    use crate::{
        error::Error,
        event::{verifiable_event::VerifiableEvent, Event},
        processor::EventProcessor,
        seal::EventSourceSeal,
        state::vc_state::TelState,
        tel::event_generator,
    };

    #[test]
    pub fn test_processing() -> Result<(), Error> {
        use std::fs;
        use tempfile::Builder;
        // Create test db and processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        fs::create_dir_all(root.path()).unwrap();
        let db = crate::database::EventDatabase::new(root.path()).unwrap();
        let processor = EventProcessor::new(&db);

        // Setup test data.
        let message = "some message";
        let message_id = SelfAddressing::Blake3_256.derive(message.as_bytes());
        let issuer_prefix: IdentifierPrefix =
            "EaKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY".parse()?;
        let derivation = SelfAddressing::Blake3_256;
        let serialization = SerializationFormats::JSON;
        let dummy_source_seal = EventSourceSeal {
            sn: 1,
            digest: "EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8".parse()?,
        };

        let vcp = event_generator::make_inception_event(
            issuer_prefix,
            vec![],
            0,
            vec![],
            &derivation,
            &serialization,
        )?;

        let management_tel_prefix = vcp.clone().prefix;

        // before applying vcp to management tel, insert anchor event seal.
        // note: source seal isn't check while event processing.
        let verifiable_vcp = VerifiableEvent::new(
            Event::Management(vcp.clone()),
            dummy_source_seal.clone().into(),
        );
        processor.process(verifiable_vcp.clone())?;

        // Check management state.
        let st = processor.get_management_tel_state(&management_tel_prefix)?;
        assert_eq!(st.sn, 0);

        // check if vcp event is in db.
        let man_event_from_db = processor.get_management_event_at_sn(&management_tel_prefix, 0)?;
        assert!(man_event_from_db.is_some());
        assert_eq!(man_event_from_db.unwrap(), verifiable_vcp);

        // create issue event
        let vc_prefix = IdentifierPrefix::SelfAddressing(message_id.clone());
        let iss_event = event_generator::make_issuance_event(
            &st,
            message_id.clone(),
            &derivation,
            &serialization,
        )?;

        let verifiable_iss = VerifiableEvent::new(
            Event::Vc(iss_event.clone()),
            dummy_source_seal.clone().into(),
        );
        processor.process(verifiable_iss.clone())?;

        // Chcek if iss event is in db.
        let o = processor.get_events(&vc_prefix)?;
        assert!(o.is_some());
        assert_eq!(o.unwrap(), verifiable_iss.serialize()?);

        let state =
            processor.get_vc_state(&IdentifierPrefix::SelfAddressing(message_id.clone()))?;
        assert!(matches!(state, TelState::Issued(_)));
        let last = match state {
            TelState::Issued(last) => last,
            _ => vec![],
        };

        // Create revocation event.
        let rev_event = event_generator::make_revoke_event(
            &message_id,
            derivation.clone().derive(&last),
            &st,
            &derivation,
            &serialization,
        )?;

        let verifiable_rev = VerifiableEvent::new(
            Event::Vc(rev_event.clone()),
            dummy_source_seal.clone().into(),
        );

        // Check if vc was revoked.
        processor.process(verifiable_rev.clone())?;
        let state = processor.get_vc_state(&vc_prefix)?;
        assert!(matches!(state, TelState::Revoked));

        // Chcek if rev event is in db.
        let o = processor.get_events(&vc_prefix)?;
        assert!(o.is_some());
        let expected_event_vec = [
            &verifiable_iss.serialize()?[..],
            &verifiable_rev.serialize()?[..],
        ]
        .concat();
        assert_eq!(o.unwrap(), expected_event_vec);

        let backers: Vec<IdentifierPrefix> =
            vec!["BwFbQvUaS4EirvZVPUav7R_KDHB8AKmSfXNpWnZU_YEU".parse()?];

        let vrt = event_generator::make_rotation_event(
            &st,
            &backers,
            &vec![],
            &derivation,
            &serialization,
        )?;

        let verifiable_vrt = VerifiableEvent::new(
            Event::Management(vrt.clone()),
            dummy_source_seal.clone().into(),
        );
        processor.process(verifiable_vrt.clone())?;

        // Check management state.
        let st = processor.get_management_tel_state(&management_tel_prefix)?;
        assert_eq!(st.sn, 1);

        // check if vrt event is in db.
        let man_event_from_db = processor.get_management_event_at_sn(&management_tel_prefix, 1)?;
        assert!(man_event_from_db.is_some());
        assert_eq!(man_event_from_db.unwrap(), verifiable_vrt);

        Ok(())
    }
}
