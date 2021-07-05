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
        Ok(match self.db.get_management_events(id) {
            Some(events) => {
                events
                    .into_iter()
                    .fold(ManagerTelState::default(), |state, ev| match ev.event {
                        Event::Management(event) => state.apply(&event).unwrap(),
                        _ => state,
                    })
            }
            None => ManagerTelState::default(),
        })
    }

    pub fn get_state(&self, vc_id: &IdentifierPrefix) -> Result<TelState, Error> {
        Ok(match self.db.get_events(vc_id) {
            Some(events) => {
                events
                    .into_iter()
                    .fold(TelState::default(), |state, ev| match ev.event {
                        Event::Vc(event) => state.apply(&event).unwrap(),
                        _ => state,
                    })
            }
            None => TelState::default(),
        })
    }

    // Process verifiable event. It doesn't check if source seal is correct. Just add event to tel.
    pub fn process(&mut self, event: VerifiableEvent) -> Result<State, Error> {
        match &event.event.clone() {
            Event::Management(ref man) => {
                self.db
                    .add_new_management_event_message(event, &man.prefix)?;
                Ok(State::Management(
                    self.get_management_tel_state(&man.prefix)?,
                ))
            }
            Event::Vc(ref vc_ev) => {
                self.db.add_new_event(event, &vc_ev.prefix)?;
                Ok(State::Tel(self.get_state(&vc_ev.prefix)?))
            }
        }
    }

    pub fn get_management_tel_vec(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
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

    pub fn get_tel_vec(&self, vc_id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
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
}
