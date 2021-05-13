use keri::state::EventSemantics;

use crate::error::Error;

pub trait State<E: EventSemantics> {
    fn apply(&self, event: E) -> Result<Self, Error>
    where
        Self: Sized;
}
