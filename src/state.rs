use crate::error::Error;

pub trait State<E: Event> {
    fn apply(&self, event: &E) -> Result<Self, Error>
    where
        Self: Sized;
}

pub trait Event {
}

pub trait Attachement {
    
}