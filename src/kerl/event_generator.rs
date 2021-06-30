use crate::error::Error;
use keri::{
    derivation::{basic::Basic, self_addressing::SelfAddressing},
    event::{
        event_data::{EventData, Receipt},
        sections::seal::{DigestSeal, EventSeal, Seal},
        Event, EventMessage, SerializationFormats,
    },
    event_message::event_msg_builder::{EventMsgBuilder, EventType},
    prefix::IdentifierPrefix,
    signer::KeyManager,
    state::IdentifierState,
};

pub enum KeyType {
    Ed25519Sha512,
}

pub struct Key {
    key: Vec<u8>,
    key_type: KeyType,
}

impl Key {
    pub fn new(key: Vec<u8>, key_type: KeyType) -> Key {
        Self { key, key_type }
    }

    // pub fn derive_key_prefix(&self) -> BasicPrefix {
    //     let pk = self.key.clone();
    //     match self.key_type {
    //         KeyType::Ed25519Sha512 => BasicPrefix::new(Basic::Ed25519, keri::keys::Key::new(pk))
    //     }
    // }
}

pub fn make_icp(
    km: &dyn KeyManager,
    prefix: Option<IdentifierPrefix>,
) -> Result<EventMessage, Error> {
    let key_prefix = vec![Basic::Ed25519.derive(km.public_key())];
    let pref = prefix.unwrap_or(IdentifierPrefix::Basic(key_prefix[0].clone()));
    let nxt_key_prefix = vec![Basic::Ed25519.derive(km.next_public_key())];
    let icp = EventMsgBuilder::new(EventType::Inception)?
        .with_prefix(pref)
        .with_keys(key_prefix)
        .with_next_keys(nxt_key_prefix)
        .build()?;
    Ok(icp)
}

pub fn make_rot(km: &dyn KeyManager, state: IdentifierState) -> Result<EventMessage, Error> {
    let key_prefix = vec![Basic::Ed25519.derive(km.public_key())];
    let nxt_key_prefix = vec![Basic::Ed25519.derive(km.next_public_key())];
    let ixn = EventMsgBuilder::new(EventType::Rotation)?
        .with_prefix(state.prefix.clone())
        .with_sn(state.sn + 1)
        .with_previous_event(SelfAddressing::Blake3_256.derive(&state.last))
        .with_keys(key_prefix)
        .with_next_keys(nxt_key_prefix)
        .build()?;
    Ok(ixn)
}

pub fn make_ixn(payload: Option<&str>, state: IdentifierState) -> Result<EventMessage, Error> {
    let seal_list = match payload {
        Some(payload) => {
            vec![Seal::Digest(DigestSeal {
                dig: SelfAddressing::Blake3_256.derive(payload.as_bytes()),
            })]
        }
        None => vec![],
    };
    let ev = EventMsgBuilder::new(EventType::Interaction)?
        .with_prefix(state.prefix.clone())
        .with_sn(state.sn + 1)
        .with_previous_event(SelfAddressing::Blake3_256.derive(&state.last))
        .with_seal(seal_list)
        .build()?;
    Ok(ev)
}

pub fn make_ixn_with_event_seal(
    event_seal: EventSeal,
    state: IdentifierState,
) -> Result<EventMessage, Error> {
    let seal_list = vec![Seal::Event(event_seal)];
    let ev = EventMsgBuilder::new(EventType::Interaction)?
        .with_prefix(state.prefix.clone())
        .with_sn(state.sn + 1)
        .with_previous_event(SelfAddressing::Blake3_256.derive(&state.last))
        .with_seal(seal_list)
        .build()?;
    Ok(ev)
}

pub fn make_rct(
    event: EventMessage,
    _validator_seal: EventSeal,
    _state: IdentifierState,
) -> Result<EventMessage, Error> {
    let ser = event.serialize()?;
    let rcp = Event {
        prefix: event.event.prefix,
        sn: event.event.sn,
        event_data: EventData::Rct(Receipt {
            receipted_event_digest: SelfAddressing::Blake3_256.derive(&ser),
        }),
    }
    .to_message(SerializationFormats::JSON)?;
    Ok(rcp)
}
