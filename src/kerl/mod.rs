// use event_generator::{Key, KeyType};
use keri::{
    database::sled::SledEventDatabase,
    derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning},
    event::{
        event_data::EventData,
        sections::seal::{DigestSeal, EventSeal, Seal},
        EventMessage,
    },
    event_message::parse::signed_message,
    event_message::parse::{signed_event_stream, Deserialized},
    event_message::SignedEventMessage,
    prefix::AttachedSignaturePrefix,
    prefix::IdentifierPrefix,
    processor::EventProcessor,
    signer::KeyManager,
    state::IdentifierState,
};

use crate::error::Error;
pub mod event_generator;

pub struct KERL<'d> {
    prefix: IdentifierPrefix,
    processor: EventProcessor<'d>,
}

impl<'d> KERL<'d> {
    // incept a state and keys
    pub fn new(db: &'d SledEventDatabase, prefix: IdentifierPrefix) -> Result<KERL<'d>, Error> {
        Ok(KERL {
            prefix,
            processor: EventProcessor::new(db),
        })
    }

    pub fn process(
        &mut self,
        message: EventMessage,
        signature: Vec<u8>,
    ) -> Result<SignedEventMessage, Error> {
        let sigged = message.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]);
        self.processor
            .process(signed_message(&sigged.serialize()?).unwrap().1)?;
        match message.event.event_data {
            EventData::Icp(_) => {
                if self.prefix == IdentifierPrefix::default() {
                    self.prefix = message.clone().event.prefix
                }
            }
            _ => {}
        };
        Ok(sigged)
    }

    pub fn incept<K: KeyManager>(&mut self, key_manager: &K) -> Result<SignedEventMessage, Error> {
        let icp = event_generator::make_icp(key_manager, Some(self.prefix.clone()))?;

        let sigged = icp.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            key_manager.sign(&icp.serialize()?)?,
            0,
        )]);

        self.processor
            .process(signed_message(&sigged.serialize()?).unwrap().1)?;

        self.prefix = icp.event.prefix;

        Ok(sigged)
    }

    pub fn rotate<K: KeyManager>(
        &mut self,
        key_manager: &mut K,
    ) -> Result<SignedEventMessage, Error> {
        key_manager.rotate()?;
        let rot = event_generator::make_rot(key_manager, self.get_state()?.unwrap()).unwrap();

        let rot = rot.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            key_manager.sign(&rot.serialize()?)?,
            0,
        )]);

        self.processor
            .process(signed_message(&rot.serialize()?).unwrap().1)?;

        Ok(rot)
    }

    pub fn make_ixn<K: KeyManager>(
        &mut self,
        payload: Option<&str>,
        key_manager: &K,
    ) -> Result<SignedEventMessage, Error> {
        let state = self.get_state()?.unwrap();
        let seal_list = match payload {
            Some(payload) => {
                vec![Seal::Digest(DigestSeal {
                    dig: SelfAddressing::Blake3_256.derive(payload.as_bytes()),
                })]
            }
            None => vec![],
        };

        let ev = event_generator::make_ixn_with_seal(&seal_list, state).unwrap();

        let ixn = ev.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            key_manager.sign(&ev.serialize()?)?,
            0,
        )]);

        self.processor
            .process(signed_message(&ixn.serialize()?).unwrap().1)?;

        Ok(ixn)
    }

    pub fn make_ixn_with_seal<K: KeyManager>(
        &mut self,
        seal_list: &[Seal],
        key_manager: &K,
    ) -> Result<SignedEventMessage, Error> {
        let state = self.get_state()?.unwrap();

        let ev = event_generator::make_ixn_with_seal(seal_list, state).unwrap();

        let ixn = ev.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            key_manager.sign(&ev.serialize()?)?,
            0,
        )]);

        self.processor
            .process(signed_message(&ixn.serialize()?).unwrap().1)?;

        Ok(ixn)
    }

    pub fn respond<K: KeyManager>(&self, msg: &[u8], key_manager: &K) -> Result<Vec<u8>, Error> {
        let events = signed_event_stream(msg)
            .map_err(|e| Error::Generic(e.to_string()))?
            .1;
        let (processed_ok, _processed_failed): (Vec<_>, Vec<_>) = events
            .into_iter()
            .map(|event| {
                self.processor
                    .process(event.clone())
                    .and_then(|_| Ok(event))
            })
            .partition(Result::is_ok);
        let response: Vec<u8> = processed_ok
            .into_iter()
            .map(Result::unwrap)
            .map(|des_event| -> Result<Vec<u8>, Error> {
                match des_event {
                    Deserialized::Event(ev) => {
                        let mut buf = vec![];
                        if let EventData::Icp(_) = ev.event.event.event.event_data {
                            if !self.processor.has_receipt(
                                &self.prefix,
                                0,
                                &ev.event.event.event.prefix,
                            )? {
                                buf.append(
                                    &mut self
                                        .processor
                                        .get_kerl(&self.prefix)?
                                        .ok_or(Error::Generic("KEL is empty".into()))?,
                                )
                            }
                        }
                        buf.append(
                            &mut self
                                .make_rct(ev.event.event.clone(), key_manager)?
                                .serialize()?,
                        );
                        Ok(buf)
                    }
                    _ => Ok(vec![]),
                }
            })
            .filter_map(|x| x.ok())
            .flatten()
            .collect();
        Ok(response)
    }

    fn make_rct<K: KeyManager>(
        &self,
        event: EventMessage,
        key_manager: &K,
    ) -> Result<SignedEventMessage, Error> {
        let ser = event.serialize()?;
        let signature = key_manager.sign(&ser)?;
        let validator_event_seal = self
            .processor
            .get_last_establishment_event_seal(&self.prefix)?
            .ok_or(Error::Generic("No establishment event seal".into()))?;

        let rcp =
            event_generator::make_rct(event, validator_event_seal, self.get_state()?.unwrap())
                .unwrap();

        let rcp = rcp.sign(vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )]);
        self.processor
            .process(signed_message(&rcp.serialize()?).unwrap().1)?;

        Ok(rcp)
    }

    pub fn get_state(&self) -> Result<Option<IdentifierState>, Error> {
        self.processor
            .compute_state(&self.prefix)
            .map_err(|e| Error::KeriError(e))
    }

    pub fn get_kerl(&self) -> Result<Option<Vec<u8>>, Error> {
        self.processor
            .get_kerl(&self.prefix)
            .map_err(|e| Error::KeriError(e))
    }

    pub fn get_state_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.processor
            .compute_state(prefix)
            .map_err(|e| Error::KeriError(e))
    }

    pub fn get_state_for_seal(&self, seal: &EventSeal) -> Result<Option<IdentifierState>, Error> {
        self.processor
            .compute_state_at_sn(&seal.prefix, seal.sn)
            .map_err(|e| Error::KeriError(e))
    }
}
