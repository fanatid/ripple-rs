#![warn(elided_lifetimes_in_paths)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(unused_results)]

//! Ripple protocol messages in [protobuf](https://developers.google.com/protocol-buffers).

use bytes::Buf;
use prost::{DecodeError, Message as _};

pub mod proto;

/// All possible messages in protocol
#[allow(missing_docs)] // TODO: remove
#[derive(Debug)]
pub enum Message {
    Manifests(proto::TmManifests),
    Ping(proto::TmPing),
    Cluster(proto::TmCluster),
    Endpoints(proto::TmEndpoints),
    Transaction(proto::TmTransaction),
    GetLedger(proto::TmGetLedger),
    LedgerData(proto::TmLedgerData),
    ProposeLedger(proto::TmProposeSet),
    StatusChange(proto::TmStatusChange),
    HaveSet(proto::TmHaveTransactionSet),
    Validation(proto::TmValidation),
    GetObjects(proto::TmGetObjectByHash),
    GetShardInfo(proto::TmGetShardInfo),
    ShardInfo(proto::TmShardInfo),
    GetPeerShardInfo(proto::TmGetPeerShardInfo),
    PeerShardInfo(proto::TmPeerShardInfo),
    Validatorlist(proto::TmValidatorList),
}

impl Message {
    /// Decode [`Buf`][bytes::Buf] to [`Message`][Message].
    /// First 2 bytes in buffer is message type, rest is encoded message.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        use proto::MessageType;

        let message_type = buf.get_u16() as i32;
        let message_type = MessageType::from_i32(message_type).expect("Invalid message type");

        let msg = match message_type {
            MessageType::MtManifests => Message::Manifests(proto::TmManifests::decode(buf)?),
            MessageType::MtPing => Message::Ping(proto::TmPing::decode(buf)?),
            MessageType::MtCluster => Message::Cluster(proto::TmCluster::decode(buf)?),
            MessageType::MtEndpoints => Message::Endpoints(proto::TmEndpoints::decode(buf)?),
            MessageType::MtTransaction => Message::Transaction(proto::TmTransaction::decode(buf)?),
            MessageType::MtGetLedger => Message::GetLedger(proto::TmGetLedger::decode(buf)?),
            MessageType::MtLedgerData => Message::LedgerData(proto::TmLedgerData::decode(buf)?),
            MessageType::MtProposeLedger => {
                Message::ProposeLedger(proto::TmProposeSet::decode(buf)?)
            }
            MessageType::MtStatusChange => {
                Message::StatusChange(proto::TmStatusChange::decode(buf)?)
            }
            MessageType::MtHaveSet => Message::HaveSet(proto::TmHaveTransactionSet::decode(buf)?),
            MessageType::MtValidation => Message::Validation(proto::TmValidation::decode(buf)?),
            MessageType::MtGetObjects => {
                Message::GetObjects(proto::TmGetObjectByHash::decode(buf)?)
            }
            MessageType::MtGetShardInfo => {
                Message::GetShardInfo(proto::TmGetShardInfo::decode(buf)?)
            }
            MessageType::MtShardInfo => Message::ShardInfo(proto::TmShardInfo::decode(buf)?),
            MessageType::MtGetPeerShardInfo => {
                Message::GetPeerShardInfo(proto::TmGetPeerShardInfo::decode(buf)?)
            }
            MessageType::MtPeerShardInfo => {
                Message::PeerShardInfo(proto::TmPeerShardInfo::decode(buf)?)
            }
            MessageType::MtValidatorlist => {
                Message::Validatorlist(proto::TmValidatorList::decode(buf)?)
            }
        };

        Ok(msg)
    }
}
