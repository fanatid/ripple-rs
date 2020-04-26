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
#[derive(Debug)]
pub enum Message {
    /// Validators manifests. On protocol start all known manifest sent to connected peer.
    /// If peer receive new manifest it's can be resent to other peers.
    Manifests(proto::TmManifests),
    /// Ping/Pong messages. It's not required sent pings, but we always should send pong as reply.
    /// If pong will not be received during few timer triggers connection will be closed.
    /// By default, timer interval is 8s, no ping limit is 10, i.e. limit is 80s.
    Ping(proto::TmPing),
    /// Cluster related. Ignore.
    Cluster(proto::TmCluster),
    /// Receive other peers endpoints. Rippled sent such message every ~1s.
    Endpoints(proto::TmEndpoints),
    /// Relayed transaction. Need more info.
    Transaction(proto::TmTransaction),
    /// Request ledger information, can be relayed. Need more info.
    GetLedger(proto::TmGetLedger),
    /// Response on ledger request. Need more info.
    LedgerData(proto::TmLedgerData),
    /// Not sure. Need more info.
    ProposeLedger(proto::TmProposeSet),
    /// Peer status. Connection will be dropped in outgoing peer will not sent status after some time.
    StatusChange(proto::TmStatusChange),
    /// Transactions set with root hash. Need more info.
    HaveSet(proto::TmHaveTransactionSet),
    /// Need more info.
    Validation(proto::TmValidation),
    /// Request/Response of different data.
    GetObjects(proto::TmGetObjectByHash),
    /// Deprecated.
    GetShardInfo(proto::TmGetShardInfo),
    /// Deprecated.
    ShardInfo(proto::TmShardInfo),
    /// Request information about shards. Ignore.
    GetPeerShardInfo(proto::TmGetPeerShardInfo),
    /// Response on request about shards. Ignore.
    PeerShardInfo(proto::TmPeerShardInfo),
    /// Validators list. Supported from XRPL/1.2. Sent on startup. Can be relayed on receiving to
    /// peers who have old validator sequence.
    Validatorlist(proto::TmValidatorList),
}

impl Message {
    /// Decode [`Buf`][bytes::Buf] to [`Message`][Message].
    /// First 2 bytes in buffer is message type, rest is encoded message.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, DecodeError> {
        use proto::MessageType;

        let message_type = buf.get_u16() as i32;
        let message_type = MessageType::from_i32(message_type)
            .ok_or_else(|| DecodeError::new("invalid message"))?;

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
