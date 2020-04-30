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

#![feature(cell_leak)]

use std::cell::{Ref, RefCell};
use std::net::SocketAddr;

use bytes::{Buf, BufMut};
use prost::Message as _;
pub use prost::{DecodeError, EncodeError};

use ripple::{tm_endpoints::TmEndpointv2, tm_ping::PingType, *};

// Export `prost` generated enums/structs.
pub mod ripple;

/// Encode/Decode trait.
pub trait EncodeDecode {
    /// Encode/decode trait for type.
    type Type;

    /// Returns the encoded length of the message.
    fn encoded_len(&self) -> usize;

    /// Encode the message to a buffer.
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError>;

    /// Decode an intsance of the message from a buffer.
    fn decode<B: Buf>(buf: &mut B) -> Result<Self::Type, DecodeError>;
}

// Implement EncodeDecode trait for struct.
macro_rules! impl_encode_decode {
    ($type:ty, $inner:ty) => {
        impl EncodeDecode for $type {
            type Type = $type;

            fn encoded_len(&self) -> usize {
                self.to_inner().encoded_len()
            }

            fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
                self.to_inner().encode(buf)
            }

            fn decode<B: Buf>(buf: &mut B) -> Result<Self::Type, DecodeError> {
                let inner = <$inner>::decode(buf)?;
                Ok(Self::Type::from_inner(inner))
            }
        }
    };
}

// Default functions for manipulating with inner.
macro_rules! impl_inner_fns {
    ($type:ty, $inner:ty) => {
        impl $type {
            fn from_inner(inner: $inner) -> Self {
                Self { inner }
            }

            fn to_inner(&self) -> &$inner {
                &self.inner
            }
        }
    };
}

/// All possible messages in protocol
#[derive(Debug)]
pub enum Message {
    /// Validators manifests. On protocol start all known manifest sent to connected peer.
    /// If peer receive new manifest it's can be resent to other peers.
    Manifests(TmManifests),
    /// Ping/Pong messages. It's not required sent pings, but we always should send pong as reply.
    /// If pong will not be received during few timer triggers connection will be closed.
    /// By default, timer interval is 8s, no ping limit is 10, i.e. limit is 80s.
    PingPong(PingPong),
    /// Cluster related. Ignore.
    Cluster(TmCluster),
    /// Receive other peers endpoints. Rippled sent such message every ~1s.
    Endpoints(Endpoints),
    /// Relayed transaction. Need more info.
    Transaction(TmTransaction),
    /// Request ledger information, can be relayed. Need more info.
    GetLedger(TmGetLedger),
    /// Response on ledger request. Need more info.
    LedgerData(TmLedgerData),
    /// Not sure. Need more info.
    ProposeLedger(TmProposeSet),
    /// Peer status. Connection will be dropped in outgoing peer will not sent status after some time.
    StatusChange(TmStatusChange),
    /// Transactions set with root hash. Need more info.
    HaveSet(TmHaveTransactionSet),
    /// Need more info.
    Validation(TmValidation),
    /// Request/Response of different data.
    Objects(TmGetObjectByHash),
    /// Deprecated.
    GetShardInfo(TmGetShardInfo),
    /// Deprecated.
    ShardInfo(TmShardInfo),
    /// Request information about shards. Ignore.
    GetPeerShardInfo(TmGetPeerShardInfo),
    /// Response on request about shards. Ignore.
    PeerShardInfo(TmPeerShardInfo),
    /// Validators list. Supported from XRPL/1.2. Sent on startup. Can be relayed on receiving to
    /// peers who have old validator sequence.
    Validatorlist(TmValidatorList),
}

impl Message {
    /// Check that message type is valid.
    pub fn is_valid_type<B: Buf>(buf: &B) -> bool {
        let bytes = buf.bytes();
        let ty = ((bytes[0] as u16) << 8) + (bytes[1] as u16);
        MessageType::is_valid(ty as i32)
    }
}

impl EncodeDecode for Message {
    type Type = Message;

    /// Returns the encoded length of the message.
    fn encoded_len(&self) -> usize {
        2 + match *self {
            Self::Manifests(ref v) => v.encoded_len(),
            Self::PingPong(ref v) => v.encoded_len(),
            Self::Cluster(ref v) => v.encoded_len(),
            Self::Endpoints(ref v) => v.encoded_len(),
            Self::Transaction(ref v) => v.encoded_len(),
            Self::GetLedger(ref v) => v.encoded_len(),
            Self::LedgerData(ref v) => v.encoded_len(),
            Self::ProposeLedger(ref v) => v.encoded_len(),
            Self::StatusChange(ref v) => v.encoded_len(),
            Self::HaveSet(ref v) => v.encoded_len(),
            Self::Validation(ref v) => v.encoded_len(),
            Self::Objects(ref v) => v.encoded_len(),
            Self::GetShardInfo(ref v) => v.encoded_len(),
            Self::ShardInfo(ref v) => v.encoded_len(),
            Self::GetPeerShardInfo(ref v) => v.encoded_len(),
            Self::PeerShardInfo(ref v) => v.encoded_len(),
            Self::Validatorlist(ref v) => v.encoded_len(),
        }
    }

    /// Encode the message to a buffer.
    fn encode<B: BufMut>(&self, buf: &mut B) -> Result<(), EncodeError> {
        use MessageType::*;

        let message_type = match *self {
            Self::Manifests(_) => MtManifests,
            Self::PingPong(_) => MtPing,
            Self::Cluster(_) => MtCluster,
            Self::Endpoints(_) => MtEndpoints,
            Self::Transaction(_) => MtTransaction,
            Self::GetLedger(_) => MtGetLedger,
            Self::LedgerData(_) => MtLedgerData,
            Self::ProposeLedger(_) => MtProposeLedger,
            Self::StatusChange(_) => MtStatusChange,
            Self::HaveSet(_) => MtHaveSet,
            Self::Validation(_) => MtValidation,
            Self::Objects(_) => MtGetObjects,
            Self::GetShardInfo(_) => MtGetPeerShardInfo,
            Self::ShardInfo(_) => MtShardInfo,
            Self::GetPeerShardInfo(_) => MtGetPeerShardInfo,
            Self::PeerShardInfo(_) => MtPeerShardInfo,
            Self::Validatorlist(_) => MtValidatorlist,
        };
        buf.put_u16(message_type as u16);

        match *self {
            Self::Manifests(ref v) => v.encode(buf),
            Self::PingPong(ref v) => v.encode(buf),
            Self::Cluster(ref v) => v.encode(buf),
            Self::Endpoints(ref v) => v.encode(buf),
            Self::Transaction(ref v) => v.encode(buf),
            Self::GetLedger(ref v) => v.encode(buf),
            Self::LedgerData(ref v) => v.encode(buf),
            Self::ProposeLedger(ref v) => v.encode(buf),
            Self::StatusChange(ref v) => v.encode(buf),
            Self::HaveSet(ref v) => v.encode(buf),
            Self::Validation(ref v) => v.encode(buf),
            Self::Objects(ref v) => v.encode(buf),
            Self::GetShardInfo(ref v) => v.encode(buf),
            Self::ShardInfo(ref v) => v.encode(buf),
            Self::GetPeerShardInfo(ref v) => v.encode(buf),
            Self::PeerShardInfo(ref v) => v.encode(buf),
            Self::Validatorlist(ref v) => v.encode(buf),
        }
    }

    /// Decode an intsance of the message from a buffer.
    fn decode<B: Buf>(buf: &mut B) -> Result<Self::Type, DecodeError> {
        use MessageType::*;

        let message_type = buf.get_u16() as i32;
        let message_type = MessageType::from_i32(message_type)
            .ok_or_else(|| DecodeError::new("invalid message"))?;

        Ok(match message_type {
            MtManifests => Message::Manifests(TmManifests::decode(buf)?),
            MtPing => Message::PingPong(PingPong::decode(buf)?),
            MtCluster => Message::Cluster(TmCluster::decode(buf)?),
            MtEndpoints => Message::Endpoints(Endpoints::decode(buf)?),
            MtTransaction => Message::Transaction(TmTransaction::decode(buf)?),
            MtGetLedger => Message::GetLedger(TmGetLedger::decode(buf)?),
            MtLedgerData => Message::LedgerData(TmLedgerData::decode(buf)?),
            MtProposeLedger => Message::ProposeLedger(TmProposeSet::decode(buf)?),
            MtStatusChange => Message::StatusChange(TmStatusChange::decode(buf)?),
            MtHaveSet => Message::HaveSet(TmHaveTransactionSet::decode(buf)?),
            MtValidation => Message::Validation(TmValidation::decode(buf)?),
            MtGetObjects => Message::Objects(TmGetObjectByHash::decode(buf)?),
            MtGetShardInfo => Message::GetShardInfo(TmGetShardInfo::decode(buf)?),
            MtShardInfo => Message::ShardInfo(TmShardInfo::decode(buf)?),
            MtGetPeerShardInfo => Message::GetPeerShardInfo(TmGetPeerShardInfo::decode(buf)?),
            MtPeerShardInfo => Message::PeerShardInfo(TmPeerShardInfo::decode(buf)?),
            MtValidatorlist => Message::Validatorlist(TmValidatorList::decode(buf)?),
        })
    }
}

/// Ping/Pong message. This messages used for checking that connected peer is alive.
#[derive(Debug)]
pub struct PingPong {
    inner: TmPing,
}

impl_encode_decode!(PingPong, TmPing);
impl_inner_fns!(PingPong, TmPing);

impl PingPong {
    fn build(r#type: PingType, seq: Option<u32>) -> Self {
        let r#type = r#type as i32;
        Self::from_inner(TmPing {
            r#type,
            seq,
            ping_time: None,
            net_time: None,
        })
    }

    /// Build ping type.
    pub fn build_ping(seq: Option<u32>) -> Self {
        Self::build(PingType::PtPing, seq)
    }

    /// Build pong type.
    pub fn build_pong(seq: Option<u32>) -> Self {
        Self::build(PingType::PtPong, seq)
    }

    /// Return true if ping message.
    pub fn is_ping(&self) -> bool {
        self.inner.r#type() == PingType::PtPing
    }

    /// Return message sequence.
    pub fn sequence(&self) -> Option<u32> {
        self.inner.seq
    }
}

/// Represent exactly one endpoint.
#[allow(missing_docs)]
#[derive(Debug)]
pub struct Endpoint {
    pub addr: SocketAddr,
    pub hops: u32,
}

/// Endpoints message. TODO: more
#[derive(Debug)]
pub struct Endpoints {
    inner: RefCell<TmEndpoints>,
    /// Vec of [`Endpoint`][Endpoint].
    pub endpoints: Vec<Endpoint>,
}

impl_encode_decode!(Endpoints, TmEndpoints);

impl Default for Endpoints {
    fn default() -> Self {
        Self::from_inner(TmEndpoints {
            // Not used in rippled, but set to 2
            version: 2,
            endpoints: vec![],
            endpoints_v2: vec![],
        })
    }
}

impl Endpoints {
    fn from_inner(inner: TmEndpoints) -> Self {
        // We ignore `endpoints`, because they outdated.
        // `endpoints_v2` have both IPv4 & IPv6.
        let endpoints = inner
            .endpoints_v2
            .iter()
            .filter_map(|s| {
                s.endpoint
                    .parse::<SocketAddr>()
                    .map(|addr| Endpoint { addr, hops: s.hops })
                    .ok()
            })
            .collect();

        Self {
            inner: RefCell::new(inner),
            endpoints,
        }
    }

    fn to_inner(&self) -> &TmEndpoints {
        self.inner.borrow_mut().endpoints_v2 = self
            .endpoints
            .iter()
            .map(|s| TmEndpointv2 {
                endpoint: s.addr.to_string(),
                hops: s.hops,
            })
            .collect();

        Ref::leak(self.inner.borrow())
    }
}
