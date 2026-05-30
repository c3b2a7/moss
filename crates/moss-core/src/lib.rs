//! Core socket APIs for `moss`.
//!
//! This crate contains the reusable data model, Darwin socket query logic,
//! filter parser, and resolver helpers.
//!
//! # Examples
//!
//! List sockets with process information:
//!
//! ```no_run
//! use moss::{SocketQuery, list_sockets};
//!
//! let query = SocketQuery {
//!     include_processes: true,
//!     ..SocketQuery::default()
//! };
//! let sockets = list_sockets(query)?;
//! # Ok::<(), moss::Error>(())
//! ```
//!
//! Parse an `ss`-style destination-port filter:
//!
//! ```no_run
//! use moss::{FilterExpression, SocketFilter, SocketQuery, filter_sockets, list_sockets};
//!
//! let expression = FilterExpression::parse(&["dport = :443".to_string()])?;
//! let filter = SocketFilter {
//!     expression,
//!     all: true,
//!     ..SocketFilter::default()
//! };
//!
//! let sockets = filter_sockets(list_sockets(SocketQuery::default())?, &filter);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Build a filter expression programmatically:
//!
//! ```no_run
//! use moss::{CompareOp, EndpointSide, FilterExpression, Predicate};
//!
//! let expression = FilterExpression::Predicate(Predicate::Port {
//!     side: EndpointSide::Peer,
//!     op: CompareOp::Eq,
//!     port: 443,
//! });
//! ```
//!
//! # Modules
//!
//! - [`model`] defines socket, endpoint, protocol, process, and memory types.
//! - [`platform`] queries macOS socket state.
//! - [`filter`] parses and applies `ss`-style filter expressions.
//! - [`resolver`] resolves host names and service names.

pub mod filter;
pub mod model;
pub mod platform;
pub mod resolver;

pub use filter::{
    AddressMatcher, CompareOp, EndpointSide, FilterExpression, IpNetwork, PathMatcher, Predicate,
    SocketFilter, filter_sockets,
};
pub use model::{
    AddressFamily, Endpoint, ProcessInfo, Protocol, SocketAddress, SocketInfo, SocketMemory,
    TcpState,
};
pub use platform::{Error, SocketQuery, list_sockets};
pub use resolver::{
    Resolver, ResolverConfig, hostname_lookup, service_name_lookup, service_port_lookup,
};
