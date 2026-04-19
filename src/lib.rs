//! Async Rust client for VPP's binary API over Unix domain sockets.
//!
//! This crate provides a typed, async interface to VPP's binary API,
//! replacing the fragile vppctl text-parsing approach. It communicates
//! via the Unix socket at `/run/vpp/core-api.sock` using VPP's native
//! wire protocol (16-byte framed, big-endian packed structs).
//!
//! # Architecture
//!
//! - **codec**: Wire format encoding/decoding (framing headers, BE serialization)
//! - **client**: Async connection management, request/reply dispatch, dump sequences
//! - **event**: Event subscription streams (want_interface_events, etc.)
//! - **message**: `VppMessage` trait implemented by all generated message types
//! - **generated**: Auto-generated message structs from VPP's `.api.json` files

pub mod client;
pub mod codec;
pub mod error;
pub mod event;
pub mod message;

pub mod generated;

pub use client::VppClient;
pub use error::VppError;
pub use message::VppMessage;
