use std::io;

/// Errors that can occur when communicating with VPP.
#[derive(Debug, thiserror::Error)]
pub enum VppError {
    /// I/O error on the Unix socket.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// VPP returned an error response code.
    #[error("VPP API error: retval={retval} for {message}")]
    ApiError { retval: i32, message: String },

    /// Failed to decode a message from the wire.
    #[error("decode error: {0}")]
    Decode(String),

    /// Failed to encode a message for the wire.
    #[error("encode error: {0}")]
    Encode(String),

    /// Message ID not found in the message table after handshake.
    #[error("unknown message: {0}")]
    UnknownMessage(String),

    /// Handshake with VPP failed.
    #[error("handshake failed: {0}")]
    Handshake(String),

    /// The connection was closed.
    #[error("connection closed")]
    ConnectionClosed,

    /// A request timed out waiting for a reply.
    #[error("request timed out")]
    Timeout,
}
