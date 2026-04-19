//! VPP event subscription handling.
//!
//! VPP uses a `want_*` registration pattern: the client sends a registration
//! message (e.g., `want_interface_events`), and VPP asynchronously pushes
//! event messages thereafter. These arrive on the same socket connection,
//! identified by their msg_id.

use std::collections::HashSet;

/// A raw VPP event received from the background reader.
#[derive(Debug, Clone)]
pub struct VppEvent {
    /// The numeric message ID of this event.
    pub msg_id: u16,
    /// The raw payload bytes (after the common header).
    pub payload: Vec<u8>,
}

/// Tracks which message IDs are registered as event types.
///
/// The background reader uses this to distinguish async events
/// from request/reply responses.
#[derive(Debug, Default)]
pub struct EventRegistry {
    event_msg_ids: HashSet<u16>,
}

impl EventRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a message ID as an event type.
    pub fn register(&mut self, msg_id: u16) {
        self.event_msg_ids.insert(msg_id);
    }

    /// Check if a message ID is a registered event type.
    pub fn is_event(&self, msg_id: u16) -> bool {
        self.event_msg_ids.contains(&msg_id)
    }
}
