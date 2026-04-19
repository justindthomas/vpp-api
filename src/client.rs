//! Async VPP binary API client.
//!
//! Connects to VPP's Unix domain socket, performs the handshake to build
//! the message table, and provides typed request/reply and dump operations.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::net::UnixStream;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};

use crate::codec;
use crate::error::VppError;
use crate::event::{EventRegistry, VppEvent};
use crate::generated::vpe::*;
use crate::message::VppMessage;

/// Default VPP binary API socket path.
pub const DEFAULT_API_SOCKET: &str = "/run/vpp/core-api.sock";

/// A pending reply channel — either single (request/reply) or multi (dump).
enum PendingReply {
    Single(oneshot::Sender<Vec<u8>>),
    Multi(mpsc::Sender<Vec<u8>>),
}

/// Async VPP binary API client.
pub struct VppClient {
    writer: Arc<Mutex<tokio::net::unix::OwnedWriteHalf>>,
    client_index: u32,
    msg_table: HashMap<String, u16>,
    msg_table_rev: HashMap<u16, String>,
    next_context: AtomicU32,
    pending: Arc<Mutex<HashMap<u32, PendingReply>>>,
    event_tx: broadcast::Sender<VppEvent>,
    event_registry: Arc<Mutex<EventRegistry>>,
    _reader_handle: tokio::task::JoinHandle<()>,
}

impl VppClient {
    /// Connect to VPP and perform the handshake.
    pub async fn connect(socket_path: &str) -> Result<Self, VppError> {
        let stream = UnixStream::connect(socket_path).await?;
        let (read_half, write_half) = stream.into_split();
        let mut stream = read_half
            .reunite(write_half)
            .map_err(|_| VppError::Handshake("failed to reunite stream halves".into()))?;

        let (client_index, msg_table, msg_table_rev) = Self::handshake(&mut stream).await?;

        tracing::info!(
            client_index,
            msg_count = msg_table.len(),
            "VPP handshake complete"
        );

        let (read_half, write_half) = stream.into_split();
        let writer = Arc::new(Mutex::new(write_half));
        let pending: Arc<Mutex<HashMap<u32, PendingReply>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (event_tx, _) = broadcast::channel(256);
        let event_registry = Arc::new(Mutex::new(EventRegistry::new()));

        let reader_handle = tokio::spawn(Self::reader_loop(
            read_half,
            pending.clone(),
            event_tx.clone(),
            event_registry.clone(),
        ));

        Ok(VppClient {
            writer,
            client_index,
            msg_table,
            msg_table_rev,
            next_context: AtomicU32::new(1),
            pending,
            event_tx,
            event_registry,
            _reader_handle: reader_handle,
        })
    }

    /// Perform the initial handshake.
    async fn handshake(
        stream: &mut UnixStream,
    ) -> Result<(u32, HashMap<String, u16>, HashMap<u16, String>), VppError> {
        let msg = SockclntCreate {
            name: "imp-vpp-api".to_string(),
        };

        // sockclnt_create has a special header: msg_id(u16) + context(u32), no client_index.
        let mut payload = Vec::new();
        payload.extend_from_slice(&SOCKCLNT_CREATE_MSG_ID.to_be_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        msg.encode_fields(&mut payload);

        codec::write_frame(stream, &payload).await?;

        // sockclnt_create_reply has the full 10-byte header (msg_id + client_index + context).
        let reply_payload = codec::read_frame(stream).await?;
        let reply_fields = &reply_payload[codec::REQ_HEADER_SIZE..];
        let reply = SockclntCreateReply::decode_fields(reply_fields)?;

        if reply.response != 0 {
            return Err(VppError::Handshake(format!(
                "sockclnt_create failed: response={}",
                reply.response
            )));
        }

        let mut msg_table = HashMap::new();
        let mut msg_table_rev = HashMap::new();
        for entry in &reply.message_table {
            msg_table.insert(entry.name.clone(), entry.index);
            msg_table_rev.insert(entry.index, entry.name.clone());
        }

        Ok((reply.index, msg_table, msg_table_rev))
    }

    /// Background reader loop.
    async fn reader_loop(
        mut reader: tokio::net::unix::OwnedReadHalf,
        pending: Arc<Mutex<HashMap<u32, PendingReply>>>,
        event_tx: broadcast::Sender<VppEvent>,
        event_registry: Arc<Mutex<EventRegistry>>,
    ) {
        loop {
            let frame = match read_frame_from_reader(&mut reader).await {
                Ok(frame) => frame,
                Err(VppError::ConnectionClosed) => {
                    tracing::info!("VPP connection closed");
                    break;
                }
                Err(e) => {
                    tracing::error!("VPP read error: {}", e);
                    break;
                }
            };

            if frame.len() < codec::REPLY_HEADER_SIZE {
                tracing::warn!("received short frame ({} bytes), skipping", frame.len());
                continue;
            }

            // Reply header: msg_id(2) + context(4)
            let msg_id = u16::from_be_bytes([frame[0], frame[1]]);
            let context = u32::from_be_bytes([frame[2], frame[3], frame[4], frame[5]]);

            tracing::debug!(msg_id, context, frame_len = frame.len(), "received frame");

            // Check if this is a registered event
            if event_registry.lock().await.is_event(msg_id) {
                let event = VppEvent {
                    msg_id,
                    payload: frame[codec::REPLY_HEADER_SIZE..].to_vec(),
                };
                let _ = event_tx.send(event);
                continue;
            }

            // Dispatch to pending request
            let mut map = pending.lock().await;
            if let Some(entry) = map.get(&context) {
                match entry {
                    PendingReply::Single(_) => {
                        // Take ownership and send
                        if let Some(PendingReply::Single(tx)) = map.remove(&context) {
                            let _ = tx.send(frame);
                        }
                    }
                    PendingReply::Multi(tx) => {
                        // Clone sender and send — don't remove (more messages may come)
                        let tx = tx.clone();
                        drop(map); // Release lock before async send
                        let _ = tx.send(frame).await;
                    }
                }
            } else {
                tracing::trace!(msg_id, context, "unmatched message");
            }
        }
    }

    /// Look up the runtime message ID for a message type.
    pub fn resolve_msg_id<M: VppMessage>(&self) -> Result<u16, VppError> {
        let name_crc = M::name_crc();
        self.msg_table
            .get(&name_crc)
            .copied()
            .ok_or_else(|| VppError::UnknownMessage(name_crc))
    }

    /// Send a request and wait for the reply.
    pub async fn request<Req: VppMessage, Reply: VppMessage>(
        &self,
        req: Req,
    ) -> Result<Reply, VppError> {
        let msg_id = self.resolve_msg_id::<Req>()?;
        let context = self.next_context.fetch_add(1, Ordering::Relaxed);

        tracing::debug!(
            msg_name = Req::NAME,
            msg_id,
            context,
            "sending request"
        );

        let mut payload = codec::encode_msg_header(msg_id, self.client_index, context);
        req.encode_fields(&mut payload);

        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .await
            .insert(context, PendingReply::Single(tx));

        {
            let mut writer = self.writer.lock().await;
            write_frame_to_writer(&mut *writer, &payload).await?;
        }

        let reply_frame = rx.await.map_err(|_| VppError::ConnectionClosed)?;
        let reply_fields = &reply_frame[codec::REPLY_HEADER_SIZE..];
        Reply::decode_fields(reply_fields)
    }

    /// Send a dump request and collect all detail replies.
    ///
    /// VPP dump sequences:
    /// 1. Send the dump request
    /// 2. VPP sends N detail messages (all with the dump request's context)
    /// 3. We send a control_ping
    /// 4. VPP replies with control_ping_reply (with ping's context) to signal end
    pub async fn dump<Req: VppMessage, Detail: VppMessage>(
        &self,
        req: Req,
    ) -> Result<Vec<Detail>, VppError> {
        let dump_msg_id = self.resolve_msg_id::<Req>()?;
        let ping_msg_id = self.resolve_msg_id::<ControlPing>()?;
        let dump_context = self.next_context.fetch_add(1, Ordering::Relaxed);
        let ping_context = self.next_context.fetch_add(1, Ordering::Relaxed);

        // Register an mpsc channel for dump detail replies
        let (detail_tx, mut detail_rx) = mpsc::channel::<Vec<u8>>(512);
        self.pending
            .lock()
            .await
            .insert(dump_context, PendingReply::Multi(detail_tx));

        // Register a oneshot for the ping reply (end-of-dump marker)
        let (ping_tx, ping_rx) = oneshot::channel();
        self.pending
            .lock()
            .await
            .insert(ping_context, PendingReply::Single(ping_tx));

        // Send dump request
        let mut dump_payload =
            codec::encode_msg_header(dump_msg_id, self.client_index, dump_context);
        req.encode_fields(&mut dump_payload);

        // Send control_ping immediately after
        let ping_payload =
            codec::encode_msg_header(ping_msg_id, self.client_index, ping_context);

        {
            let mut writer = self.writer.lock().await;
            write_frame_to_writer(&mut *writer, &dump_payload).await?;
            write_frame_to_writer(&mut *writer, &ping_payload).await?;
        }

        // Collect detail messages until ping reply arrives
        let mut details = Vec::new();
        tokio::pin!(let ping_fut = ping_rx;);

        loop {
            tokio::select! {
                biased; // Prefer detail messages over ping
                frame = detail_rx.recv() => {
                    match frame {
                        Some(f) => {
                            let fields = &f[codec::REPLY_HEADER_SIZE..];
                            match Detail::decode_fields(fields) {
                                Ok(detail) => details.push(detail),
                                Err(e) => {
                                    tracing::warn!("failed to decode dump detail: {}", e);
                                }
                            }
                        }
                        None => break,
                    }
                }
                _ = &mut ping_fut => {
                    // Drain any remaining detail messages that arrived before ping
                    while let Ok(f) = detail_rx.try_recv() {
                        let fields = &f[codec::REPLY_HEADER_SIZE..];
                        if let Ok(detail) = Detail::decode_fields(fields) {
                            details.push(detail);
                        }
                    }
                    break;
                }
            }
        }

        // Clean up
        self.pending.lock().await.remove(&dump_context);

        Ok(details)
    }

    /// Register a message ID as an event type.
    pub async fn register_event<M: VppMessage>(&self) -> Result<(), VppError> {
        let msg_id = self.resolve_msg_id::<M>()?;
        self.event_registry.lock().await.register(msg_id);
        Ok(())
    }

    /// Subscribe to the event broadcast channel.
    pub fn subscribe_events(&self) -> broadcast::Receiver<VppEvent> {
        self.event_tx.subscribe()
    }

    /// Get the client index assigned by VPP during handshake.
    pub fn client_index(&self) -> u32 {
        self.client_index
    }

    /// Get the message table.
    pub fn message_table(&self) -> &HashMap<String, u16> {
        &self.msg_table
    }

    /// Look up a message name by its runtime ID.
    pub fn msg_name(&self, msg_id: u16) -> Option<&str> {
        self.msg_table_rev.get(&msg_id).map(|s| s.as_str())
    }
}

/// Read a frame from an OwnedReadHalf.
async fn read_frame_from_reader(
    reader: &mut tokio::net::unix::OwnedReadHalf,
) -> Result<Vec<u8>, VppError> {
    use tokio::io::AsyncReadExt;

    let mut header = [0u8; codec::HEADER_SIZE];
    reader.read_exact(&mut header).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            VppError::ConnectionClosed
        } else {
            VppError::Io(e)
        }
    })?;

    let payload_len =
        u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;

    if payload_len == 0 {
        return Ok(Vec::new());
    }

    if payload_len > 1_048_576 {
        return Err(VppError::Decode(format!(
            "frame payload too large: {} bytes",
            payload_len
        )));
    }

    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            VppError::ConnectionClosed
        } else {
            VppError::Io(e)
        }
    })?;

    Ok(payload)
}

/// Write a frame to an OwnedWriteHalf.
async fn write_frame_to_writer(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    payload: &[u8],
) -> Result<(), VppError> {
    use tokio::io::AsyncWriteExt;

    let frame = codec::encode_frame(payload);
    writer.write_all(&frame).await?;
    Ok(())
}
