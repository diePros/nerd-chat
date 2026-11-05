//! Chat engine: online-only, serverless, RAM-only messaging between pinned contacts.
//!  * `proto`     message framing on top of signed+encrypted cells (text chunks, keepalive)
//!  * `transport` how streams reach a contact (Tor onion services, or an in-memory test network)
//!  * `conn`      one authenticated connection (polled cell reader, keepalive, idle timeout)
//!  * `engine`    the supervisor thread: who dials, reconnects with backoff, RAM outbox, events for the UI
//! Nothing here ever touches the disk: messages live in RAM only and are wiped when dropped.
#![forbid(unsafe_code)]

pub mod conn;
pub mod engine;
pub mod file;
pub mod proto;
pub mod transport;

pub use conn::FileOut;
pub use engine::{we_dial, Command, ContactCfg, Engine, Event, Timing};
pub use transport::{MemNet, Transport};
