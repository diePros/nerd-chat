//! Contact book + vault file. Everything secret lives in ONE encrypted vault; message history is
//! deliberately NOT persisted (no-cache principle): messages exist only in RAM.
#![forbid(unsafe_code)]

mod book;
pub mod history;
mod file;

pub use history::{Clock, History, Line, NoPlatformKeys, Persist, PlatformKeys, State, Swept, SystemClock, Tick, Unwrapped};
pub use book::{Contact, OutMsg, SavedMsg, Store, MAX_CONTACTS, MAX_NAME, MAX_OUTBOX, MAX_OUTBOX_TOTAL, MAX_SAVED, MAX_SAVED_TOTAL};
pub use file::{counter_path_for, read_regular_file, shred_file, OpenInfo, VaultFile};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invalid contact name")]
    BadName,
    #[error("a contact with that name already exists")]
    Duplicate,
    #[error("too many contacts")]
    TooMany,
    #[error("stored data is corrupt")]
    Corrupt,
    #[error("vault: {0}")]
    Vault(#[from] nerd_chat_vault::VaultError),
    #[error("file i/o: {0}")]
    Io(String),
    #[error("a vault already exists at that path (refusing to overwrite)")]
    Exists,
    #[error("the platform key store did not answer; the history file was left untouched")]
    KeysUnavailable,
    #[error("the history file is OLDER than what this vault last wrote: a copy of it was put back")]
    HistoryRolledBack,
    #[error("cancelled")]
    Cancelled,
    #[error("the saved messages are full ({MAX_SAVED} per contact, {} KiB in total): delete some first", MAX_SAVED_TOTAL / 1024)]
    SavedFull,
    #[error("the vault was written, but its rollback-counter file could not be: {0}")]
    CounterWrite(String),
    #[error("a message must be 1 byte to 32 KiB of text")]
    BadText,
    #[error("the encrypted outbox is full (50 texts per contact, 1 MiB in total) or the contact cannot receive: wait until earlier texts are confirmed")]
    OutboxFull,
    #[error("a rollback-counter file already exists for this path: the vault may have been deleted or the path is wrong. Refusing to create a new vault that would reset it (remove the counter file yourself if this is intentional)")]
    CounterExists,
}
