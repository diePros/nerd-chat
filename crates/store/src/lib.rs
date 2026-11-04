//! Contact book + vault file. Everything secret lives in ONE encrypted vault; message history is
//! deliberately NOT persisted (no-cache principle): messages exist only in RAM.
#![forbid(unsafe_code)]

mod book;
mod file;

pub use book::{Contact, Store, MAX_CONTACTS, MAX_NAME};
pub use file::{read_regular_file, OpenInfo, VaultFile};

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
    Vault(#[from] seburity_vault::VaultError),
    #[error("file i/o: {0}")]
    Io(String),
    #[error("a vault already exists at that path (refusing to overwrite)")]
    Exists,
    #[error("a rollback-counter file already exists for this path: the vault may have been deleted or the path is wrong. Refusing to create a new vault that would reset it (remove the counter file yourself if this is intentional)")]
    CounterExists,
}
