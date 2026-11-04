//! How far a contact's identity has been authenticated. Never collapse these into one bool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Trust {
    /// Imported from a file/paste, or paired with a code that travelled over a weak channel.
    Unverified,
    /// Paired over the local link with a one-time code exchanged in person. Anyone who learned the code could have been the peer.
    CodeAuthenticated,
    /// The user compared the combined safety number out-of-band.
    SafetyVerified,
}
