use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[cfg(feature = "storage")]
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("crypto: {0}")]
    Crypto(String),

    #[error("malformed: {0}")]
    Malformed(&'static str),

    /// A policy/limit violation on the local SQLite side (e.g. the snapshot is too
    /// large). `Sqlite` is for raw backend errors; this variant is a deliberate reject.
    #[error("storage: {0}")]
    Storage(String),

    /// The backup file could not be opened: wrong recovery key (or a corrupt file).
    ///
    /// Kept separate from `Malformed` because the UI explains the two cases differently
    /// ("check your key" vs. "this is not a backup file"). The distinction has to travel as a
    /// CODE: when it travelled as a sentence, Dart drew it with `contains(...)` and rewording
    /// the sentence silently broke the UI.
    #[error("backup/wrong-key")]
    BackupWrongKey,

    /// No `ServerCtx` for this server id — it is not attached (logged out, detached, or the id is
    /// wrong). The UI's answer differs from every other failure: there is nothing to retry, the
    /// user has to attach the server.
    ///
    /// It is a code and not a sentence for the reason `backup/wrong-key` gives: a sentence cannot
    /// be localized once it has left Rust, and the FRB waist carries all of them through one
    /// `Result<_, String>`, so prose here is text the UI can only print verbatim or grep.
    #[error("server/not-attached")]
    ServerNotAttached,

    /// The kernel actor is gone: its task ended, or the oneshot reply channel was dropped before an
    /// answer arrived. Distinct from `ServerNotAttached` — nothing about the server is wrong, the
    /// process-local kernel is simply no longer there, and the UI's honest move is to say so rather
    /// than to blame the connection.
    #[error("kernel/closed")]
    KernelClosed,

    /// The display name the user typed is empty, or is nothing but characters `sanitize_display_name`
    /// strips. Their move: type a different name — so unlike the validation failures around it, this
    /// one has to be readable in their language.
    #[error("profile/display-name-invalid")]
    DisplayNameInvalid,

    /// An HTML card is over the 16 KB the transport accepts. The detail carries the two sizes, which
    /// are numbers and need no translation.
    #[error("message/html-too-large: {actual_kb} KB > {limit_kb} KB")]
    HtmlMessageTooLarge { actual_kb: usize, limit_kb: usize },

    /// A photo's, file's or voice note's caption is over the core's character limit. Its move:
    /// shorten it. The detail carries the two counts, which are numbers and need no translation.
    #[error("message/caption-too-long: {chars} > {limit} characters")]
    CaptionTooLong { chars: usize, limit: usize },

    /// A contact request addressed to the sender's own account. Reachable from the UI by scanning
    /// your own code, so it is a thing a person does, not a bug.
    #[error("contact/self-request")]
    ContactSelfRequest,

    /// "Delete for everyone" was asked for on a message older than the window the server's owner
    /// configured, so the peer-facing delete marker was NOT sent. The local copy and the sender's
    /// own other devices are still deleted — only the recipient keeps theirs.
    ///
    /// It is a code and not a sentence for the usual reason, plus one specific to this gate: the
    /// window is per-server policy, so the same action succeeds on one server and is refused on
    /// the next, and the person has to be told which happened in their own language. It must also
    /// stay an ERROR rather than a log line — silence here means the bubble vanishes from the
    /// sender's screen and stays on the recipient's, with nothing said anywhere.
    #[error("delete-for-everyone/window-expired")]
    DeleteForEveryoneWindowExpired,

    /// A scanned QR did not parse as a device-link payload — a photo of the wrong thing, a damaged
    /// code, or one from another app.
    #[error("qr/undecodable: {0}")]
    QrUndecodable(String),

    /// The file is not a Sezi backup (or not a backup of the expected kind).
    #[error("backup/not-a-backup")]
    BackupNotRecognized,

    #[error("pickle: {0}")]
    Pickle(#[from] vodozemac::PickleError),

    #[error("session-create: {0}")]
    SessionCreate(#[from] vodozemac::olm::SessionCreationError),

    #[error("encrypt: {0}")]
    Encrypt(#[from] vodozemac::olm::EncryptionError),

    #[error("decrypt: {0}")]
    Decrypt(#[from] vodozemac::olm::DecryptionError),

    #[error("key: {0}")]
    Key(#[from] vodozemac::KeyError),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("session not found for peer {0}")]
    NoSession(String),

    #[cfg(feature = "client")]
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    // Native only: tokio-tungstenite needs a real socket and has no browser story, so it is the
    // crate that keeps `tokio/net` — and therefore `mio` — in front of every wasm build. The
    // browser's transport is `web-sys::WebSocket` (`client/sync_web.rs`) and it reports through
    // `Error::Crypto`, because what a browser hands back is a `JsValue` with no structure to map
    // onto tungstenite's variants — it will not even say WHY a handshake failed.
    #[cfg(all(feature = "client", not(target_arch = "wasm32")))]
    #[error("ws: {0}")]
    Ws(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("api: {status} {message}")]
    Api { status: u16, message: String },

    /// A `429` from one of the auth door's three requests (redeem, verify, `/bootstrap`), with the
    /// wait the relay's `Retry-After` named, in seconds — `None` when it named none. The door
    /// counts down to it instead of saying "a few minutes".
    ///
    /// Produced by THOSE calls only (`client::api::decode_door`), never by the shared decoder:
    /// every other caller recognises its own rate limit as `Api { status: 429, .. }`, and turning
    /// that into a second shape everywhere would quietly stop each of them recognising it. The text
    /// is `Api`'s, so a log line reads the same either way.
    #[error("api: 429 {message}")]
    RateLimited {
        retry_after_s: Option<u32>,
        message: String,
    },

    #[error("not authenticated")]
    Unauthenticated,

    #[error("cancelled")]
    Cancelled,
}
