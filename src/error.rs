use std::fmt;

#[derive(Debug)]
pub enum Error {
    /// Authentication failed. Deliberately carries no detail.
    Denied,
    Locked,
    ApprovalRequired {
        ticket: String,
        reason: String,
        methods: Vec<String>,
    },
    NotFound(String),
    Exists(String),
    Invalid(String),
    Crypto(String),
    Io(std::io::Error),
    Remote(String),
    Refused(String),
    /// Allowed, but only once the person confirms they understand the consequence.
    Confirm(String),
    Throttled(u64),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Denied => write!(f, "access denied"),
            Error::Locked => write!(f, "the pit is locked — run `pit unlock`"),
            Error::ApprovalRequired { reason, ticket, .. } => {
                write!(f, "approval required: {reason} (ticket {ticket})")
            }
            Error::NotFound(s) => write!(f, "not found: {s}"),
            Error::Exists(s) => write!(f, "already exists: {s}"),
            Error::Invalid(s) => write!(f, "{s}"),
            Error::Crypto(s) => write!(f, "crypto: {s}"),
            Error::Io(e) => write!(f, "{e}"),
            Error::Remote(s) => write!(f, "{s}"),
            Error::Refused(s) => write!(f, "refused: {s}"),
            Error::Confirm(s) => write!(f, "{s}"),
            Error::Throttled(s) => write!(f, "too many failed attempts — try again in {s}s"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Invalid(format!("data: {e}"))
    }
}

impl From<toml::de::Error> for Error {
    fn from(e: toml::de::Error) -> Self {
        Error::Invalid(format!("toml: {e}"))
    }
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::Denied => "denied",
            Error::Locked => "locked",
            Error::ApprovalRequired { .. } => "approval_required",
            Error::NotFound(_) => "not_found",
            Error::Exists(_) => "exists",
            Error::Invalid(_) => "invalid",
            Error::Crypto(_) => "crypto",
            Error::Io(_) => "io",
            Error::Remote(_) => "remote",
            Error::Refused(_) => "refused",
            Error::Confirm(_) => "confirm",
            Error::Throttled(_) => "throttled",
        }
    }
}

pub fn invalid<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Invalid(msg.into()))
}
