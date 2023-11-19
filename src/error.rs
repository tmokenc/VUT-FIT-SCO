use core::fmt;

#[derive(Copy, Clone, Debug)]
pub enum Error {
    DataTooLong,
    AadTooLong,
    Unauthenticated,
    OutOfMemory,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataTooLong => write!(f, "Data is too long"),
            Self::AadTooLong => write!(f, "Additional Data is too long"),
            Self::Unauthenticated => write!(f, "Unauthenticated"),
            Self::OutOfMemory => write!(f, "Out Of Memory"),
        }
    }
}
