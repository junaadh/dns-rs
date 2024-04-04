use core::fmt;

#[derive(Debug)]
pub enum DnsError {
    OutOfBounds,
    JumpsExceed,
    LabelLengthExceed,
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds => write!(f, "Buffer out of bounds, Buffer len is 512."),
            Self::JumpsExceed => write!(f, "Limit of jumps exceeded."),
            Self::LabelLengthExceed => write!(f, "Single label exceeds 63 characters of length."),
        }
    }
}

impl DnsError {
    pub fn write(self) -> Self {
        println!("{}", self);
        self
    }
}

#[macro_export]
macro_rules! err {
    ($err:ident) => {{
        $crate::error::DnsError::$err.write()
    }};
}
