use std::str;

use thiserror::Error;

pub const MAGIC: &[u8; 4] = b"EPDN";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EncodeError {
    #[error("{field} exceeds its maximum length: {actual} > {maximum}")]
    LengthExceeded {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("{field} has invalid length: {actual}, expected {expected}")]
    InvalidLength {
        field: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("{field} is not in canonical order")]
    NonCanonicalOrder { field: &'static str },
    #[error("{field} has a non-canonical value")]
    NonCanonicalValue { field: &'static str },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DecodeError {
    #[error("packet exceeds maximum size: {actual} > {maximum}")]
    Oversized { actual: usize, maximum: usize },
    #[error("unexpected end of packet")]
    UnexpectedEof,
    #[error("invalid EPDN magic")]
    InvalidMagic,
    #[error("unexpected object type {actual}, expected {expected}")]
    UnexpectedType { actual: u8, expected: u8 },
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("{field} exceeds its maximum length: {actual} > {maximum}")]
    LengthExceeded {
        field: &'static str,
        actual: usize,
        maximum: usize,
    },
    #[error("{field} has invalid UTF-8")]
    InvalidUtf8 { field: &'static str },
    #[error("invalid enum value {value} for {field}")]
    InvalidEnum { field: &'static str, value: u8 },
    #[error("{field} is not encoded canonically")]
    NonCanonical { field: &'static str },
    #[error("packet contains {0} trailing bytes")]
    TrailingBytes(usize),
}

#[derive(Debug, Default)]
pub struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    #[must_use]
    pub fn with_header(object_type: u8, version: u16) -> Self {
        let mut encoder = Self {
            bytes: Vec::with_capacity(256),
        };
        encoder.fixed(MAGIC);
        encoder.u8(object_type);
        encoder.u16(version);
        encoder
    }

    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub fn bytes_u16(
        &mut self,
        field: &'static str,
        value: &[u8],
        maximum: usize,
    ) -> Result<(), EncodeError> {
        if value.len() > maximum || value.len() > usize::from(u16::MAX) {
            return Err(EncodeError::LengthExceeded {
                field,
                actual: value.len(),
                maximum: maximum.min(usize::from(u16::MAX)),
            });
        }
        self.u16(value.len() as u16);
        self.fixed(value);
        Ok(())
    }

    pub fn bytes_u32(
        &mut self,
        field: &'static str,
        value: &[u8],
        maximum: usize,
    ) -> Result<(), EncodeError> {
        if value.len() > maximum || value.len() > u32::MAX as usize {
            return Err(EncodeError::LengthExceeded {
                field,
                actual: value.len(),
                maximum: maximum.min(u32::MAX as usize),
            });
        }
        self.u32(value.len() as u32);
        self.fixed(value);
        Ok(())
    }

    pub fn string(
        &mut self,
        field: &'static str,
        value: &str,
        maximum: usize,
    ) -> Result<(), EncodeError> {
        self.bytes_u16(field, value.as_bytes(), maximum)
    }

    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug)]
pub struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub fn with_header(
        input: &'a [u8],
        maximum: usize,
        expected_type: u8,
        expected_version: u16,
    ) -> Result<Self, DecodeError> {
        if input.len() > maximum {
            return Err(DecodeError::Oversized {
                actual: input.len(),
                maximum,
            });
        }
        let mut decoder = Self { input, offset: 0 };
        if decoder.take(4)? != MAGIC {
            return Err(DecodeError::InvalidMagic);
        }
        let actual_type = decoder.u8()?;
        if actual_type != expected_type {
            return Err(DecodeError::UnexpectedType {
                actual: actual_type,
                expected: expected_type,
            });
        }
        let actual_version = decoder.u16()?;
        if actual_version != expected_version {
            return Err(DecodeError::UnsupportedVersion(actual_version));
        }
        Ok(decoder)
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| DecodeError::UnexpectedEof)?;
        Ok(u16::from_be_bytes(bytes))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| DecodeError::UnexpectedEof)?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| DecodeError::UnexpectedEof)?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| DecodeError::UnexpectedEof)
    }

    pub fn bytes_u16(
        &mut self,
        field: &'static str,
        maximum: usize,
    ) -> Result<Vec<u8>, DecodeError> {
        let length = usize::from(self.u16()?);
        self.bounded_bytes(field, length, maximum)
    }

    pub fn bytes_u32(
        &mut self,
        field: &'static str,
        maximum: usize,
    ) -> Result<Vec<u8>, DecodeError> {
        let length = self.u32()? as usize;
        self.bounded_bytes(field, length, maximum)
    }

    pub fn string(&mut self, field: &'static str, maximum: usize) -> Result<String, DecodeError> {
        let value = self.bytes_u16(field, maximum)?;
        str::from_utf8(&value)
            .map(str::to_owned)
            .map_err(|_| DecodeError::InvalidUtf8 { field })
    }

    pub fn finish(self) -> Result<(), DecodeError> {
        let remaining = self.input.len().saturating_sub(self.offset);
        if remaining == 0 {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes(remaining))
        }
    }

    fn bounded_bytes(
        &mut self,
        field: &'static str,
        length: usize,
        maximum: usize,
    ) -> Result<Vec<u8>, DecodeError> {
        if length > maximum {
            return Err(DecodeError::LengthExceeded {
                field,
                actual: length,
                maximum,
            });
        }
        Ok(self.take(length)?.to_vec())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DecodeError::UnexpectedEof)?;
        let value = self
            .input
            .get(self.offset..end)
            .ok_or(DecodeError::UnexpectedEof)?;
        self.offset = end;
        Ok(value)
    }
}

pub fn ensure_exact_length(
    field: &'static str,
    value: &[u8],
    expected: usize,
) -> Result<(), EncodeError> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(EncodeError::InvalidLength {
            field,
            actual: value.len(),
            expected,
        })
    }
}
