use std::io::{self, Read, Write};

use serde::{de::DeserializeOwned, Serialize};

use crate::protocol::MAX_CONTROL_FRAME_BYTES;

pub fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: Write,
    T: Serialize,
{
    let frame = encode_frame(value)?;
    writer.write_all(&frame).map_err(FrameError::Io)?;
    writer.flush().map_err(FrameError::Io)
}

/// One frame: the body's length, little-endian, then the JSON body.
pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(value).map_err(FrameError::Json)?;
    if body.is_empty() || body.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::InvalidLength(body.len()));
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn read_frame<R, T>(reader: &mut R) -> Result<Option<T>, FrameError>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut prefix = [0_u8; 4];
    match reader.read(&mut prefix[..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => reader
            .read_exact(&mut prefix[1..])
            .map_err(FrameError::Io)?,
        Ok(_) => unreachable!("one-byte prefix read"),
        Err(error) => return Err(FrameError::Io(error)),
    }
    let len = u32::from_le_bytes(prefix) as usize;
    if len == 0 || len > MAX_CONTROL_FRAME_BYTES {
        return Err(FrameError::InvalidLength(len));
    }
    let mut body = vec![0_u8; len];
    reader.read_exact(&mut body).map_err(FrameError::Io)?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(FrameError::Json)
}

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    Json(serde_json::Error),
    InvalidLength(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::Json(error) => error.fmt(formatter),
            Self::InvalidLength(len) => write!(formatter, "invalid control frame length: {len}"),
        }
    }
}

impl std::error::Error for FrameError {}
