//! Кадрирование: каждый кадр ровно [`FRAME_SIZE`] байт.
//!
//! ```text
//! u8  version
//! u8  frame_type
//! u16 body_len (big-endian)
//! [body_len] body
//! [...]      padding нулями до FRAME_SIZE
//! ```

use crate::PROTOCOL_VERSION;

pub const FRAME_SIZE: usize = 16 * 1024;
pub const FRAME_HEADER: usize = 4;
pub const MAX_BODY: usize = FRAME_SIZE - FRAME_HEADER;
/// Медиа-соединение (звонки): кадры мельче, но тоже одинакового размера — по трафику
/// не отличить речь от тишины и ключевой кадр видео от обычного.
pub const MEDIA_FRAME_SIZE: usize = 1200;
pub const MEDIA_MAX_BODY: usize = MEDIA_FRAME_SIZE - FRAME_HEADER;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Request = 1,
    Response = 2,
    Event = 3,
}

impl TryFrom<u8> for FrameType {
    type Error = FrameError;

    fn try_from(v: u8) -> Result<Self, FrameError> {
        match v {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            3 => Ok(Self::Event),
            other => Err(FrameError::UnknownType(other)),
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame body too large: {0} > {MAX_BODY}")]
    TooLarge(usize),
    #[error("invalid frame size: {0}")]
    BadSize(usize),
    #[error("unsupported protocol version: {0}")]
    Version(u8),
    #[error("unknown frame type: {0}")]
    UnknownType(u8),
    #[error("body length {0} exceeds frame")]
    BadLength(usize),
}

pub fn encode(ty: FrameType, body: &[u8]) -> Result<Vec<u8>, FrameError> {
    encode_sized(ty, body, FRAME_SIZE)
}

pub fn decode(frame: &[u8]) -> Result<(FrameType, &[u8]), FrameError> {
    decode_sized(frame, FRAME_SIZE)
}

/// Кадр заданного размера (`FRAME_SIZE` или `MEDIA_FRAME_SIZE`).
pub fn encode_sized(ty: FrameType, body: &[u8], size: usize) -> Result<Vec<u8>, FrameError> {
    if body.len() > size - FRAME_HEADER {
        return Err(FrameError::TooLarge(body.len()));
    }
    let mut frame = vec![0u8; size];
    frame[0] = PROTOCOL_VERSION;
    frame[1] = ty as u8;
    frame[2..4].copy_from_slice(&(body.len() as u16).to_be_bytes());
    frame[FRAME_HEADER..FRAME_HEADER + body.len()].copy_from_slice(body);
    Ok(frame)
}

pub fn decode_sized(frame: &[u8], size: usize) -> Result<(FrameType, &[u8]), FrameError> {
    if frame.len() != size {
        return Err(FrameError::BadSize(frame.len()));
    }
    if frame[0] != PROTOCOL_VERSION {
        return Err(FrameError::Version(frame[0]));
    }
    let ty = FrameType::try_from(frame[1])?;
    let len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    if len > size - FRAME_HEADER {
        return Err(FrameError::BadLength(len));
    }
    Ok((ty, &frame[FRAME_HEADER..FRAME_HEADER + len]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let frame = encode(FrameType::Event, b"hello").unwrap();
        assert_eq!(frame.len(), FRAME_SIZE);
        let (ty, body) = decode(&frame).unwrap();
        assert_eq!(ty, FrameType::Event);
        assert_eq!(body, b"hello");
    }

    #[test]
    fn empty_and_max_body() {
        let frame = encode(FrameType::Request, &[]).unwrap();
        assert!(decode(&frame).unwrap().1.is_empty());
        let max = vec![7u8; MAX_BODY];
        let frame = encode(FrameType::Request, &max).unwrap();
        assert_eq!(decode(&frame).unwrap().1, &max[..]);
    }

    #[test]
    fn media_frames() {
        let frame = encode_sized(FrameType::Event, b"voice", MEDIA_FRAME_SIZE).unwrap();
        assert_eq!(frame.len(), MEDIA_FRAME_SIZE);
        assert_eq!(decode_sized(&frame, MEDIA_FRAME_SIZE).unwrap().1, b"voice");
        assert!(encode_sized(FrameType::Event, &vec![0; MEDIA_MAX_BODY + 1], MEDIA_FRAME_SIZE).is_err());
        assert_eq!(decode(&frame), Err(FrameError::BadSize(MEDIA_FRAME_SIZE)));
    }

    #[test]
    fn rejects_bad_frames() {
        assert_eq!(encode(FrameType::Request, &vec![0; MAX_BODY + 1]), Err(FrameError::TooLarge(MAX_BODY + 1)));
        assert_eq!(decode(&[0u8; 10]), Err(FrameError::BadSize(10)));

        let mut frame = encode(FrameType::Request, b"x").unwrap();
        frame[0] = 99;
        assert_eq!(decode(&frame), Err(FrameError::Version(99)));

        let mut frame = encode(FrameType::Request, b"x").unwrap();
        frame[1] = 42;
        assert_eq!(decode(&frame), Err(FrameError::UnknownType(42)));

        let mut frame = encode(FrameType::Request, b"x").unwrap();
        frame[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(decode(&frame), Err(FrameError::BadLength(u16::MAX as usize)));
    }
}
