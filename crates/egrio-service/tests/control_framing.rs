use std::io::{Cursor, Read};

use egrio_service::framing::{read_frame, write_frame, FrameError};
use egrio_service::protocol::MAX_CONTROL_FRAME_BYTES;

struct OneByteReader<R>(R);
impl<R: Read> Read for OneByteReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let len = buffer.len().min(1);
        self.0.read(&mut buffer[..len])
    }
}

#[test]
fn length_prefixed_json_survives_partial_reads() {
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &vec!["hello", "world"]).unwrap();
    let mut reader = OneByteReader(Cursor::new(bytes));
    assert_eq!(
        read_frame::<_, Vec<String>>(&mut reader).unwrap().unwrap(),
        ["hello", "world"]
    );
    assert!(read_frame::<_, Vec<String>>(&mut reader).unwrap().is_none());
}

#[test]
fn oversized_and_zero_frames_are_rejected() {
    let mut zero = Cursor::new(0_u32.to_le_bytes());
    assert!(matches!(
        read_frame::<_, serde_json::Value>(&mut zero),
        Err(FrameError::InvalidLength(0))
    ));
    let mut oversized = Cursor::new(((MAX_CONTROL_FRAME_BYTES + 1) as u32).to_le_bytes());
    assert!(matches!(
        read_frame::<_, serde_json::Value>(&mut oversized),
        Err(FrameError::InvalidLength(_))
    ));
}
