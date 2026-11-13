use tokio::io::{AsyncRead, AsyncReadExt};

/// The largest header block either half accepts.
const MAX_HEADER_BYTES: usize = 8192;

/// Reads one CRLF-terminated HTTP header block, byte-capped. Both halves
/// speak it: the connector reads its proxy's CONNECT response, the
/// acceptor reads its client's request. It reads in chunks, not a byte per
/// read, so it also returns the bytes that arrived after the header (a
/// request body, a tunnel's first bytes); the caller replays them to the
/// stream's next reader.
pub(crate) async fn read_http_header<S: AsyncRead + Unpin + ?Sized>(
    stream: &mut S,
) -> Result<(String, Vec<u8>), String> {
    let mut header = Vec::new();
    let mut chunk = [0_u8; 4096];
    while header.len() < MAX_HEADER_BYTES {
        let room = chunk.len().min(MAX_HEADER_BYTES - header.len());
        let read = stream
            .read(&mut chunk[..room])
            .await
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("connection closed while reading HTTP header".into());
        }
        // The terminator may straddle the previous chunk.
        let searched = header.len().saturating_sub(3);
        header.extend_from_slice(&chunk[..read]);
        if let Some(end) = header[searched..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            let rest = header.split_off(searched + end + 4);
            return String::from_utf8(header)
                .map(|header| (header, rest))
                .map_err(|error| error.to_string());
        }
    }

    Err(format!("HTTP header exceeded {MAX_HEADER_BYTES} bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_the_bytes_after_the_header_and_finds_a_split_terminator() {
        // A chain yields each part from its own read.
        let mut stream = (&b"HTTP/1.1 200 OK\r\n\r"[..]).chain(&b"\nfirst bytes"[..]);
        let (header, rest) = read_http_header(&mut stream).await.unwrap();
        assert_eq!(header, "HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(rest, b"first bytes");
    }
}
