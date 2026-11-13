//! Plain `http://` requests through the HTTP proxy: the absolute-form
//! request a client sends to its configured proxy (RFC 9112 §3.2.2) is
//! rewritten for its origin and replayed ahead of the body.
//!
//! One client connection serves exactly one request to one origin. The
//! forwarded head asks the origin to close after its response, and the
//! client stream ends the message at its framing (RFC 9112 §6.3): should a
//! client reuse the connection anyway, its next request — possibly for
//! another host — never reaches this origin; the connection resets and
//! the client retries on a new one. Keep-alive is therefore not preserved
//! across plain HTTP requests. An upgrade (WebSocket) hands the connection
//! to the origin, so nothing bounds it.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::inbound::acceptor::BoxedInboundStream;
use crate::target::{parse_connect_authority, ConnectTarget};

/// A plain request for one origin, with its head rewritten for that hop.
pub(super) struct ForwardRequest {
    pub(super) target: ConnectTarget,
    head: Vec<u8>,
    body: RequestBody,
}

impl ForwardRequest {
    /// Parses a non-`CONNECT` request: `lines` are the header field lines
    /// after the request line.
    pub(super) fn parse<'a>(
        method: &str,
        target: &str,
        version: &str,
        lines: impl Iterator<Item = &'a str>,
    ) -> Result<Self, String> {
        if !(version.eq_ignore_ascii_case("HTTP/1.1") || version.eq_ignore_ascii_case("HTTP/1.0")) {
            return Err(format!("unsupported HTTP proxy request version {version}"));
        }
        let (authority, origin_form) = split_absolute_http_target(target)?;
        let target = http_authority_target(authority)?;
        let mut fields = Vec::new();
        for line in lines.filter(|line| !line.is_empty()) {
            if line.starts_with([' ', '\t']) {
                return Err("obsolete HTTP header line folding is not supported".into());
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| format!("malformed HTTP header line: {line}"))?;
            fields.push((name.trim(), value.trim()));
        }
        let options: Vec<String> = values(&fields, "connection")
            .map(str::to_ascii_lowercase)
            .collect();
        let upgrade = options.iter().any(|option| option == "upgrade")
            && fields
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("upgrade"));
        let body = if upgrade {
            RequestBody::Unbounded
        } else {
            RequestBody::from_fields(&fields)?
        };
        Ok(Self {
            target,
            head: rewrite_head(
                method,
                &origin_form,
                version,
                authority,
                &fields,
                &options,
                upgrade,
            ),
            body,
        })
    }

    /// The client stream as the origin must receive it.
    pub(super) fn into_stream(self, client: BoxedInboundStream) -> ForwardedStream {
        ForwardedStream {
            head: self.head,
            replayed: 0,
            body: self.body,
            reused: false,
            client,
        }
    }
}

/// Splits an absolute-form `http://` request target into its authority and
/// the origin-form target the origin expects (RFC 9112 §3.2.1). HTTPS goes
/// through `CONNECT`, so no other scheme is proxied in the clear.
fn split_absolute_http_target(target: &str) -> Result<(&str, String), String> {
    let rest = target
        .get(..7)
        .filter(|scheme| scheme.eq_ignore_ascii_case("http://"))
        .map(|_| &target[7..])
        .ok_or_else(|| {
            format!("expected CONNECT or an absolute http:// request target, got {target}")
        })?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, rest) = rest.split_at(end);
    if authority.is_empty() || authority.contains('@') {
        return Err(format!("invalid http:// authority in {target}"));
    }
    // A fragment never reaches the origin.
    let path = rest.split('#').next().unwrap_or_default();
    let origin_form = match path.chars().next() {
        None => "/".to_owned(),
        Some('?') => format!("/{path}"),
        Some(_) => path.to_owned(),
    };
    Ok((authority, origin_form))
}

/// An `http://` authority's port is optional and defaults to 80.
fn http_authority_target(authority: &str) -> Result<ConnectTarget, String> {
    let has_port = authority
        .rfind(':')
        .is_some_and(|colon| !authority[colon..].contains(']'));
    if has_port {
        parse_connect_authority(authority)
    } else {
        parse_connect_authority(&format!("{authority}:80"))
    }
}

/// The comma-separated list members of every `name` field.
fn values<'a>(fields: &'a [(&str, &str)], name: &'a str) -> impl Iterator<Item = &'a str> {
    fields
        .iter()
        .filter(move |(field, _)| field.eq_ignore_ascii_case(name))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|member| !member.is_empty())
}

/// The head the origin receives: origin-form target, a `Host` from the
/// request target (RFC 9112 §3.2.2), and none of the connection options or
/// proxy fields meant for this hop (RFC 9110 §7.6.1). Message framing
/// (`Content-Length`, `Transfer-Encoding`) always stays, since the body is
/// relayed unchanged.
fn rewrite_head(
    method: &str,
    origin_form: &str,
    version: &str,
    authority: &str,
    fields: &[(&str, &str)],
    options: &[String],
    upgrade: bool,
) -> Vec<u8> {
    let mut head = format!("{method} {origin_form} {version}\r\nHost: {authority}\r\n");
    for (name, value) in fields {
        let name_lower = name.to_ascii_lowercase();
        let framing = matches!(name_lower.as_str(), "content-length" | "transfer-encoding");
        let hop = matches!(
            name_lower.as_str(),
            "host" | "connection" | "proxy-connection" | "keep-alive" | "proxy-authorization"
        ) || (name_lower == "upgrade" && !upgrade)
            || (options.contains(&name_lower) && name_lower != "upgrade");
        if framing || !hop {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    head.push_str(if upgrade {
        "Connection: Upgrade\r\n\r\n"
    } else {
        "Connection: close\r\n\r\n"
    });
    head.into_bytes()
}

/// Where the forwarded request's message ends.
#[derive(Debug)]
enum RequestBody {
    /// An upgrade: after the origin's 101 the stream belongs to it.
    Unbounded,
    /// This many body bytes remain.
    Length(u64),
    /// A chunked body (RFC 9112 §7.1), tracked byte by byte.
    Chunked(Chunked),
    /// The message is complete; only stray CRLF may follow.
    Complete,
}

impl RequestBody {
    /// The request's framing (RFC 9112 §6.3). Framing the origin could read
    /// differently — both fields, a final coding other than chunked, or
    /// disagreeing lengths — is refused rather than guessed.
    fn from_fields(fields: &[(&str, &str)]) -> Result<Self, String> {
        let codings: Vec<&str> = values(fields, "transfer-encoding").collect();
        let lengths: Vec<&str> = values(fields, "content-length").collect();
        match (codings.last(), lengths.first()) {
            (Some(_), Some(_)) => {
                Err("request carries both Transfer-Encoding and Content-Length".into())
            }
            (Some(coding), None) if coding.eq_ignore_ascii_case("chunked") => {
                Ok(Self::Chunked(Chunked::default()))
            }
            (Some(coding), None) => Err(format!(
                "request body's final transfer coding is {coding}, not chunked"
            )),
            (None, Some(first)) => {
                if lengths.iter().any(|length| length != first) {
                    return Err("request carries conflicting Content-Length values".into());
                }
                match first.parse::<u64>() {
                    Ok(0) => Ok(Self::Complete),
                    Ok(length) => Ok(Self::Length(length)),
                    Err(_) => Err(format!("invalid request Content-Length {first}")),
                }
            }
            (None, None) => Ok(Self::Complete),
        }
    }

    /// Advances over `bytes` read from the client and returns how many of
    /// them belong to the message; the rest follow it.
    fn advance(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let consumed = match self {
            Self::Unbounded => return Ok(bytes.len()),
            Self::Complete => return Ok(0),
            Self::Length(remaining) => {
                let take = usize::try_from(*remaining)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len());
                *remaining -= take as u64;
                take
            }
            Self::Chunked(chunked) => chunked.advance(bytes)?,
        };
        if matches!(self, Self::Length(0))
            || matches!(self, Self::Chunked(chunked) if chunked.is_done())
        {
            *self = Self::Complete;
        }
        Ok(consumed)
    }
}

/// The chunked transfer coding's grammar (RFC 9112 §7.1):
/// `*chunk last-chunk trailer-section CRLF`.
#[derive(Debug, Default)]
enum Chunked {
    #[default]
    SizeStart,
    Size(u64),
    Extension(u64),
    SizeLf(u64),
    Data(u64),
    DataCr,
    DataLf,
    TrailerStart,
    Trailer,
    TrailerLf,
    EndLf,
    Done,
}

impl Chunked {
    fn is_done(&self) -> bool {
        matches!(self, Self::Done)
    }

    fn advance(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut index = 0;
        while index < bytes.len() && !self.is_done() {
            if let Self::Data(remaining) = self {
                let take = usize::try_from(*remaining)
                    .unwrap_or(usize::MAX)
                    .min(bytes.len() - index);
                *remaining -= take as u64;
                index += take;
                if *remaining == 0 {
                    *self = Self::DataCr;
                }
                continue;
            }
            let byte = bytes[index];
            index += 1;
            *self = match (&*self, byte) {
                (Self::SizeStart, _) => Self::Size(hex_digit(byte).ok_or_else(malformed)?),
                (Self::Size(size), b';' | b' ' | b'\t') => Self::Extension(*size),
                (Self::Size(size), b'\r') | (Self::Extension(size), b'\r') => Self::SizeLf(*size),
                (Self::Size(size), _) => Self::Size(
                    hex_digit(byte)
                        .and_then(|digit| size.checked_mul(16)?.checked_add(digit))
                        .ok_or_else(malformed)?,
                ),
                (Self::Extension(size), _) => Self::Extension(*size),
                (Self::SizeLf(0), b'\n') => Self::TrailerStart,
                (Self::SizeLf(size), b'\n') => Self::Data(*size),
                (Self::DataCr, b'\r') => Self::DataLf,
                (Self::DataLf, b'\n') => Self::SizeStart,
                (Self::TrailerStart, b'\r') => Self::EndLf,
                (Self::Trailer, b'\r') => Self::TrailerLf,
                (Self::TrailerStart | Self::Trailer, _) => Self::Trailer,
                (Self::TrailerLf, b'\n') => Self::TrailerStart,
                (Self::EndLf, b'\n') => Self::Done,
                _ => return Err(malformed()),
            };
        }
        Ok(index)
    }
}

fn hex_digit(byte: u8) -> Option<u64> {
    char::from(byte).to_digit(16).map(u64::from)
}

fn malformed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed chunked request body")
}

/// The client stream with the rewritten head replayed first, so sniffing,
/// the dial's early data and the relay all see exactly the bytes the origin
/// must receive, and with the message bounded at its framing.
pub(super) struct ForwardedStream {
    head: Vec<u8>,
    replayed: usize,
    body: RequestBody,
    /// The client sent a next request after this one.
    reused: bool,
    client: BoxedInboundStream,
}

impl AsyncRead for ForwardedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.replayed < this.head.len() {
            let count = (this.head.len() - this.replayed).min(buf.remaining());
            buf.put_slice(&this.head[this.replayed..this.replayed + count]);
            this.replayed += count;
            return Poll::Ready(Ok(()));
        }
        loop {
            if this.reused {
                // The end of this message, not a failure. An error here ended
                // both directions of the relay, so the response to the
                // request already on its way back was dropped with them --
                // and that one the client could have had. Ending only this
                // direction half-closes the origin, which is what the client
                // going quiet after its request does too; the next request is
                // never carried on this connection, and the client retries it
                // on a new one as it would after any close.
                return Poll::Ready(Ok(()));
            }
            let start = buf.filled().len();
            ready!(Pin::new(&mut this.client).poll_read(cx, buf))?;
            let read = buf.filled().len() - start;
            if read == 0 {
                return Poll::Ready(Ok(()));
            }
            let message = this.body.advance(&buf.filled()[start..])?;
            if message < read {
                let after = &buf.filled()[start + message..];
                this.reused = after.iter().any(|byte| !matches!(byte, b'\r' | b'\n'));
                buf.set_filled(start + message);
            }
            if message > 0 {
                return Poll::Ready(Ok(()));
            }
            // Only stray CRLF after the message, or a next request: neither
            // is data for the origin, and an empty read would mean EOF.
        }
    }
}

impl AsyncWrite for ForwardedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.client).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.client).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.client).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunked_message_length(bytes: &[u8]) -> io::Result<(usize, bool)> {
        let mut chunked = Chunked::default();
        let consumed = chunked.advance(bytes)?;
        Ok((consumed, chunked.is_done()))
    }

    #[test]
    fn a_chunked_body_ends_after_its_last_chunk_and_trailers() {
        let body = b"5;name=value\r\nhello\r\nA\r\n0123456789\r\n0\r\nX-Sum: 1\r\n\r\n";
        let mut message = body.to_vec();
        message.extend_from_slice(b"GET http://other/ HTTP/1.1\r\n\r\n");
        assert_eq!(
            chunked_message_length(&message).unwrap(),
            (body.len(), true)
        );
        assert_eq!(
            chunked_message_length(b"0\r\n\r\n").unwrap(),
            (5, true),
            "an empty body is just the last chunk"
        );
    }

    #[test]
    fn a_chunked_body_split_across_reads_ends_at_the_same_byte() {
        let body = b"3\r\nabc\r\n0\r\n\r\n";
        let mut chunked = Chunked::default();
        let mut consumed = 0;
        for byte in body {
            consumed += chunked.advance(std::slice::from_ref(byte)).unwrap();
        }
        assert_eq!(consumed, body.len());
        assert!(chunked.is_done());
    }

    #[test]
    fn malformed_chunked_bodies_are_refused() {
        for body in [
            &b"z\r\n"[..],
            b"5\r\nhelloX",
            b"\r\n",
            b"5\rx",
            b"10000000000000000\r\n",
        ] {
            assert!(chunked_message_length(body).is_err(), "{body:?}");
        }
    }

    #[test]
    fn framing_follows_rfc_9112_and_refuses_ambiguity() {
        let framing = |fields: &[(&str, &str)]| RequestBody::from_fields(fields);
        assert!(matches!(framing(&[]), Ok(RequestBody::Complete)));
        assert!(matches!(
            framing(&[("Content-Length", "5")]),
            Ok(RequestBody::Length(5))
        ));
        assert!(matches!(
            framing(&[("Content-Length", "5, 5")]),
            Ok(RequestBody::Length(5))
        ));
        assert!(matches!(
            framing(&[("Transfer-Encoding", "gzip, chunked")]),
            Ok(RequestBody::Chunked(_))
        ));
        for fields in [
            &[("Content-Length", "5"), ("Transfer-Encoding", "chunked")][..],
            &[("Transfer-Encoding", "chunked, gzip")],
            &[("Content-Length", "5"), ("Content-Length", "6")],
            &[("Content-Length", "-1")],
        ] {
            assert!(framing(fields).is_err(), "{fields:?}");
        }
    }
}
