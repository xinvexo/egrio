//! The UDP socket under a Hysteria 2 client endpoint. Every client connection
//! owns its endpoint, so the socket talks to one server only. Without UDP
//! segmentation offload each transmit is one datagram, and an unconnected send
//! makes the kernel choose the source address and check its route for every
//! datagram (on macOS a send through a connected socket takes well under half
//! the CPU); there the socket is connected to the server and its sends carry
//! no address. Where the platform offloads segmentation, quinn's own socket
//! keeps it.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use quinn::udp::{RecvMeta, Transmit, UdpSocketState};
use quinn::{AsyncUdpSocket, Runtime, TokioRuntime, UdpPoller};
use tokio::io::Interest;

/// Wraps the endpoint's bound socket, connecting it to `server` unless the
/// platform offloads segmentation.
pub(super) fn client_socket(
    socket: std::net::UdpSocket,
    server: SocketAddr,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    let state = UdpSocketState::new((&socket).into())?;
    if state.max_gso_segments() > 1 {
        return TokioRuntime.wrap_udp_socket(socket);
    }
    Ok(Arc::new(ConnectedSocket::new(socket, state, server)?))
}

/// A socket connected to the endpoint's server. A transmit is always one
/// datagram (no segmentation offload) and goes to that server.
struct ConnectedSocket {
    io: tokio::net::UdpSocket,
    state: UdpSocketState,
}

impl ConnectedSocket {
    fn new(
        socket: std::net::UdpSocket,
        state: UdpSocketState,
        server: SocketAddr,
    ) -> io::Result<Self> {
        socket.connect(server)?;
        Ok(Self {
            io: tokio::net::UdpSocket::from_std(socket)?,
            state,
        })
    }
}

impl fmt::Debug for ConnectedSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectedSocket")
            .field("io", &self.io)
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for ConnectedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(WritablePoller(self))
    }

    /// Only `WouldBlock` reaches quinn, which would end the connection on any
    /// other error. As quinn-udp does, every other failure loses just this
    /// datagram and QUIC recovers it like any loss: a full interface queue
    /// (ENOBUFS under a heavy upload), or an ICMP error that a connected socket
    /// reports on its next call (ECONNREFUSED).
    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        loop {
            match self.io.try_send(transmit.contents) {
                Ok(_) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Err(error),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Ok(()),
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Like quinn's own socket: a failed receive (WouldBlock, or an ICMP
        // error reported as ECONNREFUSED) waits for the next datagram rather
        // than ending the endpoint.
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(count) = self.io.try_io(Interest::READABLE, || {
                self.state.recv((&self.io).into(), bufs, meta)
            }) {
                return Poll::Ready(Ok(count));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        self.state.gro_segments()
    }
}

#[derive(Debug)]
struct WritablePoller(Arc<ConnectedSocket>);

impl UdpPoller for WritablePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0.io.poll_send_ready(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
    use quinn::{ClientConfig, Endpoint, EndpointConfig, ServerConfig};

    use super::*;

    /// A datagram the kernel refuses is lost alone: after a port unreachable
    /// the next send reports ECONNREFUSED, and the socket keeps sending.
    #[tokio::test]
    async fn a_refused_send_loses_only_that_datagram() {
        let closed = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let target = closed.local_addr().expect("address");
        drop(closed);
        let bound = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind client");
        let state = UdpSocketState::new((&bound).into()).expect("socket state");
        bound.set_nonblocking(true).expect("non-blocking");
        let socket = ConnectedSocket::new(bound, state, target).expect("connect");
        let transmit = Transmit {
            destination: target,
            ecn: None,
            contents: b"lost",
            segment_size: None,
            src_ip: None,
        };
        for _ in 0..3 {
            socket.io.writable().await.expect("writable");
            socket
                .try_send(&transmit)
                .expect("a refused datagram is only lost");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// A QUIC exchange both ways through a connected client socket: the
    /// handshake, a request and a reply of many datagrams.
    #[tokio::test]
    async fn a_connected_client_socket_carries_a_quic_exchange() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let key_pair = rcgen::KeyPair::generate().expect("keypair");
        let certificate = rcgen::CertificateParams::new(vec!["localhost".into()])
            .expect("params")
            .self_signed(&key_pair)
            .expect("self-signed cert");
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
            )
            .expect("server tls");
        server_tls.alpn_protocols = vec![b"test".to_vec()];
        let server_config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls).expect("quic server tls"),
        ));
        let server = Endpoint::server(server_config, (Ipv4Addr::LOCALHOST, 0).into())
            .expect("server endpoint");
        let server_addr = server.local_addr().expect("server address");

        // Built directly: a platform with segmentation offload would keep
        // quinn's own socket in `client_socket`.
        let bound = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind client");
        let state = UdpSocketState::new((&bound).into()).expect("socket state");
        bound.set_nonblocking(true).expect("non-blocking");
        let socket = Arc::new(ConnectedSocket::new(bound, state, server_addr).expect("connect"));
        let mut client = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )
        .expect("client endpoint");
        let client_tls = crate::tls::client_config(true, &[b"test".to_vec()]);
        client.set_default_client_config(ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_tls).expect("quic client tls"),
        )));

        let reply = vec![7_u8; 200_000];
        let served = {
            let reply = reply.clone();
            tokio::spawn(async move {
                let connection = server
                    .accept()
                    .await
                    .expect("incoming")
                    .await
                    .expect("accept");
                let (mut send, mut recv) = connection.accept_bi().await.expect("stream");
                let request = recv.read_to_end(64).await.expect("request");
                send.write_all(&reply).await.expect("reply");
                send.finish().expect("finish");
                let _ = send.stopped().await;
                request
            })
        };
        let exchange = async {
            let connection = client
                .connect(server_addr, "localhost")
                .expect("dial")
                .await
                .expect("handshake");
            let (mut send, mut recv) = connection.open_bi().await.expect("stream");
            send.write_all(b"hello").await.expect("request");
            send.finish().expect("finish");
            recv.read_to_end(1 << 20).await.expect("reply")
        };
        let received = tokio::time::timeout(Duration::from_secs(10), exchange)
            .await
            .expect("the exchange finishes");
        assert_eq!(received, reply);
        assert_eq!(served.await.expect("server task"), b"hello");
    }
}
