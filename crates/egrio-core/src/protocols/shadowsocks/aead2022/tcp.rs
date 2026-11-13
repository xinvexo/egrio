use std::sync::atomic::{AtomicU64, Ordering};

use shadowsocks::relay::tcprelay::{ProxyClientStream, ProxyServerStream};
use shadowsocks_crypto::v2::tcp::TcpCipher;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{from_address, to_address, Config};
use crate::attribution::ClientOwner;
use crate::inbound::acceptor::{AcceptedStream, BoxedInboundStream, InboundReplyPlan};
use crate::outbound::BoxedOutboundStream;
use crate::prefixed::PrefixedStream;
use crate::protocols::shadowsocks::acceptor::ShadowsocksUserTable;
use crate::protocols::shadowsocks::discard_until_closed;
use crate::target::ConnectTarget;

pub(in crate::protocols::shadowsocks) async fn connect<
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
>(
    transport: S,
    config: &Config,
    target: &ConnectTarget,
    early_data: &[u8],
) -> Result<BoxedOutboundStream, String> {
    let mut stream = ProxyClientStream::from_stream(
        config.context.clone(),
        transport,
        &config.server,
        to_address(target)?,
    );
    // Force a padded request even for server-first protocols. write_all([])
    // would not poll the codec and would deadlock a client waiting for data.
    if early_data.is_empty() {
        stream.write(&[]).await.map_err(|error| error.to_string())?;
    } else {
        for chunk in early_data.chunks(16 * 1024) {
            stream
                .write_all(chunk)
                .await
                .map_err(|error| error.to_string())?;
        }
    }
    stream.flush().await.map_err(|error| error.to_string())?;
    Ok(Box::new(stream))
}

pub(in crate::protocols::shadowsocks) async fn accept(
    mut transport: BoxedInboundStream,
    table: &ShadowsocksUserTable,
    auth_failures: &AtomicU64,
) -> Result<AcceptedStream, String> {
    // Authenticate the fixed header to select the user and classify a bad
    // credential separately from a replay or malformed authenticated body.
    // The official codec then validates the entire handshake, including
    // timestamp, replay salt, target, padding and response binding.
    let salt_len = table.method().salt_len();
    let mut prefix = vec![0; salt_len + 11 + table.method().tag_len()];
    let read = transport
        .read(&mut prefix)
        .await
        .map_err(|error| error.to_string())?;
    // A refused connection is read until the peer closes it, so the close
    // shows nothing of how much was read (`discard_until_closed`).
    if read != prefix.len() {
        if read > 0 {
            auth_failures.fetch_add(1, Ordering::Relaxed);
        }
        discard_until_closed(&mut transport).await;
        return Err("Shadowsocks 2022 fixed header must arrive in one read".into());
    }
    let Some(user) = table.users.iter().find(|user| {
        let mut header = prefix[salt_len..].to_vec();
        TcpCipher::new(table.method(), &user.key, &prefix[..salt_len]).decrypt_packet(&mut header)
    }) else {
        auth_failures.fetch_add(1, Ordering::Relaxed);
        discard_until_closed(&mut transport).await;
        return Err("shadowsocks 2022: no user key authenticated the request".to_string());
    };
    let mut stream = ProxyServerStream::from_stream(
        table.context.clone(),
        PrefixedStream::new(prefix, transport),
        table.method(),
        &user.key,
    );
    let target = match stream.handshake().await {
        Ok(target) => target,
        Err(error) => {
            discard_until_closed(&mut stream.into_inner()).await;
            return Err(error.to_string());
        }
    };
    Ok(AcceptedStream {
        inbound: "shadowsocks",
        user: Some(user.name.clone()),
        process: ClientOwner::Known(None),
        target: from_address(target),
        io: Box::new(stream),
        replies: InboundReplyPlan::default(),
        reset: None,
    })
}
