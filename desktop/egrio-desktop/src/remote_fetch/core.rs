//! HTTP over the Runtime's own outbounds, including before ordinary ingress.
use egrio_core::CoreOutboundStream;
use egrio_runtime::Runtime;
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{
        connect::{Connected, Connection},
        Client,
    },
    rt::{TokioExecutor, TokioIo},
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower_service::Service;

use super::{
    ensure_body_size_within_limit, validate_remote_url, MAX_REMOTE_DOCUMENT_BYTES,
    REMOTE_FETCH_TIMEOUT_SECONDS, REMOTE_MAX_REDIRECTS,
};

#[derive(Clone)]
struct CoreConnector(Arc<Runtime>);

struct CoreConnection(CoreOutboundStream);

impl Connection for CoreConnection {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}
impl AsyncRead for CoreConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for CoreConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Service<Uri> for CoreConnector {
    type Response = TokioIo<CoreConnection>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, io::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        let runtime = self.0.clone();
        Box::pin(async move {
            let host = uri
                .host()
                .expect("validated download URI host")
                .trim_matches(['[', ']']);
            let port = uri
                .port_u16()
                .unwrap_or(if uri.scheme_str() == Some("https") {
                    443
                } else {
                    80
                });
            runtime
                .connect_outbound(None, host, port)
                .await
                .map(|stream| TokioIo::new(CoreConnection(stream)))
                .map_err(io::Error::other)
        })
    }
}

pub(crate) struct CoreDownloadClient {
    client: Client<HttpsConnector<CoreConnector>, Empty<Bytes>>,
}

impl CoreDownloadClient {
    pub(crate) fn new(runtime: Arc<Runtime>) -> Result<Self, String> {
        let connector = HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(|error| error.to_string())?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(CoreConnector(runtime));
        Ok(Self {
            client: Client::builder(TokioExecutor::new())
                .retry_canceled_requests(false)
                .build(connector),
        })
    }

    pub(crate) async fn get(&self, url: reqwest::Url, user_agent: &str) -> Result<String, String> {
        tokio::time::timeout(
            Duration::from_secs(REMOTE_FETCH_TIMEOUT_SECONDS),
            self.fetch(url, user_agent),
        )
        .await
        .map_err(|_| {
            format!("rule provider download timed out after {REMOTE_FETCH_TIMEOUT_SECONDS}s")
        })?
    }

    async fn fetch(&self, mut url: reqwest::Url, user_agent: &str) -> Result<String, String> {
        let mut redirects = 0;
        loop {
            let request = Request::get(url.as_str())
                .header(hyper::header::USER_AGENT, user_agent)
                .body(Empty::new())
                .map_err(|error| error.to_string())?;
            let response = self.client.request(request).await.map_err(error_chain)?;
            let status = response.status();
            if matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308) {
                if let Some(location) = response.headers().get(hyper::header::LOCATION) {
                    if redirects >= REMOTE_MAX_REDIRECTS {
                        return Err(format!(
                            "URL redirected more than {REMOTE_MAX_REDIRECTS} times"
                        ));
                    }
                    let next = url
                        .join(location.to_str().map_err(|error| error.to_string())?)
                        .map_err(|error| error.to_string())?;
                    url = validate_remote_url(next.as_str())?;
                    redirects += 1;
                    continue;
                }
            }
            if !status.is_success() {
                return Err(format!(
                    "rule provider fetch failed: HTTP {}",
                    status.as_u16()
                ));
            }
            if let Some(size) = response
                .headers()
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok())
            {
                ensure_body_size_within_limit(size, MAX_REMOTE_DOCUMENT_BYTES)?;
            }
            let mut body = response.into_body();
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame.map_err(error_chain)?.into_data() {
                    ensure_body_size_within_limit(
                        (bytes.len() + data.len()) as u64,
                        MAX_REMOTE_DOCUMENT_BYTES,
                    )?;
                    bytes.extend_from_slice(&data);
                }
            }
            return String::from_utf8(bytes)
                .map_err(|error| format!("download is not UTF-8: {error}"));
        }
    }
}

fn error_chain(error: impl std::error::Error) -> String {
    let mut message = error.to_string();
    let mut cause = error.source();
    while let Some(error) = cause {
        message.push_str(": ");
        message.push_str(&error.to_string());
        cause = error.source();
    }
    message
}
