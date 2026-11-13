//! Plain `http://` through the mixed listener, the way a browser sends it to
//! the HTTP proxy its system settings name: an absolute-form request, routed
//! like any connection and forwarded to its origin in origin-form.
use super::*;
use crate::inbound::CoreSessionManager;

/// Serves one request: records its head, answers, and closes as the
/// forwarded `Connection: close` asks.
async fn spawn_origin() -> (SocketAddr, oneshot::Receiver<String>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (head_tx, head_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let (head, _) = crate::protocols::http::read_http_header(&mut stream)
            .await
            .unwrap();
        let _ = head_tx.send(head);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            .await
            .unwrap();
    });
    (address, head_rx)
}

async fn start_listener(core: &NativeCoreDevice) -> (CoreSessionManager, SocketAddr) {
    let manager = CoreSessionManager::default();
    let address = manager
        .start_on_device(
            core.clone(),
            Some(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            None,
            false,
        )
        .await
        .unwrap()
        .listen_addr
        .unwrap()
        .parse()
        .unwrap();
    (manager, address)
}

#[tokio::test]
async fn a_plain_http_request_reaches_its_origin_and_the_response_returns() {
    let (origin, head) = spawn_origin().await;
    let core = NativeCoreDevice::compile(&direct_profile());
    let (manager, listener) = start_listener(&core).await;

    let mut client = TcpStream::connect(listener).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{origin}/page?id=7 HTTP/1.1\r\nHost: {origin}\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .expect("the origin's response arrives and the connection closes")
        .unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.ends_with("\r\n\r\nhello"), "{response}");

    let head = timeout(Duration::from_secs(5), head)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        head,
        format!(
            "GET /page?id=7 HTTP/1.1\r\nHost: {origin}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        )
    );
    let telemetry = core.traffic_telemetry_snapshot();
    let row = telemetry
        .connections
        .iter()
        .find(|row| row.inbound == "http-forward")
        .expect("the forwarded request is a connection row");
    assert_eq!(*row.destination, origin.to_string());
    assert_eq!(&*row.outbound, "DIRECT");

    manager.stop();
    core.close();
}

#[tokio::test]
async fn a_rejected_plain_http_request_gets_a_forbidden_reply() {
    let core = NativeCoreDevice::compile(&reject_all_profile());
    let (manager, listener) = start_listener(&core).await;

    let mut client = TcpStream::connect(listener).await.unwrap();
    client
        .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), client.read_to_end(&mut response))
        .await
        .expect("the reply arrives and the connection closes")
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 403 Forbidden"),
        "{}",
        String::from_utf8_lossy(&response)
    );

    manager.stop();
    core.close();
}

/// An origin that ignores `Connection: close` keeps its connection open. A
/// keep-alive client that reuses the proxy connection for another host must
/// never reach that origin: the reused connection resets instead, so the
/// client retries the request on a new one.
#[tokio::test]
async fn a_reused_proxy_connection_never_reaches_the_first_origin_again() {
    let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let origin = origin_listener.local_addr().unwrap();
    let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        let (mut stream, _) = origin_listener.accept().await.unwrap();
        let (head, mut rest) = crate::protocols::http::read_http_header(&mut stream)
            .await
            .unwrap();
        let _ = seen_tx.send(head);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        let _ = stream.read_to_end(&mut rest).await;
        let _ = seen_tx.send(String::from_utf8_lossy(&rest).into_owned());
    });
    let core = NativeCoreDevice::compile(&direct_profile());
    let (manager, listener) = start_listener(&core).await;

    let mut client = TcpStream::connect(listener).await.unwrap();
    client
        .write_all(
            format!("GET http://{origin}/first HTTP/1.1\r\nHost: {origin}\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let (head, mut body) = timeout(
        Duration::from_secs(5),
        crate::protocols::http::read_http_header(&mut client),
    )
    .await
    .expect("the first response arrives")
    .unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    let received = body.len();
    body.resize(2, 0);
    client.read_exact(&mut body[received..]).await.unwrap();
    assert_eq!(body, b"ok");

    client
        .write_all(b"GET http://other.invalid/second HTTP/1.1\r\nHost: other.invalid\r\n\r\n")
        .await
        .unwrap();
    let mut rest = Vec::new();
    let _ = timeout(Duration::from_secs(5), client.read_to_end(&mut rest))
        .await
        .expect("the reused connection ends");
    assert!(rest.is_empty(), "no reply to the reused request: {rest:?}");

    let first = seen_rx.recv().await.unwrap();
    assert!(first.starts_with("GET /first HTTP/1.1\r\n"), "{first}");
    let after = timeout(Duration::from_secs(5), seen_rx.recv())
        .await
        .expect("the origin connection ends with the client's")
        .unwrap();
    assert!(after.is_empty(), "the origin received: {after}");

    manager.stop();
    core.close();
}
