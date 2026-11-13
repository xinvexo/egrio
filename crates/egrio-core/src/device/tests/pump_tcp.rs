//! The packet pump's captured TCP when the capture ends.

use super::pump_udp::{ChannelPacketDevice, CLIENT};
use super::*;

const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// The next TCP segment the pump writes.
async fn next_tcp(written: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) -> Vec<u8> {
    loop {
        let packet = timeout(Duration::from_secs(5), written.recv())
            .await
            .expect("the pump writes a segment")
            .expect("the pump is running");
        if packet.get(9) == Some(&6) {
            return packet;
        }
    }
}

/// Stopping the pump, as turning TUN off does, resets a captured flow toward
/// its client before the device goes, at the number the client expects, and
/// fails the flow's relay so its upstream connection ends too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ending_capture_resets_its_flows_toward_their_clients() {
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target = upstream.local_addr().unwrap();
    let (accepted, accepted_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let _ = accepted.send(());
        let mut buffer = [0_u8; 64];
        // Held open until the relay closes its side.
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    });

    let core = Arc::new(NativeCoreDevice::compile(&direct_profile()));
    let (mut device, inject, mut written) = ChannelPacketDevice::new();
    let stop = CancellationToken::new();
    let pump = tokio::spawn({
        let core = Arc::clone(&core);
        let stop = stop.clone();
        async move {
            core.run_packet_queue(PacketQueue::ONLY, &mut device, stop)
                .await
        }
    });
    let segment = |seq, ack, flags| {
        captured_ipv4_tcp_packet(
            CLIENT,
            Ipv4Addr::LOCALHOST,
            53200,
            target.port(),
            seq,
            ack,
            flags,
            &[],
        )
        .into()
    };
    inject.send(segment(1000, 0, SYN)).unwrap();
    let syn_ack = next_tcp(&mut written).await;
    assert_eq!(captured_tcp_flags(&syn_ack), SYN | ACK);
    let server = captured_tcp_sequence_number(&syn_ack).wrapping_add(1);
    inject.send(segment(1001, server, ACK)).unwrap();
    timeout(Duration::from_secs(5), accepted_rx)
        .await
        .expect("the relay reaches the upstream")
        .unwrap();

    stop.cancel();
    let report = pump.await.unwrap();
    assert!(report.shutdown_requested);
    let mut reset = None;
    while let Ok(packet) = written.try_recv() {
        if packet.get(9) == Some(&6) && captured_tcp_flags(&packet) & RST != 0 {
            reset = Some(packet);
        }
    }
    let reset = reset.expect("the client gets a reset before the device goes");
    assert_eq!(captured_tcp_flags(&reset), RST | ACK);
    assert_eq!(captured_tcp_sequence_number(&reset), server);
    assert_eq!(captured_tcp_ack_number(&reset), 1001);
    timeout(Duration::from_secs(5), upstream_task)
        .await
        .expect("the upstream connection ends with the flow")
        .unwrap();
    core.close();
}
