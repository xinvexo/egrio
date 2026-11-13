use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use egrio_service::shared_memory::{ChannelLayout, ChannelMemory, RingError, RingPop};
use uuid::Uuid;

#[test]
fn ring_preserves_fifo_and_wraps_payload_at_arena_end() {
    let layout = ChannelLayout::new(4, 16, 8).unwrap();
    let channel = ChannelMemory::new(layout, Uuid::from_u128(1)).unwrap();
    let producer = channel.rx_ring();
    let consumer = channel.rx_ring();

    producer.try_push(&[1, 2, 3, 4, 5, 6]).unwrap();
    assert_eq!(consumer.try_pop().unwrap().packet(), &[1, 2, 3, 4, 5, 6]);
    producer.try_push(&[7, 8, 9, 10, 11, 12, 13, 14]).unwrap();
    assert_eq!(
        consumer.try_pop().unwrap().packet(),
        &[7, 8, 9, 10, 11, 12, 13, 14]
    );
}

#[test]
fn a_packet_in_parts_lands_whole_even_across_the_arena_end() {
    let layout = ChannelLayout::new(4, 16, 12).unwrap();
    let channel = ChannelMemory::new(layout, Uuid::from_u128(3)).unwrap();
    let ring = channel.tx_ring();

    ring.try_push(&[0; 10]).unwrap();
    assert_eq!(ring.try_pop().unwrap().packet(), &[0; 10]);
    // Starts at offset 10 of 16: the second part wraps to the arena start.
    ring.try_push_parts(&[&[1, 2, 3], &[4, 5, 6, 7, 8], &[], &[9]])
        .unwrap();
    assert_eq!(
        ring.try_pop().unwrap().packet(),
        &[1, 2, 3, 4, 5, 6, 7, 8, 9]
    );
    assert_eq!(
        ring.try_push_parts(&[&[0; 8], &[0; 5]]).unwrap_err(),
        RingError::PacketTooLarge,
        "the parts together exceed the largest packet"
    );
}

#[test]
fn descriptor_and_payload_capacity_apply_backpressure_without_overwrite() {
    let layout = ChannelLayout::new(2, 8, 4).unwrap();
    let channel = ChannelMemory::new(layout, Uuid::from_u128(2)).unwrap();
    let ring = channel.tx_ring();

    ring.try_push(&[1, 2, 3, 4]).unwrap();
    ring.try_push(&[5, 6, 7, 8]).unwrap();
    assert_eq!(ring.try_push(&[9]).unwrap_err(), RingError::WouldBlock);
    assert_eq!(ring.try_pop().unwrap().packet(), &[1, 2, 3, 4]);
    ring.try_push(&[9]).unwrap();
    assert_eq!(ring.try_pop().unwrap().packet(), &[5, 6, 7, 8]);
    assert_eq!(ring.try_pop().unwrap().packet(), &[9]);
    assert_eq!(ring.try_pop().unwrap_err(), RingError::WouldBlock);
}

#[test]
fn a_push_wakes_the_consumer_only_while_it_waits() {
    let channel =
        ChannelMemory::new(ChannelLayout::new(4, 64, 16).unwrap(), Uuid::from_u128(5)).unwrap();
    let ring = channel.tx_ring();

    ring.try_push(&[1]).unwrap();
    assert!(!ring.consumer_needs_wake(), "nobody waits");
    assert!(
        !ring.begin_consumer_wait(),
        "a pending packet is popped instead of parking"
    );
    assert_eq!(ring.try_pop().unwrap().packet(), &[1]);
    assert!(
        ring.begin_consumer_wait(),
        "an empty ring parks the consumer"
    );
    ring.try_push(&[2]).unwrap();
    assert!(ring.consumer_needs_wake(), "the parked consumer is woken");
    assert!(!ring.consumer_needs_wake(), "one wakeup per wait");
}

#[test]
fn a_waiting_producer_wakes_once_the_ring_drained_to_half() {
    // Bound by descriptors: eight slots, woken at four.
    let channel =
        ChannelMemory::new(ChannelLayout::new(8, 1024, 16).unwrap(), Uuid::from_u128(6)).unwrap();
    let ring = channel.tx_ring();
    for packet in 0_u8..8 {
        ring.try_push(&[packet]).unwrap();
    }
    assert_eq!(ring.try_push(&[8]).unwrap_err(), RingError::WouldBlock);
    assert!(ring.begin_producer_wait(), "a full ring parks the producer");
    for popped in 1..=3 {
        ring.try_pop().unwrap();
        assert!(
            !ring.producer_needs_wake(),
            "{popped} pops leave it above half"
        );
    }
    ring.try_pop().unwrap();
    assert!(
        ring.producer_needs_wake(),
        "half drained wakes the producer"
    );
    assert!(!ring.producer_needs_wake(), "one wakeup per wait");
    assert!(
        !ring.begin_producer_wait(),
        "a ring at the watermark does not park the producer"
    );

    // Bound by payload bytes: four 16-byte packets fill 64 bytes.
    let channel =
        ChannelMemory::new(ChannelLayout::new(64, 64, 16).unwrap(), Uuid::from_u128(7)).unwrap();
    let ring = channel.rx_ring();
    for packet in 0_u8..4 {
        ring.try_push(&[packet; 16]).unwrap();
    }
    assert_eq!(ring.try_push(&[4; 16]).unwrap_err(), RingError::WouldBlock);
    assert!(ring.begin_producer_wait());
    ring.try_pop().unwrap();
    assert!(
        !ring.producer_needs_wake(),
        "48 of 64 bytes are still in use"
    );
    ring.try_pop().unwrap();
    assert!(
        ring.producer_needs_wake(),
        "32 of 64 bytes reach the watermark"
    );

    // An arena under two packets wakes the producer only once the largest
    // packet fits: 10 of 32 bytes in use leave 22, too few for 24.
    let channel =
        ChannelMemory::new(ChannelLayout::new(8, 32, 24).unwrap(), Uuid::from_u128(9)).unwrap();
    let ring = channel.tx_ring();
    ring.try_push(&[1; 10]).unwrap();
    ring.try_push(&[2; 10]).unwrap();
    assert_eq!(ring.try_push(&[3; 24]).unwrap_err(), RingError::WouldBlock);
    assert!(ring.begin_producer_wait());
    ring.try_pop().unwrap();
    assert!(
        !ring.producer_needs_wake(),
        "a 24-byte packet does not fit yet"
    );
    ring.try_pop().unwrap();
    assert!(ring.producer_needs_wake(), "an empty arena fits it");
    ring.try_push(&[3; 24]).unwrap();
}

#[test]
fn corrupt_header_is_rejected_before_ring_access() {
    let layout = ChannelLayout::new(4, 64, 32).unwrap();
    let mut bytes = vec![0_u8; layout.mapping_len()];
    assert_eq!(
        ChannelMemory::from_bytes(&mut bytes).unwrap_err(),
        RingError::InvalidHeader
    );
}

#[test]
fn blocking_helpers_honor_notifications_and_cancellation() {
    let layout = ChannelLayout::new(1, 4, 4).unwrap();
    let channel = ChannelMemory::new(layout, Uuid::from_u128(4)).unwrap();
    let ring = channel.tx_ring();
    // A consumer is parked, so the push signals it; the parked producer below
    // is signaled by the pop that empties the ring.
    assert!(ring.begin_consumer_wait());
    let mut data_notifications = 0;
    ring.push_until(
        &[1, 2, 3, 4],
        || panic!("space wait must not run"),
        || {
            data_notifications += 1;
            Ok(())
        },
        || false,
    )
    .unwrap();
    assert_eq!(data_notifications, 1);
    assert_eq!(
        ring.push_until(&[5], || Ok(()), || Ok(()), || true)
            .unwrap_err(),
        RingError::Cancelled
    );

    assert!(ring.begin_producer_wait());
    let mut space_notifications = 0;
    let packet = ring
        .pop_until(
            || panic!("data wait must not run"),
            || {
                space_notifications += 1;
                Ok(())
            },
            || false,
        )
        .unwrap();
    assert_eq!(packet, [1, 2, 3, 4]);
    assert_eq!(space_notifications, 1);
    assert_eq!(
        ring.pop_until(|| Ok(()), || Ok(()), || true).unwrap_err(),
        RingError::Cancelled
    );
}

/// An auto-reset event, as the Windows ring events are: a signal releases
/// one wait, and a signal without a waiter is kept for the next wait.
#[derive(Default)]
struct AutoResetEvent {
    set: Mutex<bool>,
    changed: Condvar,
}

impl AutoResetEvent {
    fn signal(&self) {
        *self.set.lock().unwrap() = true;
        self.changed.notify_one();
    }

    fn wait(&self) {
        let mut set = self.set.lock().unwrap();
        while !*set {
            set = self.changed.wait(set).unwrap();
        }
        *set = false;
    }
}

/// The wait flags must never lose a wakeup: a producer and a consumer that
/// park on events whenever the ring is full or empty move every packet. A
/// lost wakeup parks both sides for good and the run times out.
#[test]
fn parked_producer_and_consumer_never_lose_a_wakeup() {
    const PACKETS: u64 = 200_000;
    let channel = Arc::new(
        ChannelMemory::new(ChannelLayout::new(4, 64, 16).unwrap(), Uuid::from_u128(8)).unwrap(),
    );
    let data = Arc::new(AutoResetEvent::default());
    let space = Arc::new(AutoResetEvent::default());
    let parks = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
    let (done_tx, done_rx) = mpsc::channel();

    let producer = {
        let (channel, data, space, parks, done_tx) = (
            Arc::clone(&channel),
            Arc::clone(&data),
            Arc::clone(&space),
            Arc::clone(&parks),
            done_tx.clone(),
        );
        thread::spawn(move || {
            let ring = channel.rx_ring();
            for sequence in 0..PACKETS {
                ring.push_until(
                    &sequence.to_le_bytes(),
                    || {
                        parks[0].fetch_add(1, Ordering::Relaxed);
                        space.wait();
                        Ok(())
                    },
                    || {
                        data.signal();
                        Ok(())
                    },
                    || false,
                )
                .unwrap();
            }
            done_tx.send("producer").unwrap();
        })
    };
    let consumer = {
        let (channel, data, space, parks) = (
            Arc::clone(&channel),
            Arc::clone(&data),
            Arc::clone(&space),
            Arc::clone(&parks),
        );
        thread::spawn(move || {
            let ring = channel.rx_ring();
            for expected in 0..PACKETS {
                let packet = ring
                    .pop_until(
                        || {
                            parks[1].fetch_add(1, Ordering::Relaxed);
                            data.wait();
                            Ok(())
                        },
                        || {
                            space.signal();
                            Ok(())
                        },
                        || false,
                    )
                    .unwrap();
                assert_eq!(u64::from_le_bytes(packet.try_into().unwrap()), expected);
            }
            done_tx.send("consumer").unwrap();
        })
    };

    for _ in 0..2 {
        done_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("both sides finish: no wakeup was lost");
    }
    producer.join().unwrap();
    consumer.join().unwrap();
    assert!(
        parks[0].load(Ordering::Relaxed) > 0 && parks[1].load(Ordering::Relaxed) > 0,
        "both sides parked"
    );
}

#[test]
fn producer_and_consumer_survive_one_hundred_thousand_wraps() {
    let layout = ChannelLayout::new(64, 4096, 64).unwrap();
    let channel = Arc::new(ChannelMemory::new(layout, Uuid::from_u128(3)).unwrap());
    let producer_channel = channel.clone();
    let producer = thread::spawn(move || {
        let ring = producer_channel.rx_ring();
        for sequence in 0_u64..100_000 {
            let packet = sequence.to_le_bytes();
            loop {
                match ring.try_push(&packet) {
                    Ok(_) => break,
                    Err(RingError::WouldBlock) => thread::yield_now(),
                    Err(error) => panic!("producer failed: {error:?}"),
                }
            }
        }
    });
    let consumer_channel = channel.clone();
    let consumer = thread::spawn(move || {
        let ring = consumer_channel.rx_ring();
        for expected in 0_u64..100_000 {
            let packet = loop {
                match ring.try_pop() {
                    Ok(RingPop { packet, .. }) => break packet,
                    Err(RingError::WouldBlock) => thread::yield_now(),
                    Err(error) => panic!("consumer failed: {error:?}"),
                }
            };
            assert_eq!(u64::from_le_bytes(packet.try_into().unwrap()), expected);
        }
    });

    producer.join().unwrap();
    consumer.join().unwrap();
}

#[test]
fn peek_does_not_release_packet_until_commit() {
    let channel =
        ChannelMemory::new(ChannelLayout::new(2, 64, 32).unwrap(), Uuid::from_u128(4)).unwrap();
    let ring = channel.tx_ring();
    ring.try_push(&[1, 2, 3]).unwrap();

    let first = ring.try_peek().unwrap();
    let mut packet = [0; 3];
    ring.copy_peeked(&first, &mut packet);
    assert_eq!(packet, [1, 2, 3]);
    assert_eq!(ring.try_peek().unwrap().sequence, first.sequence);
    ring.commit_peek(&first).unwrap();

    assert_eq!(ring.try_peek().unwrap_err(), RingError::WouldBlock);
}
