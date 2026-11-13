//! Holds a new flow's packets briefly while the worker attributes the flow,
//! when a routing rule reads the process; otherwise lets them through at
//! once, a TCP connection's opening SYN carrying its pending lookup. Packets
//! are never rewritten or dropped here: overload and deadlines release the
//! original bytes as unknown, and each flow keeps its order.
use super::worker::{AttributionWorker, Lookup};
use super::{ClientOwner, FlowKey, FlowProtocol, ProcessInfo, ATTRIBUTION_BUDGET};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    sync::Arc,
    time::Instant,
};
use tokio::sync::watch;

const PENDING_PACKETS: usize = 256;
const PENDING_BYTES: usize = 512 * 1024;
/// Packets one flow may hold at once. The queue used to be first come, and
/// overload released whichever packet had waited longest, whoever it belonged
/// to: a flow with packets to spare pushed out another application's single
/// SYN just before its answer arrived, and that connection then missed its
/// PROCESS-NAME rule and took another outbound -- the wrong route, not merely
/// a late one. A flow over its share now pays with its own oldest packet.
const PENDING_PER_FLOW: usize = 16;

#[derive(Debug)]
pub(crate) struct Attributed {
    pub(crate) bytes: Vec<u8>,
    pub(crate) process: ClientOwner,
}

#[derive(Debug)]
struct Pending {
    bytes: Vec<u8>,
    flow: FlowKey,
    deadline: Instant,
}

/// Owned by one packet pump run, over the Core's shared worker.
#[derive(Debug, Default)]
pub(crate) struct AttributionGate {
    worker: Option<(Arc<AttributionWorker>, watch::Receiver<u64>)>,
    /// Whether a routing rule reads the process, so a new flow's packets
    /// wait for its owner.
    holding: bool,
    pending: VecDeque<Pending>,
    /// Where [`Self::release_ready`] moves the packets that stay, kept
    /// between calls so the pass costs no allocation.
    staying: VecDeque<Pending>,
    pending_bytes: usize,
    pending_flows: HashMap<FlowKey, usize>,
}

impl AttributionGate {
    pub(crate) fn new(worker: Option<Arc<AttributionWorker>>) -> Self {
        Self {
            worker: worker.map(|worker| {
                let completions = worker.completions();
                (worker, completions)
            }),
            holding: true,
            ..Self::default()
        }
    }

    /// Follows the current policy: hold new flows for their owner only while
    /// a routing rule reads the process. Packets already held stay until
    /// their lookup or budget ends, so no flow is reordered.
    pub(crate) fn set_holding(&mut self, holding: bool) {
        self.holding = holding;
    }

    /// Whether earlier packets of `flow` wait here for its owner: a later
    /// one must queue behind them rather than go on by itself.
    pub(crate) fn holds(&self, flow: &FlowKey) -> bool {
        self.pending_flows.contains_key(flow)
    }

    /// Whether another packet of `bytes` bytes would not fit.
    fn full(&self, bytes: usize) -> bool {
        self.pending.len() >= PENDING_PACKETS || self.pending_bytes + bytes > PENDING_BYTES
    }

    /// Admits one whole IP packet. `flow` is `None` for traffic that has no
    /// attributable socket (ICMP, malformed or port-zero packets).
    pub(crate) fn admit(
        &mut self,
        bytes: Vec<u8>,
        flow: Option<(FlowKey, bool)>,
        out: &mut Vec<Attributed>,
    ) {
        let (Some((worker, _)), Some((flow, fresh_tcp_syn))) = (self.worker.as_ref(), flow) else {
            out.push(Attributed {
                bytes,
                process: ClientOwner::Known(None),
            });
            return;
        };
        if !self.pending_flows.contains_key(&flow) {
            // Only a flow's start needs its owner. A TCP connection's owner
            // goes with the SYN that opens its connection; the segments
            // after it never consult one, so they pass without a lookup
            // instead of waiting on a rescan whenever the cache entry ages.
            if flow.protocol == FlowProtocol::Tcp && !fresh_tcp_syn {
                out.push(Attributed {
                    bytes,
                    process: ClientOwner::Known(None),
                });
                return;
            }
            if !self.holding {
                // Nothing routes by process: the SYN goes on with its lookup,
                // which the connection's record awaits; a datagram takes the
                // owner the cache has, and a miss queues the lookup that later
                // datagrams of the flow find.
                let process = if fresh_tcp_syn {
                    ClientOwner::Pending(worker.request(flow, false))
                } else {
                    match worker.lookup(&flow, false, false) {
                        Lookup::Ready(process) => ClientOwner::Known(process),
                        Lookup::Pending(..) => ClientOwner::Known(None),
                    }
                };
                out.push(Attributed { bytes, process });
                return;
            }
            if let Lookup::Ready(process) = worker.lookup(&flow, fresh_tcp_syn, true) {
                out.push(Attributed {
                    bytes,
                    process: ClientOwner::Known(process),
                });
                return;
            }
        } else if fresh_tcp_syn {
            // A new SYN behind held packets still needs its own observation.
            worker.lookup(&flow, true, true);
        }
        // Reserve space first, so overload releases a held packet as unknown
        // instead of growing the queue or dropping bytes. A flow pays for its
        // own packet: its oldest goes on, which keeps its order and leaves the
        // other flows' waits alone.
        while self.holds(&flow)
            && (self.pending_flows[&flow] >= PENDING_PER_FLOW || self.full(bytes.len()))
        {
            let Some(index) = self.pending.iter().position(|held| held.flow == flow) else {
                break;
            };
            let oldest = self.pending.remove(index).expect("pending index");
            out.push(release(
                &mut self.pending_bytes,
                &mut self.pending_flows,
                oldest,
                None,
            ));
        }
        if self.full(bytes.len()) {
            // The queue is other flows' waits, each as entitled to its owner
            // as this one, and each closer to its answer. Taking one of their
            // places would trade their route for this packet's.
            out.push(Attributed {
                bytes,
                process: ClientOwner::Known(None),
            });
            return;
        }
        self.pending_bytes += bytes.len();
        *self.pending_flows.entry(flow.clone()).or_default() += 1;
        self.pending.push_back(Pending {
            bytes,
            flow,
            deadline: Instant::now() + ATTRIBUTION_BUDGET,
        });
    }

    /// Releases held packets whose lookup finished or whose budget elapsed,
    /// never ahead of an earlier held packet of the same flow.
    pub(crate) fn release_ready(&mut self, out: &mut Vec<Attributed>) {
        let Some((worker, _)) = self.worker.as_ref() else {
            return;
        };
        let now = Instant::now();
        let mut blocked = HashSet::new();
        // One pass, with what stays moving to `staying`: releasing from the
        // middle of the queue in place moved every packet behind it, every
        // time, and the state that fills the queue -- many flows waiting on
        // a lookup that is slow -- is exactly where the releases land in the
        // middle.
        let mut staying = std::mem::take(&mut self.staying);
        while let Some(pending) = self.pending.pop_front() {
            if blocked.contains(&pending.flow) {
                staying.push_back(pending);
                continue;
            }
            let process = if now >= pending.deadline {
                Some(None)
            } else if let Lookup::Ready(process) = worker.lookup(&pending.flow, false, true) {
                Some(process)
            } else {
                None
            };
            match process {
                Some(process) => out.push(release(
                    &mut self.pending_bytes,
                    &mut self.pending_flows,
                    pending,
                    process,
                )),
                None => {
                    blocked.insert(pending.flow.clone());
                    staying.push_back(pending);
                }
            }
        }
        // `pending` is empty now and `staying` holds the order it had.
        std::mem::swap(&mut self.pending, &mut staying);
        self.staying = staying;
    }

    /// The earliest held packet's deadline. Packets go in with the same
    /// budget ahead of them, so the deadlines rise with the queue and the
    /// front holds the earliest.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.pending.front().map(|pending| pending.deadline)
    }

    /// Completes after the worker finishes a batch; `None` without a worker.
    pub(crate) fn completed(&mut self) -> Option<impl Future<Output = ()> + '_> {
        let (_, completions) = self.worker.as_mut()?;
        Some(async move {
            // The gate holds the worker, so its sender outlives every wait;
            // a closed channel must still never resolve in a loop.
            if completions.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        })
    }
}

fn release(
    pending_bytes: &mut usize,
    pending_flows: &mut HashMap<FlowKey, usize>,
    pending: Pending,
    process: Option<Arc<ProcessInfo>>,
) -> Attributed {
    *pending_bytes -= pending.bytes.len();
    if let Some(count) = pending_flows.get_mut(&pending.flow) {
        *count -= 1;
        if *count == 0 {
            pending_flows.remove(&pending.flow);
        }
    }
    Attributed {
        bytes: pending.bytes,
        process: ClientOwner::Known(process),
    }
}

#[cfg(test)]
mod tests {
    use super::super::worker::tests::{flow, scanner};
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn blocked_gate() -> (AttributionGate, Arc<AtomicBool>) {
        let release = Arc::new(AtomicBool::new(false));
        let flag = release.clone();
        let worker = AttributionWorker::start(scanner(move |keys, stop| {
            while !flag.load(Ordering::Acquire) && !stop.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            keys.iter()
                .map(|_| {
                    Some(ProcessInfo {
                        name: Some("Test".into()),
                        path: Some("/Applications/Test.app/Contents/MacOS/Test".into()),
                    })
                })
                .collect()
        }));
        (AttributionGate::new(Some(Arc::new(worker))), release)
    }

    fn keyed(port: u16) -> Option<(FlowKey, bool)> {
        let mut key = flow(true);
        key.source_port = port;
        Some((key, false))
    }

    #[test]
    fn without_a_scanner_every_packet_passes_unattributed() {
        let mut gate = AttributionGate::new(None);
        let mut out = Vec::new();
        gate.admit(vec![1], keyed(1), &mut out);
        assert_eq!(out.len(), 1);
        assert!(out[0].process.known().is_none());
        assert!(gate.completed().is_none());
    }

    #[test]
    fn pending_lookup_holds_original_bytes_until_the_worker_answers() {
        let (mut gate, release) = blocked_gate();
        let mut out = Vec::new();
        gate.admit(vec![7, 7], keyed(1), &mut out);
        gate.admit(vec![9], None, &mut out);
        assert_eq!(out.len(), 1, "unkeyed traffic is never held");
        out.clear();
        release.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(2);
        while out.is_empty() {
            gate.release_ready(&mut out);
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(out[0].bytes, vec![7, 7]);
        assert_eq!(
            out[0].process.known().unwrap().name.as_deref(),
            Some("Test")
        );
        assert_eq!(gate.pending_bytes, 0);
        assert!(gate.pending_flows.is_empty());
    }

    #[test]
    fn deadline_and_overload_release_unknown_without_dropping_bytes() {
        let (mut gate, _release) = blocked_gate();
        let mut out = Vec::new();
        for index in 0..PENDING_PER_FLOW {
            gate.admit(vec![index as u8], keyed(1), &mut out);
        }
        assert!(out.is_empty(), "a flow may hold its share");
        gate.admit(vec![255], keyed(1), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].bytes,
            vec![0],
            "the flow over its share pays with its own oldest, so its order holds"
        );
        assert!(out[0].process.known().is_none());
        assert_eq!(gate.pending.len(), PENDING_PER_FLOW);
        out.clear();
        gate.pending.front_mut().unwrap().deadline = Instant::now() - Duration::from_millis(1);
        gate.release_ready(&mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].bytes, vec![1]);
        assert!(gate.pending_bytes <= PENDING_BYTES);
    }

    /// The queue full of other flows' waits: each of them is as entitled to
    /// its owner as the newcomer and closer to its answer, and one of them
    /// losing its place is one application's connection taking the wrong
    /// outbound.
    #[test]
    fn a_full_queue_releases_the_newcomer_not_the_flows_waiting_for_their_owner() {
        let (mut gate, _release) = blocked_gate();
        let mut out = Vec::new();
        for index in 0..PENDING_PACKETS {
            gate.admit(vec![index as u8], keyed(index as u16 + 1), &mut out);
        }
        assert!(out.is_empty(), "every flow holds one packet");

        gate.admit(vec![255], keyed(60_000), &mut out);

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].bytes, vec![255], "the newcomer goes on unattributed");
        assert!(out[0].process.known().is_none());
        assert_eq!(
            gate.pending.len(),
            PENDING_PACKETS,
            "every waiting flow kept its place"
        );
    }

    fn tcp(port: u16, syn: bool) -> Option<(FlowKey, bool)> {
        let mut key = flow(false);
        key.source_port = port;
        Some((key, syn))
    }

    #[test]
    fn established_tcp_segments_pass_without_a_lookup() {
        let scans = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = scans.clone();
        let worker = AttributionWorker::start(scanner(move |keys, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            vec![None; keys.len()]
        }));
        let mut gate = AttributionGate::new(Some(Arc::new(worker)));
        let mut out = Vec::new();
        for index in 0..100 {
            gate.admit(vec![index], tcp(1, false), &mut out);
        }
        assert_eq!(out.len(), 100, "no segment is held");
        assert!(out.iter().all(|packet| packet.process.known().is_none()));
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            scans.load(Ordering::SeqCst),
            0,
            "no segment asks for a scan"
        );
        assert!(gate.pending.is_empty());
    }

    #[test]
    fn a_segment_behind_its_held_syn_keeps_the_order_and_the_owner() {
        let (mut gate, release) = blocked_gate();
        let mut out = Vec::new();
        gate.admit(vec![1], tcp(1, true), &mut out);
        gate.admit(vec![2], tcp(1, false), &mut out);
        assert!(out.is_empty(), "the segment waits behind its SYN");
        release.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(2);
        while out.len() < 2 {
            gate.release_ready(&mut out);
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(out[0].bytes, vec![1]);
        assert_eq!(out[1].bytes, vec![2]);
        assert!(out[0].process.known().is_some());
    }

    #[test]
    fn without_process_rules_a_syn_goes_on_with_its_lookup() {
        let (mut gate, release) = blocked_gate();
        gate.set_holding(false);
        let mut out = Vec::new();
        gate.admit(vec![1], tcp(1, true), &mut out);
        gate.admit(vec![2], tcp(1, false), &mut out);
        assert_eq!(out.len(), 2, "nothing waits for the owner");
        let ClientOwner::Pending(lookup) =
            std::mem::replace(&mut out[0].process, ClientOwner::Known(None))
        else {
            panic!("the SYN carries its pending lookup");
        };
        release.store(true, Ordering::Release);
        let process = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(lookup.resolve());
        assert_eq!(process.unwrap().name.as_deref(), Some("Test"));
        assert!(gate.pending.is_empty());
    }

    #[test]
    fn without_process_rules_datagrams_take_the_cached_owner() {
        let (mut gate, release) = blocked_gate();
        gate.set_holding(false);
        let mut out = Vec::new();
        gate.admit(vec![1], keyed(1), &mut out);
        assert!(out[0].process.known().is_none(), "a miss passes as unknown");
        release.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            gate.admit(vec![2], keyed(1), &mut out);
            if out.last().unwrap().process.known().is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "a later datagram finds the owner"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(gate.pending.is_empty());
    }

    #[test]
    fn a_flow_never_overtakes_its_own_held_packets() {
        let (mut gate, release) = blocked_gate();
        let mut out = Vec::new();
        gate.admit(vec![1], keyed(1), &mut out);
        release.store(true, Ordering::Release);
        // Even once the lookup is answered, a second packet queues behind the
        // first rather than being emitted ahead of it.
        std::thread::sleep(Duration::from_millis(20));
        gate.admit(vec![2], keyed(1), &mut out);
        assert!(out.is_empty());
        let deadline = Instant::now() + Duration::from_secs(2);
        while out.len() < 2 {
            gate.release_ready(&mut out);
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(out[0].bytes, vec![1]);
        assert_eq!(out[1].bytes, vec![2]);
    }
}
