//! One ICMP echo over the physical uplink. Sending it is the egress guard's:
//! each platform has its own way out (see [`EgressSocketGuard::echo`]), and
//! the Core only relays echo when its guard has one.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use super::{EgressRuntime, EgressSocketGuard};

impl EgressRuntime {
    /// Whether an echo can leave over the physical uplink.
    pub(crate) fn relays_echo(&self) -> bool {
        self.echo_guard().is_some()
    }

    fn echo_guard(&self) -> Option<&Arc<dyn EgressSocketGuard>> {
        self.socket_guard
            .as_ref()
            .filter(|guard| guard.sends_echo())
    }

    /// Sends one echo request carrying `payload` to `target` and waits up to
    /// `wait` for its reply, on a blocking thread: the guards' ways out block.
    pub(crate) async fn echo(
        &self,
        target: IpAddr,
        payload: &[u8],
        wait: Duration,
    ) -> Result<(), String> {
        let guard = Arc::clone(
            self.echo_guard()
                .ok_or("the egress guard sends no ICMP echo")?,
        );
        let payload = payload.to_vec();
        tokio::task::spawn_blocking(move || guard.echo(target, &payload, wait))
            .await
            .map_err(|error| format!("ICMP echo task failed: {error}"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::{
        EgressBinding, EgressSocketContext, EgressSocketDescriptor, NativeCoreEgressConfig,
    };
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct EchoingGuard {
        echoed: Mutex<Vec<(IpAddr, Vec<u8>)>>,
    }

    impl EgressSocketGuard for EchoingGuard {
        fn protect_socket(
            &self,
            _: EgressSocketDescriptor,
            _: EgressSocketContext,
        ) -> Result<EgressBinding, String> {
            Ok(EgressBinding::unbound())
        }

        fn sends_echo(&self) -> bool {
            true
        }

        fn echo(&self, target: IpAddr, payload: &[u8], _: Duration) -> Result<(), String> {
            self.echoed.lock().unwrap().push((target, payload.to_vec()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn the_guard_sends_the_echo() {
        let guard = Arc::new(EchoingGuard::default());
        let egress = EgressRuntime::with_socket_guard(
            NativeCoreEgressConfig::default(),
            Some(guard.clone() as Arc<dyn EgressSocketGuard>),
        );
        assert!(egress.relays_echo());
        let target: IpAddr = "192.0.2.7".parse().unwrap();
        egress
            .echo(target, b"ping", Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(
            *guard.echoed.lock().unwrap(),
            vec![(target, b"ping".to_vec())]
        );

        let without = EgressRuntime::with_socket_guard(NativeCoreEgressConfig::default(), None);
        assert!(!without.relays_echo());
        assert!(without
            .echo(target, b"ping", Duration::from_secs(1))
            .await
            .is_err());
    }
}
