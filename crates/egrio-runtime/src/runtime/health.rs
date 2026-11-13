//! The platform session's connection health: the watcher that degrades the
//! Runtime when the session behind its capabilities ends.
use super::*;

impl Runtime {
    /// Changes each time the platform session behind packet capture ends
    /// while it is applied and the Runtime degrades: the connection-health
    /// port reports a lost service, or the packet data plane exits on its own
    /// (the service or the OS tunnel ended it). A host recovers by readying
    /// the platform and reloading: the degraded reload restores only what
    /// lived in that session and keeps the rest.
    pub fn subscribe_session_loss(&self) -> tokio::sync::watch::Receiver<u64> {
        self.session_loss.subscribe()
    }

    /// Ends the session-loss exemption: once a transaction touches the
    /// capabilities, nothing vouches that the retained ones are untouched.
    pub(super) fn clear_session_loss(&self) {
        self.control
            .lock()
            .expect("runtime control mutex")
            .session_lost = false;
    }

    pub(super) async fn sync_health_watcher(self: &Arc<Self>) {
        let should_watch = {
            let control = self.control.lock().expect("runtime control mutex");
            control.state == RuntimeState::Running
                && (control.spec.platform.packet_capture.is_some()
                    || control.spec.platform.route.is_some()
                    || control.spec.platform.dns.is_some()
                    || control.spec.platform.firewall.is_some())
        };
        if should_watch {
            self.start_health_watcher().await;
        } else {
            self.cancel_health_watcher();
        }
    }

    pub(super) async fn start_health_watcher(self: &Arc<Self>) {
        let Some(health) = self.ports.connection_health.clone() else {
            return;
        };
        let mut task = self.health_task.lock().expect("health task mutex");
        if task.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        let runtime = Arc::downgrade(self);
        *task = Some(self.spawn(async move {
            health.wait_disconnected().await;
            if let Some(runtime) = runtime.upgrade() {
                runtime.degrade_after_disconnect().await;
            }
        }));
    }

    pub(super) fn cancel_health_watcher(&self) {
        if let Some(task) = self.health_task.lock().expect("health task mutex").take() {
            task.abort();
        }
    }

    pub(super) async fn degrade_after_disconnect(&self) {
        let _operation = self.operation.lock().await;
        let (stored, mut errors) = {
            let mut control = self.control.lock().expect("runtime control mutex");
            if control.state != RuntimeState::Running {
                return;
            }
            control.state = RuntimeState::Degraded;
            control.session_lost = true;
            let stored = control.checkpoint.clone();
            let mut errors = Vec::new();
            if let (Some(grant), Some(stored)) = (control.lease_grant.as_ref(), stored.as_ref()) {
                if let Err(error) = self
                    .lease_coordinator
                    .mark_recovery_required(grant, stored.checkpoint.id)
                {
                    errors.push(error.to_string());
                }
            }
            (stored, errors)
        };
        if let Err(error) = self.stop_packet_task().await {
            errors.push(error.to_string());
        }
        if let Some(mut stored) = stored {
            stored.checkpoint.phase = CheckpointPhase::RecoveryRequired;
            match self
                .checkpoint_store
                .replace(stored.revision, stored.checkpoint.clone())
                .await
            {
                Ok(replaced) => stored = replaced,
                Err(error) => errors.push(error.to_string()),
            }
            self.control
                .lock()
                .expect("runtime control mutex")
                .checkpoint = Some(stored);
        }
        self.control
            .lock()
            .expect("runtime control mutex")
            .degradation_error = (!errors.is_empty()).then(|| errors.join("; "));
        self.session_loss
            .send_modify(|losses| *losses = losses.wrapping_add(1));
    }
}
