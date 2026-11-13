//! The logs page's reads and actions: the backend history's new records.

use super::Ui;
use crate::backend::Backend;
use crate::msg::LogsMsg;
use crate::state::Section;

impl<B: Backend> Ui<B> {
    pub(super) fn logs(&mut self, msg: LogsMsg) {
        match msg {
            LogsMsg::Filter(filter) => self.state.log_filter = filter,
            LogsMsg::Clear => {
                self.state.logs.clear();
                egrio_desktop::logging::clear_history();
            }
        }
    }

    /// New records every second while the logs page shows.
    pub(super) fn poll_logs(&mut self) {
        if self.main.is_some() && self.state.section == Section::Logs {
            self.load_logs();
        }
    }

    /// The records after the last one read: an in-memory read.
    pub(super) fn load_logs(&mut self) {
        let records = egrio_desktop::logging::history_after(self.state.logs.last_seq());
        self.state.logs.absorb(records);
    }
}
