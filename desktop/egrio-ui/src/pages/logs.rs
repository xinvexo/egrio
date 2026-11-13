//! The logs page: the backend's recent records, newest at the bottom, all of
//! them or one level, following new records while the list is scrolled to
//! its end. A record shows its time, level and whole message, wrapped; where
//! it was logged from stays in the log file.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use egrio_desktop::logging::{LogRecord, LogRecordLevel};

use crate::format;
use crate::msg::{LogsMsg, Msg};
use crate::node::{
    badge, button, card, row, segmented, spacer, table, ButtonStyle, Cell, Column, ColumnAlign,
    ColumnWidth, Icon, Node, Row, Selection, Table, Tone,
};
use crate::state::State;

/// Records the page keeps, as many as the backend's history holds.
const KEPT: usize = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFilter {
    #[default]
    All,
    Info,
    Warn,
    Error,
}

impl LogFilter {
    const ALL: [LogFilter; 4] = [
        LogFilter::All,
        LogFilter::Info,
        LogFilter::Warn,
        LogFilter::Error,
    ];

    fn admits(self, level: LogRecordLevel) -> bool {
        match self {
            LogFilter::All => true,
            LogFilter::Info => level == LogRecordLevel::Info,
            LogFilter::Warn => level == LogRecordLevel::Warn,
            LogFilter::Error => level == LogRecordLevel::Error,
        }
    }
}

/// The rows built for a revision of the records and a filter.
type RowsMemo = (u64, LogFilter, Rc<Vec<Rc<Row>>>);

/// The records the page has read, oldest first, and the rows built from them
/// for the last render.
#[derive(Debug, Default)]
pub struct LogsView {
    records: VecDeque<LogRecord>,
    /// The last record read, shown or cleared since: reading goes on after it.
    read_through: Option<u64>,
    /// Advances whenever the records change.
    revision: u64,
    memo: RefCell<Option<RowsMemo>>,
}

impl LogsView {
    /// Gives back the rows built for the last render; the next builds them.
    pub fn forget_rows(&mut self) {
        *self.memo.get_mut() = None;
    }

    /// The last record read, after which the next read continues.
    pub fn last_seq(&self) -> Option<u64> {
        self.read_through
    }

    pub fn absorb(&mut self, records: Vec<LogRecord>) {
        let Some(last) = records.last().map(|record| record.seq) else {
            return;
        };
        self.read_through = Some(last);
        self.records.extend(records);
        while self.records.len() > KEPT {
            self.records.pop_front();
        }
        self.revision += 1;
    }

    /// Forgets the records read so far; reading goes on after the last one.
    pub fn clear(&mut self) {
        self.records.clear();
        self.revision += 1;
    }

    fn rows(&self, filter: LogFilter) -> Rc<Vec<Rc<Row>>> {
        let mut memo = self.memo.borrow_mut();
        if let Some((revision, memo_filter, rows)) = memo.as_ref() {
            if *revision == self.revision && *memo_filter == filter {
                return rows.clone();
            }
        }
        let rows: Rc<Vec<Rc<Row>>> = Rc::new(
            self.records
                .iter()
                .filter(|record| filter.admits(record.level))
                .map(|record| Rc::new(record_row(record)))
                .collect(),
        );
        *memo = Some((self.revision, filter, rows.clone()));
        rows
    }
}

fn level_label(level: LogRecordLevel) -> (&'static str, Tone) {
    match level {
        LogRecordLevel::Trace => ("TRACE", Tone::Faint),
        LogRecordLevel::Debug => ("DEBUG", Tone::Muted),
        LogRecordLevel::Info => ("INFO", Tone::Accent),
        LogRecordLevel::Warn => ("WARN", Tone::Warning),
        LogRecordLevel::Error => ("ERROR", Tone::Danger),
    }
}

fn record_row(record: &LogRecord) -> Row {
    let (level, tone) = level_label(record.level);
    let mono = |text: String, tone: Tone| Cell::Text {
        text,
        tone,
        mono: true,
    };
    Row {
        key: record.seq.to_string(),
        cells: vec![
            mono(format::time_of_day((record.at / 1000) as i64), Tone::Muted),
            mono(level.into(), tone),
            mono(record.message.clone(), Tone::Default),
        ],
    }
}

pub fn view(state: &State) -> Node {
    let text = state.text();
    let filter = state.log_filter;
    let rows = state.logs.rows(filter);
    let total = state.logs.records.len();
    let count = if filter == LogFilter::All {
        total.to_string()
    } else {
        format!("{}/{total}", rows.len())
    };
    let labels = [
        text.logs_all(),
        text.logs_info(),
        text.logs_warn(),
        text.logs_error(),
    ];
    let header = row(
        12.0,
        vec![
            segmented(
                labels.into_iter().map(String::from).collect(),
                LogFilter::ALL
                    .iter()
                    .position(|candidate| *candidate == filter),
                true,
                |index| Msg::Logs(LogsMsg::Filter(LogFilter::ALL[index])),
            ),
            badge(count, Tone::Muted),
            spacer(),
            button(text.logs_clear(), ButtonStyle::Plain)
                .icon(Icon::Clear)
                .enabled(total > 0)
                .on_press(Msg::Logs(LogsMsg::Clear)),
        ],
    );
    let empty = if total == 0 {
        text.logs_empty()
    } else {
        text.logs_empty_filtered()
    };
    let column = |width, align| Column {
        title: String::new(),
        width,
        align,
        sortable: false,
    };
    let list = table(Table {
        columns: vec![
            column(ColumnWidth::Fixed(64.0), ColumnAlign::Leading),
            column(ColumnWidth::Fixed(48.0), ColumnAlign::Leading),
            column(ColumnWidth::Flexible { min: 200.0 }, ColumnAlign::Leading),
        ],
        rows,
        header: false,
        row_height: 20.0,
        selection: Selection::None,
        selected: Vec::new(),
        sort: None,
        empty: Some(empty.into()),
        follow_end: true,
        wrap: true,
        on_select: None,
        on_activate: None,
        on_sort: None,
        on_move: None,
    })
    .grow()
    .key("logs");
    card(vec![header, list]).grow()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(seq: u64, level: LogRecordLevel) -> LogRecord {
        LogRecord {
            seq,
            at: 0,
            level,
            target: "egrio".into(),
            message: format!("record {seq}"),
        }
    }

    #[test]
    fn the_page_keeps_the_newest_records_and_reads_on_after_a_clear() {
        let mut logs = LogsView::default();
        logs.absorb(
            (0..KEPT as u64 + 3)
                .map(|seq| record(seq, LogRecordLevel::Info))
                .collect(),
        );
        assert_eq!(logs.records.len(), KEPT);
        assert_eq!(logs.records.front().map(|record| record.seq), Some(3));
        logs.clear();
        assert_eq!(logs.rows(LogFilter::All).len(), 0);
        assert_eq!(
            logs.last_seq(),
            Some(KEPT as u64 + 2),
            "reading goes on after the cleared records"
        );
    }

    #[test]
    fn a_level_filter_shows_that_level_only_and_rows_are_reused() {
        let mut logs = LogsView::default();
        logs.absorb(vec![
            record(0, LogRecordLevel::Info),
            record(1, LogRecordLevel::Warn),
            record(2, LogRecordLevel::Error),
        ]);
        let warnings = logs.rows(LogFilter::Warn);
        assert_eq!(
            warnings
                .iter()
                .map(|row| row.key.as_str())
                .collect::<Vec<_>>(),
            ["1"]
        );
        assert!(
            Rc::ptr_eq(&warnings, &logs.rows(LogFilter::Warn)),
            "unchanged rows are not rebuilt"
        );
        assert_eq!(logs.rows(LogFilter::All).len(), 3);
    }
}
