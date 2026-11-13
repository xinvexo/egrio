//! The message record behind the message panel: operation failures, results
//! that do not show in place, and what happened in the background. Nothing
//! pops up: the title bar's capsule counts the messages and shows the newest
//! unread one on one line until it is read. The record lives in
//! memory for the process's lifetime, newest first, at most [`LIMIT`] long.

use std::collections::VecDeque;

pub const LIMIT: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Tun,
    SystemProxy,
    Configuration,
    Connections,
    Listener,
    Settings,
    Geodata,
    Rules,
    Update,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub id: u64,
    pub level: Level,
    pub source: Source,
    pub title: String,
    pub detail: Option<String>,
    pub at_unix: i64,
    /// How many times it happened in a row.
    pub count: u32,
    pub unread: bool,
}

#[derive(Debug, Default)]
pub struct MessageLog {
    entries: VecDeque<Message>,
    next_id: u64,
}

impl MessageLog {
    /// Records a message; the same source and title right after the newest
    /// entry folds into it, counting once more.
    pub fn push(
        &mut self,
        level: Level,
        source: Source,
        title: String,
        detail: Option<String>,
        at_unix: i64,
    ) {
        if let Some(newest) = self.entries.front_mut() {
            if newest.source == source && newest.title == title {
                newest.count += 1;
                newest.level = level;
                newest.detail = detail;
                newest.at_unix = at_unix;
                newest.unread = true;
                return;
            }
        }
        self.next_id += 1;
        self.entries.push_front(Message {
            id: self.next_id,
            level,
            source,
            title,
            detail,
            at_unix,
            count: 1,
            unread: true,
        });
        self.entries.truncate(LIMIT);
    }

    pub fn mark_read(&mut self) {
        for entry in &mut self.entries {
            entry.unread = false;
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// The newest message not read yet.
    pub fn newest_unread(&self) -> Option<&Message> {
        self.entries.iter().find(|entry| entry.unread)
    }

    pub fn highest_unread(&self) -> Option<Level> {
        self.entries
            .iter()
            .filter(|entry| entry.unread)
            .map(|entry| entry.level)
            .max()
    }

    /// Newest first.
    pub fn entries(&self) -> impl Iterator<Item = &Message> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeats_fold_into_the_newest_entry_and_count() {
        let mut log = MessageLog::default();
        log.push(Level::Warning, Source::Tun, "interrupted".into(), None, 1);
        log.push(
            Level::Warning,
            Source::Tun,
            "interrupted".into(),
            Some("again".into()),
            5,
        );
        let entries: Vec<_> = log.entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!((entries[0].count, entries[0].at_unix), (2, 5));
        assert_eq!(entries[0].detail.as_deref(), Some("again"));

        log.push(Level::Info, Source::Tun, "recovered".into(), None, 6);
        log.push(Level::Warning, Source::Tun, "interrupted".into(), None, 7);
        assert_eq!(
            log.entries().count(),
            3,
            "only a repeat of the newest entry folds"
        );
    }

    #[test]
    fn unread_messages_and_levels_reset_when_read() {
        let mut log = MessageLog::default();
        let unread = |log: &MessageLog| {
            (
                log.newest_unread().map(|entry| entry.title.clone()),
                log.highest_unread(),
            )
        };
        log.push(Level::Error, Source::Tun, "a".into(), None, 1);
        log.push(Level::Info, Source::Configuration, "b".into(), None, 2);
        assert_eq!(unread(&log), (Some("b".into()), Some(Level::Error)));
        log.mark_read();
        assert_eq!(unread(&log), (None, None));
        log.push(Level::Info, Source::Configuration, "b".into(), None, 3);
        assert_eq!(
            unread(&log),
            (Some("b".into()), Some(Level::Info)),
            "a repeat is unread again"
        );
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn the_record_keeps_the_newest_entries() {
        let mut log = MessageLog::default();
        for index in 0..LIMIT + 10 {
            log.push(
                Level::Info,
                Source::Connections,
                format!("{index}"),
                None,
                index as i64,
            );
        }
        assert_eq!(log.entries().count(), LIMIT);
        assert_eq!(
            log.entries().next().unwrap().title,
            format!("{}", LIMIT + 9)
        );
    }
}
