//! How figures read: byte counts, rates, durations and clock times.

const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];

/// A byte count with one decimal past bytes: `512 B`, `1.5 KB`.
pub fn bytes(count: u64) -> String {
    if count < 1024 {
        return format!("{count} B");
    }
    let mut value = count as f64 / 1024.0;
    let mut unit = 1;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// A rate's figure and unit, apart: two decimals past bytes per second.
pub fn rate(bytes_per_second: f64) -> (String, &'static str) {
    const RATE_UNITS: [&str; 4] = ["B/s", "KB/s", "MB/s", "GB/s"];
    if !bytes_per_second.is_finite() || bytes_per_second <= 0.0 {
        return ("0".into(), RATE_UNITS[0]);
    }
    let mut value = bytes_per_second;
    let mut unit = 0;
    while value >= 1024.0 && unit < RATE_UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let figure = if unit == 0 {
        format!("{value:.0}")
    } else {
        format!("{value:.2}")
    };
    (figure, RATE_UNITS[unit])
}

/// A rate rounded to whole units: `12 MB/s`.
pub fn rounded_rate(bytes_per_second: f64) -> String {
    let (_, unit) = rate(bytes_per_second);
    if !bytes_per_second.is_finite() || bytes_per_second <= 0.0 {
        return format!("0 {unit}");
    }
    let mut value = bytes_per_second;
    let mut steps = 0;
    while value >= 1024.0 && steps < 3 {
        value /= 1024.0;
        steps += 1;
    }
    format!("{} {unit}", value.round() as u64)
}

/// `45s`, `3m12s`, `2h5m`.
pub fn duration(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 60 {
        return format!("{seconds}s");
    }
    if seconds < 3600 {
        let (minutes, rest) = (seconds / 60, seconds % 60);
        return if rest > 0 {
            format!("{minutes}m{rest}s")
        } else {
            format!("{minutes}m")
        };
    }
    let (hours, minutes) = (seconds / 3600, (seconds % 3600) / 60);
    if minutes > 0 {
        format!("{hours}h{minutes}m")
    } else {
        format!("{hours}h")
    }
}

/// Local month, day and time of a Unix time: `11-06 14:03:27`.
pub fn clock(unix_seconds: i64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_opt(unix_seconds, 0).single() {
        Some(time) => time.format("%m-%d %H:%M:%S").to_string(),
        None => unix_seconds.to_string(),
    }
}

/// Local time of day: `14:03:27`.
pub fn time_of_day(unix_seconds: i64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_opt(unix_seconds, 0).single() {
        Some(time) => time.format("%H:%M:%S").to_string(),
        None => unix_seconds.to_string(),
    }
}

/// Seconds with at most three decimals, trailing zeros dropped: `1.5`, `30`.
pub fn seconds(milliseconds: u64) -> String {
    let text = format!("{:.3}", milliseconds as f64 / 1000.0);
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The words of a search, in lower case: a match has every one of them.
pub fn search_terms(search: &str) -> Vec<String> {
    search.split_whitespace().map(str::to_lowercase).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_counts_use_one_decimal_past_bytes() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1023), "1023 B");
        assert_eq!(bytes(1536), "1.5 KB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MB");
        assert_eq!(bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }

    #[test]
    fn rates_split_figure_and_unit() {
        assert_eq!(rate(0.0), ("0".into(), "B/s"));
        assert_eq!(rate(f64::NAN), ("0".into(), "B/s"));
        assert_eq!(rate(512.4), ("512".into(), "B/s"));
        assert_eq!(rate(1536.0), ("1.50".into(), "KB/s"));
        assert_eq!(rate(12.5 * 1024.0 * 1024.0), ("12.50".into(), "MB/s"));
        assert_eq!(rounded_rate(12.5 * 1024.0 * 1024.0), "13 MB/s");
        assert_eq!(rounded_rate(0.0), "0 B/s");
    }

    #[test]
    fn durations_name_their_two_largest_units() {
        assert_eq!(duration(45), "45s");
        assert_eq!(duration(192), "3m12s");
        assert_eq!(duration(180), "3m");
        assert_eq!(duration(7500), "2h5m");
        assert_eq!(duration(7200), "2h");
        assert_eq!(duration(-3), "0s");
    }

    #[test]
    fn seconds_drop_trailing_zeros() {
        assert_eq!(seconds(1500), "1.5");
        assert_eq!(seconds(30_000), "30");
        assert_eq!(seconds(1234), "1.234");
    }
}
