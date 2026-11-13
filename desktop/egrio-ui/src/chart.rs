//! The traffic chart: the rate series built from the Core's traffic volume,
//! and the paths that draw its last thirty seconds.
//!
//! Each point is a second of traffic. The chart moves a step per point and
//! stands still between points: a continuous pan keeps the window server
//! compositing every frame, which behind a translucent macOS window costs a
//! third of a core.

use egrio_desktop::operations::telemetry::TrafficVolumeSample;

use crate::node::{Path, PathCommand};

/// How often the chart reads the Core's traffic volume.
pub const SAMPLE_INTERVAL_MS: f64 = 1000.0;
/// Each point's rate averages the bytes of the last second: smooth, still prompt.
const RATE_WINDOW_MS: f64 = 1000.0;
/// A longer silence (a closed window, a stalled read) starts the series over.
pub const MAX_SAMPLE_GAP_MS: f64 = 1500.0;
/// The chart's visible span.
pub const WINDOW_MS: f64 = 30_000.0;
/// How long a peak that scrolled out keeps holding the scale up, fading.
pub const SCALE_FADE_MS: f64 = 4000.0;
/// Points kept: the window, the fade, and the point the wave starts from left of the view.
const RETAIN_MS: f64 = WINDOW_MS + SCALE_FADE_MS + 2000.0;
/// The smallest scale, so idle traffic draws a flat line rather than noise.
const MIN_SCALE: f64 = 1024.0;
/// Headroom above the highest point.
const SCALE_HEADROOM: f64 = 1.15;
/// The top of the chart the highest point may reach.
const PLOT_HEIGHT: f64 = 92.0;

/// One volume reading, stamped by the backend's monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Reading {
    at: f64,
    upload: u64,
    download: u64,
}

/// One chart point: rates in bytes per second, placed at the interface's
/// receive time.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RatePoint {
    pub at: f64,
    pub upload: f64,
    pub download: f64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RateSeries {
    /// The readings the newest rate averages over (about one second).
    readings: Vec<Reading>,
    pub points: Vec<RatePoint>,
    received_at: Option<f64>,
}

impl RateSeries {
    /// Folds one read into the series. Rates divide byte differences by the
    /// backend's stamps, so the read's own latency does not wobble the line;
    /// points sit at the interface's clock, which drives the chart's motion.
    ///
    /// - No Core (`None`) reads as zero traffic, and the next Core counts afresh.
    /// - A volume that went down belongs to a new Core generation: the rate
    ///   restarts from it instead of turning negative.
    /// - A gap longer than [`MAX_SAMPLE_GAP_MS`] drops the history: a rate
    ///   averaged across it would draw a shape nobody saw happen.
    pub fn append(&mut self, sample: Option<&TrafficVolumeSample>, received_at: f64) {
        let resumed = self
            .received_at
            .is_none_or(|previous| received_at - previous > MAX_SAMPLE_GAP_MS);
        if resumed {
            *self = Self::default();
        }
        let mut rate = (0.0, 0.0);
        let readings = match sample {
            Some(sample) => {
                let reading = Reading {
                    at: sample.at_ms,
                    upload: sample.upload_bytes,
                    download: sample.download_bytes,
                };
                let continues = self.readings.last().is_some_and(|previous| {
                    reading.at > previous.at
                        && reading.upload >= previous.upload
                        && reading.download >= previous.download
                });
                let mut readings = if continues {
                    std::mem::take(&mut self.readings)
                } else {
                    Vec::new()
                };
                readings.push(reading);
                trim_readings(&mut readings);
                let oldest = readings[0];
                let seconds = (reading.at - oldest.at) / 1000.0;
                if seconds > 0.0 {
                    rate = (
                        (reading.upload - oldest.upload) as f64 / seconds,
                        (reading.download - oldest.download) as f64 / seconds,
                    );
                }
                readings
            }
            None => Vec::new(),
        };
        self.readings = readings;
        self.points.push(RatePoint {
            at: received_at,
            upload: rate.0,
            download: rate.1,
        });
        let first_kept = self
            .points
            .iter()
            .position(|point| point.at >= received_at - RETAIN_MS)
            .unwrap_or(0);
        self.points.drain(..first_kept);
        self.received_at = Some(received_at);
    }

    /// The newest point, or zero traffic before the first read.
    pub fn latest(&self) -> RatePoint {
        self.points.last().copied().unwrap_or(RatePoint {
            at: 0.0,
            upload: 0.0,
            download: 0.0,
        })
    }

    /// The highest rate in the view that ends at the newest point.
    pub fn peak_in_view(&self) -> f64 {
        self.points
            .last()
            .map(|newest| peak_rate(&self.points, newest.at - WINDOW_MS))
            .unwrap_or(0.0)
    }
}

/// Keeps the readings inside the rate window plus the one just before it.
fn trim_readings(readings: &mut Vec<Reading>) {
    let newest = readings[readings.len() - 1];
    let first_inside = readings
        .iter()
        .position(|reading| reading.at >= newest.at - RATE_WINDOW_MS)
        .unwrap_or(0);
    readings.drain(..first_inside.saturating_sub(1));
}

/// Whether no point from `since` on, nor the last one before it, shows traffic.
pub fn is_quiet(points: &[RatePoint], since: f64) -> bool {
    for point in points.iter().rev() {
        if point.upload > 0.0 || point.download > 0.0 {
            return false;
        }
        if point.at < since {
            break;
        }
    }
    true
}

/// The highest rate among the points from `since` on.
pub fn peak_rate(points: &[RatePoint], since: f64) -> f64 {
    points
        .iter()
        .filter(|point| point.at >= since)
        .fold(0.0, |peak: f64, point| {
            peak.max(point.upload).max(point.download)
        })
}

/// The y-axis maximum for a view starting at `view_start`: every visible
/// point counts in full, and a point that has scrolled out keeps counting
/// with a weight that fades to zero over `fade_ms`. A peak leaving the chart
/// lowers the scale gradually instead of in one jump, and the result depends
/// only on the points, so every rebuild agrees.
pub fn chart_scale(points: &[RatePoint], view_start: f64, fade_ms: f64) -> f64 {
    let mut top = MIN_SCALE;
    for point in points {
        let weight = if point.at >= view_start {
            1.0
        } else {
            1.0 - (view_start - point.at) / fade_ms
        };
        if weight > 0.0 {
            top = top.max(point.upload.max(point.download) * weight);
        }
    }
    top * SCALE_HEADROOM
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TrafficPaths {
    pub download: Path,
    pub download_area: Path,
    pub upload: Path,
    pub upload_area: Path,
}

/// The wave while nothing in view shows traffic: the zero line along the
/// bottom, the same every time, so the view has nothing to change until
/// traffic shows.
fn quiet_paths() -> TrafficPaths {
    let line = Path(vec![
        PathCommand::Move(-5.0, 100.0),
        PathCommand::Line(105.0, 100.0),
    ]);
    TrafficPaths {
        download: line.clone(),
        download_area: Path::default(),
        upload: line,
        upload_area: Path::default(),
    }
}

/// The wave for the view ending at the newest point.
pub fn view_paths(series: &RateSeries) -> TrafficPaths {
    let Some(latest) = series.points.last() else {
        return TrafficPaths::default();
    };
    let view_start = latest.at - WINDOW_MS;
    // A peak fading out of the scale still shapes the line, so quiet means
    // quiet back through the fade.
    if is_quiet(&series.points, view_start - SCALE_FADE_MS) {
        return quiet_paths();
    }
    let scale = chart_scale(&series.points, view_start, SCALE_FADE_MS);
    build_paths(&series.points, view_start, WINDOW_MS, scale)
}

/// Lines and fills for the view `[view_start, view_start + window_ms]` mapped
/// to x = 0..100. They start at the last point before the view, so the left
/// edge never shows a gap; time before the first point draws as zero
/// traffic, so a young series still spans the chart. Points past the view's
/// end draw beyond x = 100.
pub fn build_paths(
    points: &[RatePoint],
    view_start: f64,
    window_ms: f64,
    scale: f64,
) -> TrafficPaths {
    if points.is_empty() {
        return TrafficPaths::default();
    }
    let from = match points.iter().position(|point| point.at >= view_start) {
        Some(first_visible) => first_visible.saturating_sub(1),
        None => points.len() - 1,
    };
    let mut drawn = points[from..].to_vec();
    if drawn[0].at > view_start {
        drawn.insert(
            0,
            RatePoint {
                at: view_start - window_ms / 20.0,
                upload: 0.0,
                download: 0.0,
            },
        );
    }
    if drawn.len() < 2 {
        return TrafficPaths::default();
    }
    let place = |at: f64, rate: f64| {
        (
            (at - view_start) / window_ms * 100.0,
            100.0 - (rate / scale).min(1.0) * PLOT_HEIGHT,
        )
    };
    let download_points: Vec<_> = drawn
        .iter()
        .map(|point| place(point.at, point.download))
        .collect();
    let upload_points: Vec<_> = drawn
        .iter()
        .map(|point| place(point.at, point.upload))
        .collect();
    let download = smooth_line(&download_points);
    let upload = smooth_line(&upload_points);
    TrafficPaths {
        download_area: area_under(&download, &download_points),
        download,
        upload_area: area_under(&upload, &upload_points),
        upload,
    }
}

/// Time-scaled Hermite tangents keep extrema even with uneven sample spacing
/// (monotone piecewise cubic, as SciPy's `PchipInterpolator`).
fn smooth_line(points: &[(f64, f64)]) -> Path {
    let intervals: Vec<f64> = points
        .windows(2)
        .map(|pair| pair[1].0 - pair[0].0)
        .collect();
    let slopes: Vec<f64> = points
        .windows(2)
        .zip(&intervals)
        .map(|(pair, width)| (pair[1].1 - pair[0].1) / width)
        .collect();
    let tangents: Vec<f64> = (0..points.len())
        .map(|index| {
            if index == 0 {
                return slopes[0];
            }
            if index == points.len() - 1 {
                return slopes[index - 1];
            }
            let (before, after) = (slopes[index - 1], slopes[index]);
            if before * after <= 0.0 {
                return 0.0;
            }
            let before_weight = 2.0 * intervals[index] + intervals[index - 1];
            let after_weight = intervals[index] + 2.0 * intervals[index - 1];
            (before_weight + after_weight) / (before_weight / before + after_weight / after)
        })
        .collect();
    let mut commands = vec![PathCommand::Move(points[0].0, points[0].1)];
    for index in 0..points.len() - 1 {
        let (start, end) = (points[index], points[index + 1]);
        let third = intervals[index] / 3.0;
        commands.push(PathCommand::Curve {
            control1: (start.0 + third, start.1 + third * tangents[index]),
            control2: (end.0 - third, end.1 - third * tangents[index + 1]),
            to: end,
        });
    }
    Path(commands)
}

fn area_under(line: &Path, points: &[(f64, f64)]) -> Path {
    let mut commands = line.0.clone();
    commands.push(PathCommand::Line(points[points.len() - 1].0, 100.0));
    commands.push(PathCommand::Line(points[0].0, 100.0));
    commands.push(PathCommand::Close);
    Path(commands)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(at_ms: f64, upload: u64, download: u64) -> TrafficVolumeSample {
        TrafficVolumeSample {
            at_ms,
            upload_bytes: upload,
            download_bytes: download,
        }
    }

    fn feed(polls: &[(f64, Option<TrafficVolumeSample>)]) -> RateSeries {
        let mut series = RateSeries::default();
        for (received_at, polled) in polls {
            series.append(polled.as_ref(), *received_at);
        }
        series
    }

    fn downloads(series: &RateSeries) -> Vec<i64> {
        series
            .points
            .iter()
            .map(|point| point.download.round() as i64)
            .collect()
    }

    #[test]
    fn rates_average_about_a_second_by_the_backend_stamps() {
        let mut series = RateSeries::default();
        for index in 0..=12u64 {
            let at = (index * 250) as f64;
            // Each read arrives a jittery few milliseconds late.
            series.append(
                Some(&sample(at, index * 25_000, index * 250_000)),
                5000.0 + at + (index % 3) as f64 * 9.0,
            );
        }
        assert_eq!(series.points[0].download, 0.0);
        assert_eq!(series.latest().download.round(), 1_000_000.0);
        assert_eq!(series.latest().upload.round(), 100_000.0);
        assert_eq!(series.readings.len(), 6);
    }

    #[test]
    fn a_volume_that_goes_down_starts_the_rate_over() {
        let series = feed(&[
            (0.0, Some(sample(0.0, 0, 1000))),
            (250.0, Some(sample(250.0, 0, 5000))),
            (500.0, Some(sample(500.0, 0, 200))),
            (750.0, Some(sample(750.0, 0, 1200))),
        ]);
        assert_eq!(downloads(&series), [0, 16_000, 0, 4000]);
    }

    #[test]
    fn no_core_reads_as_zero_and_the_next_core_counts_afresh() {
        let series = feed(&[
            (0.0, Some(sample(0.0, 0, 0))),
            (250.0, Some(sample(250.0, 0, 2500))),
            (500.0, None),
            (750.0, Some(sample(750.0, 0, 9_999_999))),
            (1000.0, Some(sample(1000.0, 0, 10_000_249))),
        ]);
        assert_eq!(downloads(&series), [0, 10_000, 0, 0, 1000]);
    }

    #[test]
    fn a_pause_longer_than_the_gap_limit_drops_the_history() {
        let mut series = feed(&[
            (0.0, Some(sample(0.0, 0, 0))),
            (250.0, Some(sample(250.0, 0, 1000))),
        ]);
        series.append(
            Some(&sample(30_000.0, 0, 9_000_000)),
            250.0 + MAX_SAMPLE_GAP_MS + 1.0,
        );
        assert_eq!(series.points.len(), 1);
        assert_eq!(series.points[0].download, 0.0);
    }

    #[test]
    fn old_points_leave_once_the_chart_and_its_fade_no_longer_need_them() {
        let mut series = RateSeries::default();
        for index in 0..400u64 {
            series.append(
                Some(&sample((index * 250) as f64, 0, index)),
                (index * 250) as f64,
            );
        }
        let newest = series.latest().at;
        assert!(series.points[0].at >= newest - 36_000.0);
        assert!(series.points.len() <= 145);
    }

    #[test]
    fn the_peak_and_quiet_checks_count_the_view() {
        let point = |at: f64, upload: f64, download: f64| RatePoint {
            at,
            upload,
            download,
        };
        let points = [point(0.0, 9000.0, 0.0), point(1000.0, 10.0, 500.0)];
        assert_eq!(peak_rate(&points, 0.0), 9000.0);
        assert_eq!(peak_rate(&points, 500.0), 500.0);
        let quiet = [
            point(0.0, 0.0, 500.0),
            point(1000.0, 0.0, 0.0),
            point(2000.0, 0.0, 0.0),
            point(3000.0, 0.0, 0.0),
        ];
        assert!(is_quiet(&quiet, 1500.0));
        assert!(!is_quiet(&quiet, 500.0));
        assert!(is_quiet(&[], 0.0));
    }

    const WINDOW: f64 = 10_000.0;
    const SCALE: f64 = 1000.0;

    fn points_at(times: &[f64], rates: &[f64]) -> Vec<RatePoint> {
        times
            .iter()
            .enumerate()
            .map(|(index, at)| RatePoint {
                at: *at,
                download: rates[index % rates.len()] / 10.0,
                upload: rates[index % rates.len()],
            })
            .collect()
    }

    /// Every curve segment moves rightwards and stays between its end points'
    /// heights: the smoothing invents no peaks or dips.
    fn assert_shape_preserved(path: &Path) {
        let mut current = (0.0, 0.0);
        for command in &path.0 {
            match *command {
                PathCommand::Move(x, y) | PathCommand::Line(x, y) => current = (x, y),
                PathCommand::Curve {
                    control1,
                    control2,
                    to,
                } => {
                    assert!(to.0 > current.0);
                    let mut previous_x = current.0;
                    for step in 0..=100 {
                        let t = step as f64 / 100.0;
                        let at = |a: f64, b: f64, c: f64, d: f64| {
                            (1.0 - t).powi(3) * a
                                + 3.0 * (1.0 - t).powi(2) * t * b
                                + 3.0 * (1.0 - t) * t * t * c
                                + t.powi(3) * d
                        };
                        let x = at(current.0, control1.0, control2.0, to.0);
                        let y = at(current.1, control1.1, control2.1, to.1);
                        assert!(x >= previous_x - 1e-9);
                        assert!(y >= current.1.min(to.1) - 0.01 && y <= current.1.max(to.1) + 0.01);
                        previous_x = x;
                    }
                    current = to;
                }
                PathCommand::Close => {}
            }
        }
    }

    #[test]
    fn a_young_series_spans_the_chart_from_a_zero_baseline() {
        let paths = build_paths(
            &points_at(&[6000.0, 6250.0, 6500.0], &[0.0, 1000.0, 500.0]),
            0.0,
            WINDOW,
            SCALE,
        );
        let PathCommand::Move(x, y) = paths.upload.0[0] else {
            panic!("starts with a move")
        };
        assert!(x < 0.0);
        assert_eq!(y, 100.0);
        let PathCommand::Curve { to, .. } = paths.upload.0[1] else {
            panic!("then a curve")
        };
        assert_eq!(to.1, 100.0, "flat until the first point");
        assert_shape_preserved(&paths.upload);
    }

    #[test]
    fn the_line_enters_from_before_the_view_and_leaves_past_its_end() {
        let times: Vec<f64> = (0..50).map(|index| (index * 250) as f64).collect();
        let paths = build_paths(
            &points_at(&times, &[300.0, 1000.0, 50.0, 700.0]),
            1100.0,
            WINDOW,
            SCALE,
        );
        assert_eq!(
            paths.download.0[0],
            PathCommand::Move(-1.0, 100.0 - (30.0 / SCALE) * 92.0)
        );
        let PathCommand::Curve { to, .. } = paths.download.0.last().unwrap() else {
            panic!()
        };
        assert!(to.0 > 100.0);
        assert_eq!(paths.download_area.0.last(), Some(&PathCommand::Close));
        assert_shape_preserved(&paths.download);
        assert_shape_preserved(&paths.upload);
    }

    #[test]
    fn rates_above_the_scale_reach_the_top_and_zero_stays_on_the_baseline() {
        let spike = build_paths(
            &points_at(&[0.0, 250.0, 500.0], &[0.0, 50_000.0, 0.0]),
            0.0,
            WINDOW,
            SCALE,
        );
        let lowest = spike
            .upload
            .0
            .iter()
            .filter_map(|command| match command {
                PathCommand::Curve { to, .. } => Some(to.1),
                _ => None,
            })
            .fold(f64::INFINITY, f64::min);
        assert_eq!(lowest, 8.0);
    }

    #[test]
    fn the_scale_holds_a_scrolled_out_peak_and_lets_it_fade() {
        let points = [
            RatePoint {
                at: 1000.0,
                upload: 100_000.0,
                download: 0.0,
            },
            RatePoint {
                at: 9000.0,
                upload: 10_000.0,
                download: 20_000.0,
            },
        ];
        assert_eq!(chart_scale(&points, 0.0, 4000.0), 100_000.0 * 1.15);
        assert_eq!(chart_scale(&points, 3000.0, 4000.0), 50_000.0 * 1.15);
        assert_eq!(chart_scale(&points, 5000.0, 4000.0), 20_000.0 * 1.15);
        assert_eq!(
            chart_scale(
                &[RatePoint {
                    at: 0.0,
                    upload: 3.0,
                    download: 4.0
                }],
                0.0,
                4000.0
            ),
            1024.0 * 1.15
        );
    }

    #[test]
    fn uneven_spacing_spikes_and_plateaus_keep_their_bounds() {
        let mut seed: u32 = 42;
        let mut random = || {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            seed as f64 / 2f64.powi(32)
        };
        let gaps = [180.0, 250.0, 260.0, 400.0, 1200.0];
        for _ in 0..100 {
            let mut times = vec![0.0];
            let mut rates = vec![0.0];
            for _ in 1..40 {
                let gap = gaps[(random() * gaps.len() as f64) as usize];
                times.push(times[times.len() - 1] + gap);
                rates.push(if random() < 0.3 { 0.0 } else { random() * 1e8 });
            }
            let paths = build_paths(&points_at(&times, &rates), 0.0, times[times.len() - 1], 1e8);
            assert_shape_preserved(&paths.download);
            assert_shape_preserved(&paths.upload);
        }
    }
}
