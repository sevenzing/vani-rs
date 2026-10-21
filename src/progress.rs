//! Progress line rendering and estimates.

use crate::pattern::{iterations_for_half, probability_by};
use crate::search::Snapshot;
use std::time::Duration;

/// Formats a duration in seconds as a short human-readable string.
pub fn format_seconds(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "n/a".into();
    }
    const YEAR: f64 = 365.0 * 86_400.0;
    if secs < 60.0 {
        format!("{secs:.0}s")
    } else if secs < 3_600.0 {
        format!("{}m{:02}s", (secs / 60.0) as u64, (secs % 60.0) as u64)
    } else if secs < 86_400.0 {
        format!(
            "{}h{:02}m",
            (secs / 3_600.0) as u64,
            (secs % 3_600.0 / 60.0) as u64
        )
    } else if secs < YEAR {
        format!("{:.1}d", secs / 86_400.0)
    } else if secs / YEAR < 1e6 {
        format!("{:.1}y", secs / YEAR)
    } else {
        format!("{:.1e}y", secs / YEAR)
    }
}

fn rate(count: u64, elapsed: Duration) -> f64 {
    let s = elapsed.as_secs_f64();
    if s > 0.0 { count as f64 / s } else { 0.0 }
}

/// Iterations still needed to reach the 50% success point after `completed` candidates
/// (zero once the point has been passed).
pub fn remaining_to_half(p: f64, completed: u64) -> f64 {
    (iterations_for_half(p) - completed as f64).max(0.0)
}

/// Estimate text for a prefix pattern with per-candidate probability `p`.
///
/// Reports the probability so far, the total 50% iteration point, and the iterations and time
/// remaining until that point at the average observed rate.
pub fn estimate(p: Option<f64>, completed: u64, avg_rate: f64) -> String {
    let Some(p) = p else {
        return "estimate unavailable (pattern is not a simple hex prefix)".into();
    };
    let by_now = probability_by(p, completed as f64) * 100.0;
    let remaining = remaining_to_half(p, completed);
    let eta = if remaining == 0.0 {
        "0s".into()
    } else if avg_rate > 0.0 {
        format_seconds(remaining / avg_rate)
    } else {
        "n/a".into()
    };
    format!(
        "~P(match so far) {by_now:.2}%, 50% point ~{:.3e} iters total, ~{remaining:.3e} remaining (~{eta})",
        iterations_for_half(p)
    )
}

/// Renders the one-line status.
pub fn status_line(snap: &Snapshot, prev: (u64, Duration), p: Option<f64>) -> String {
    let avg = rate(snap.completed, snap.elapsed);
    let cur = rate(
        snap.completed.saturating_sub(prev.0),
        snap.elapsed.saturating_sub(prev.1),
    );
    format!(
        "[{}] {} tried | {:.0}/s avg, {:.0}/s now | {}",
        format_seconds(snap.elapsed.as_secs_f64()),
        snap.completed,
        avg,
        cur,
        estimate(p, snap.completed, avg)
    )
}

/// Final statistics block text.
pub fn final_stats(completed: u64, elapsed: Duration, p: Option<f64>) -> String {
    let avg = rate(completed, elapsed);
    format!(
        "Elapsed: {}\nCandidates examined: {}\nAverage rate: {:.0}/s\n{}",
        format_seconds(elapsed.as_secs_f64()),
        completed,
        avg,
        estimate(p, completed, avg)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(format_seconds(5.0), "5s");
        assert_eq!(format_seconds(125.0), "2m05s");
        assert_eq!(format_seconds(7_500.0), "2h05m");
        assert_eq!(format_seconds(f64::INFINITY), "n/a");
        assert!(format_seconds(1e20).contains('e'));
    }

    #[test]
    fn unavailable_estimate_is_explicit() {
        assert!(estimate(None, 10, 1.0).contains("unavailable"));
        assert!(estimate(Some(1.0 / 16.0), 10, 100.0).contains('%'));
    }

    #[test]
    fn remaining_is_total_minus_completed_and_clamped() {
        let p = 1.0 / 16.0;
        let total = iterations_for_half(p);
        assert!((remaining_to_half(p, 0) - total).abs() < 1e-9);
        assert!((remaining_to_half(p, 5) - (total - 5.0)).abs() < 1e-9);
        assert_eq!(remaining_to_half(p, 1_000_000), 0.0);
    }

    #[test]
    fn estimate_reports_remaining_time_at_average_rate() {
        let p = 1e-6;
        let total = iterations_for_half(p);
        let done = 100_000u64;
        let text = estimate(Some(p), done, 1_000.0);
        assert!(text.contains(&format!("{:.3e} iters total", total)));
        assert!(text.contains(&format!("{:.3e} remaining", total - done as f64)));
        assert!(text.contains(&format_seconds((total - done as f64) / 1_000.0)));
    }

    #[test]
    fn passed_half_point_shows_zero_remaining() {
        let text = estimate(Some(1.0 / 16.0), 1_000, 100.0);
        assert!(text.contains("0.000e0 remaining (~0s)"), "{text}");
    }

    #[test]
    fn status_line_has_counts() {
        let snap = Snapshot {
            completed: 1000,
            resume_point: Some(0),
            elapsed: Duration::from_secs(10),
        };
        let l = status_line(&snap, (500, Duration::from_secs(9)), None);
        assert!(l.contains("1000 tried") && l.contains("100/s avg") && l.contains("500/s now"));
    }
}
