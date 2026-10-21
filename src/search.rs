//! Concurrent search over iterations with a resume-safe watermark.
//!
//! Workers claim disjoint inclusive batches under a mutex, so no iteration is assigned twice in
//! a run. The full `u64` domain is searchable: exhaustion is the `None` state of the claim
//! cursor, not a reserved value. Each active worker publishes the iteration it is currently
//! examining (the lowest one it may not have finished). The resume point is the minimum of the
//! next unclaimed iteration and all active workers' slots: every iteration below it has been
//! examined, so restarting there never skips work (it may repeat work done above it). It is
//! `None` when the whole domain has been examined.

use crate::candidate::{Deriver, address_lower, eip55};
use crate::pattern::Pattern;
use k256::SecretKey;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const BATCH: u64 = 256;

/// A matching candidate.
pub struct Found {
    pub iteration: u64,
    pub key: SecretKey,
    /// EIP-55 address without the `0x` prefix.
    pub address: String,
}

/// Result of a search run.
pub struct Outcome {
    pub found: Option<Found>,
    /// Number of candidates examined (batched counting; exact once the run has ended).
    pub completed: u64,
    /// Lowest iteration from which a restart cannot skip unexamined candidates;
    /// `None` when every iteration up to `u64::MAX` has been examined.
    pub resume_point: Option<u64>,
    pub interrupted: bool,
    pub elapsed: Duration,
}

/// Live statistics passed to the tick callback.
pub struct Snapshot {
    pub completed: u64,
    pub resume_point: Option<u64>,
    pub elapsed: Duration,
}

struct Shared {
    /// Next unclaimed iteration; `None` once the domain is exhausted.
    next: Mutex<Option<u64>>,
    /// Iteration each worker is currently examining; meaningful only while `active`.
    slots: Vec<AtomicU64>,
    active: Vec<AtomicBool>,
    completed: AtomicU64,
    halt: AtomicBool,
    found: Mutex<Option<Found>>,
}

impl Shared {
    fn new(start: u64, threads: usize) -> Self {
        Self {
            next: Mutex::new(Some(start)),
            slots: (0..threads).map(|_| AtomicU64::new(start)).collect(),
            active: (0..threads).map(|_| AtomicBool::new(true)).collect(),
            completed: AtomicU64::new(0),
            halt: AtomicBool::new(false),
            found: Mutex::new(None),
        }
    }

    /// Claims the next inclusive batch `(first, last)` for `worker`, publishing its slot while
    /// the claim lock is held. Returns `None` (and retires the worker) once exhausted.
    fn claim(&self, worker: usize) -> Option<(u64, u64)> {
        let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        let Some(first) = *next else {
            self.active[worker].store(false, Ordering::SeqCst);
            return None;
        };
        let last = first.saturating_add(BATCH - 1);
        *next = last.checked_add(1);
        self.slots[worker].store(first, Ordering::SeqCst);
        Some((first, last))
    }

    fn resume_point(&self) -> Option<u64> {
        let next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        let slots = self
            .slots
            .iter()
            .zip(&self.active)
            .filter(|(_, active)| active.load(Ordering::SeqCst))
            .map(|(slot, _)| slot.load(Ordering::SeqCst));
        slots.chain(*next).min()
    }
}

fn worker(shared: &Shared, id: usize, deriver: &Deriver, pattern: &Pattern) {
    let ci = pattern.case_insensitive();
    while !shared.halt.load(Ordering::Relaxed) {
        let Some((first, last)) = shared.claim(id) else {
            return;
        };
        let mut done = 0u64;
        for i in first..=last {
            if shared.halt.load(Ordering::Relaxed) {
                break;
            }
            shared.slots[id].store(i, Ordering::SeqCst);
            let key = deriver.secret_key(i);
            let lower = address_lower(&key);
            let address = if ci { None } else { Some(eip55(&lower)) };
            let text = match &address {
                Some(a) => a.as_str(),
                None => std::str::from_utf8(&lower).expect("hex is ASCII"),
            };
            let hit = pattern.is_match(text);
            done += 1;
            if hit {
                let address = address.unwrap_or_else(|| eip55(&lower));
                let mut slot = shared.found.lock().unwrap_or_else(|e| e.into_inner());
                if slot.as_ref().is_none_or(|f| i < f.iteration) {
                    *slot = Some(Found {
                        iteration: i,
                        key,
                        address,
                    });
                }
                shared.halt.store(true, Ordering::SeqCst);
                break;
            }
        }
        shared.completed.fetch_add(done, Ordering::Relaxed);
    }
}

/// Runs the search until a match, exhaustion, or `stop` becomes true.
///
/// `on_tick` is called on the calling thread roughly every `tick`.
pub fn run(
    seed: &[u8],
    pattern: &Pattern,
    start: u64,
    threads: usize,
    stop: &AtomicBool,
    tick: Duration,
    mut on_tick: impl FnMut(&Snapshot),
) -> Outcome {
    assert!(threads > 0, "thread count must be positive");
    let deriver = Deriver::new(seed);
    let shared = Shared::new(start, threads);
    let began = Instant::now();
    let mut last_tick = began;
    let mut interrupted = false;
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|id| {
                let (shared, deriver) = (&shared, &deriver);
                scope.spawn(move || worker(shared, id, deriver, pattern))
            })
            .collect();
        while !handles.iter().all(|h| h.is_finished()) {
            if stop.load(Ordering::SeqCst) && !shared.halt.swap(true, Ordering::SeqCst) {
                interrupted = true;
            }
            if last_tick.elapsed() >= tick {
                last_tick = Instant::now();
                on_tick(&Snapshot {
                    completed: shared.completed.load(Ordering::Relaxed),
                    resume_point: shared.resume_point(),
                    elapsed: began.elapsed(),
                });
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    });
    let resume_point = shared.resume_point();
    let completed = shared.completed.load(Ordering::Relaxed);
    let found = shared.found.into_inner().unwrap_or_else(|e| e.into_inner());
    Outcome {
        interrupted: interrupted && found.is_none(),
        found,
        completed,
        resume_point,
        elapsed: began.elapsed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_tick(_: &Snapshot) {}

    #[test]
    fn finds_known_pattern_deterministically_across_thread_counts() {
        let seed = b"bounded integration test seed";
        let pattern = Pattern::new("0x0.*", false).unwrap(); // ~1/16 per candidate
        let stop = AtomicBool::new(false);
        let one = run(seed, &pattern, 0, 1, &stop, Duration::from_secs(1), no_tick);
        let f1 = one.found.expect("match within bounded range");
        assert!(f1.address.starts_with('0'));
        // Verify against the independent single-candidate derivation.
        let key = Deriver::new(seed).secret_key(f1.iteration);
        assert_eq!(eip55(&address_lower(&key)), f1.address);
        // With several workers any match is acceptable (a higher batch may finish first), but it
        // must be a genuine match for its iteration.
        let four = run(seed, &pattern, 0, 4, &stop, Duration::from_secs(1), no_tick)
            .found
            .unwrap();
        let key = Deriver::new(seed).secret_key(four.iteration);
        assert_eq!(eip55(&address_lower(&key)), four.address);
        assert!(four.address.starts_with('0'));
    }

    #[test]
    fn resume_from_start_index_skips_nothing_before_it() {
        let seed = b"bounded integration test seed";
        let pattern = Pattern::new("0.*", true).unwrap();
        let stop = AtomicBool::new(false);
        let first = run(seed, &pattern, 0, 1, &stop, Duration::from_secs(1), no_tick)
            .found
            .unwrap()
            .iteration;
        let after = run(
            seed,
            &pattern,
            first + 1,
            2,
            &stop,
            Duration::from_secs(1),
            no_tick,
        )
        .found
        .unwrap()
        .iteration;
        assert!(after > first);
    }

    #[test]
    fn pre_set_stop_yields_resume_point_at_start() {
        let pattern = Pattern::new("ffffffffffffffffffffffffffffffffffffffff", false).unwrap();
        let stop = AtomicBool::new(true);
        let out = run(b"s", &pattern, 1000, 3, &stop, Duration::from_secs(1), no_tick);
        assert!(out.found.is_none());
        assert!(out.interrupted);
        let resume = out.resume_point.expect("not exhausted");
        assert!((1000..=1000 + BATCH * 3).contains(&resume));
    }

    #[test]
    fn full_u64_domain_is_searched_and_exhaustion_is_explicit() {
        let pattern = Pattern::new("ffffffffffffffffffffffffffffffffffffffff", false).unwrap();
        let stop = AtomicBool::new(false);
        let start = u64::MAX - 10;
        let out = run(b"s", &pattern, start, 3, &stop, Duration::from_secs(1), no_tick);
        assert!(out.found.is_none() && !out.interrupted);
        assert_eq!(out.completed, 11, "iterations start..=u64::MAX are all examined");
        assert_eq!(out.resume_point, None);
    }

    #[test]
    fn u64_max_can_match() {
        let seed = b"s";
        let key = Deriver::new(seed).secret_key(u64::MAX);
        let address = String::from_utf8(address_lower(&key).to_vec()).unwrap();
        let pattern = Pattern::new(&address, true).unwrap();
        let stop = AtomicBool::new(false);
        let out = run(
            seed,
            &pattern,
            u64::MAX,
            2,
            &stop,
            Duration::from_secs(1),
            no_tick,
        );
        assert_eq!(out.found.unwrap().iteration, u64::MAX);
    }

    #[test]
    fn resume_point_never_skips_unexamined_iterations() {
        // A worker holds a low claim while others have claimed higher batches.
        let shared = Shared::new(0, 3);
        let a = shared.claim(0).unwrap();
        let b = shared.claim(1).unwrap();
        let c = shared.claim(2).unwrap();
        assert!(
            a.1 + 1 == b.0 && b.1 + 1 == c.0,
            "claims are disjoint and contiguous"
        );
        shared.slots[1].store(b.1, Ordering::SeqCst);
        shared.slots[2].store(c.1, Ordering::SeqCst);
        shared.slots[0].store(10, Ordering::SeqCst);
        assert_eq!(shared.resume_point(), Some(10));
        shared.slots[0].store(a.1, Ordering::SeqCst);
        assert_eq!(shared.resume_point(), Some(a.1));
    }

    #[test]
    fn claims_are_unique_under_contention() {
        let shared = Shared::new(5, 4);
        let claims = Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for w in 0..4 {
                let (shared, claims) = (&shared, &claims);
                s.spawn(move || {
                    for _ in 0..100 {
                        let c = shared.claim(w).unwrap();
                        claims.lock().unwrap().push(c);
                    }
                });
            }
        });
        let mut v = claims.into_inner().unwrap();
        v.sort();
        assert_eq!(v[0].0, 5);
        for w in v.windows(2) {
            assert_eq!(w[0].1 + 1, w[1].0);
        }
    }

    #[test]
    fn claim_cursor_exhausts_at_u64_max_without_overflow() {
        let shared = Shared::new(u64::MAX - 1, 1);
        assert_eq!(shared.claim(0), Some((u64::MAX - 1, u64::MAX)));
        assert_eq!(shared.resume_point(), Some(u64::MAX - 1));
        assert_eq!(shared.claim(0), None);
        assert_eq!(shared.resume_point(), None);
    }
}
