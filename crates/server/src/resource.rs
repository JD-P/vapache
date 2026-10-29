//! Process-generation resource accounting for attacker-controlled dynamic I/O.
//!
//! Reservations are RAII values.  A failed parse, backend error, early return,
//! or short client connection therefore releases its bytes/slot without every
//! caller having to remember a matching decrement.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct ResourceBudget {
    spool_bytes: AtomicU64,
    spool_files: AtomicU64,
    dynamic_requests: AtomicU64,
}

fn try_add(counter: &AtomicU64, amount: u64, limit: u64) -> bool {
    counter
        .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            vapache_verified::resource_budget_admit(current, amount, limit)
                .then_some(current + amount)
        })
        .is_ok()
}

impl ResourceBudget {
    pub fn try_spool(
        self: &Arc<Self>,
        max_bytes: u64,
        max_files: u64,
    ) -> io::Result<SpoolLease> {
        if !try_add(&self.spool_files, 1, max_files) {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "aggregate spool-file limit reached",
            ));
        }
        Ok(SpoolLease {
            budget: self.clone(),
            bytes: 0,
            max_bytes,
            active: true,
        })
    }

    pub fn try_dynamic(self: &Arc<Self>, limit: u64) -> io::Result<DynamicLease> {
        if !try_add(&self.dynamic_requests, 1, limit) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "dynamic backend concurrency limit reached",
            ));
        }
        Ok(DynamicLease {
            budget: self.clone(),
            active: true,
        })
    }

    #[cfg(test)]
    pub(crate) fn usage(&self) -> (u64, u64, u64) {
        (
            self.spool_bytes.load(Ordering::Acquire),
            self.spool_files.load(Ordering::Acquire),
            self.dynamic_requests.load(Ordering::Acquire),
        )
    }
}

#[derive(Debug)]
pub struct SpoolLease {
    budget: Arc<ResourceBudget>,
    bytes: u64,
    max_bytes: u64,
    active: bool,
}

impl SpoolLease {
    pub fn reserve(&mut self, amount: u64) -> io::Result<()> {
        if amount == 0 {
            return Ok(());
        }
        if !try_add(&self.budget.spool_bytes, amount, self.max_bytes) {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "aggregate spool-byte limit reached",
            ));
        }
        self.bytes += amount;
        Ok(())
    }
}

impl Drop for SpoolLease {
    fn drop(&mut self) {
        if self.active {
            self.budget
                .spool_bytes
                .fetch_sub(self.bytes, Ordering::AcqRel);
            self.budget.spool_files.fetch_sub(1, Ordering::AcqRel);
            self.active = false;
        }
    }
}

#[derive(Debug)]
pub struct DynamicLease {
    budget: Arc<ResourceBudget>,
    active: bool,
}

impl Drop for DynamicLease {
    fn drop(&mut self) {
        if self.active {
            self.budget
                .dynamic_requests
                .fetch_sub(1, Ordering::AcqRel);
            self.active = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    #[test]
    fn aggregate_spool_and_dynamic_limits_release_on_drop() {
        let budget = Arc::new(ResourceBudget::default());
        let mut first = budget.try_spool(8, 1).unwrap();
        first.reserve(0).unwrap();
        first.reserve(8).unwrap();
        assert!(first.reserve(1).is_err());
        assert!(budget.try_spool(8, 1).is_err());
        assert_eq!(budget.usage(), (8, 1, 0));
        drop(first);

        let second = budget.try_spool(8, 1).unwrap();
        let dynamic = budget.try_dynamic(1).unwrap();
        assert!(budget.try_dynamic(1).is_err());
        assert_eq!(budget.usage(), (0, 1, 1));
        drop((second, dynamic));
        assert_eq!(budget.usage(), (0, 0, 0));
    }

    #[test]
    fn concurrent_dynamic_admission_never_exceeds_the_limit() {
        const THREADS: usize = 32;
        const LIMIT: usize = 4;
        let budget = Arc::new(ResourceBudget::default());
        let start = Arc::new(std::sync::Barrier::new(THREADS));
        let attempted = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..THREADS {
            let budget = budget.clone();
            let start = start.clone();
            let attempted = attempted.clone();
            workers.push(std::thread::spawn(move || {
                start.wait();
                let lease = budget.try_dynamic(LIMIT as u64).ok();
                attempted.fetch_add(1, AtomicOrdering::AcqRel);
                while attempted.load(AtomicOrdering::Acquire) != THREADS {
                    std::thread::yield_now();
                }
                lease.is_some()
            }));
        }
        let admitted = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, LIMIT);
        assert_eq!(budget.usage(), (0, 0, 0));
    }
}
