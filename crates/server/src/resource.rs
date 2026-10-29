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
    h2_streams: AtomicU64,
    request_bytes: AtomicU64,
    response_bytes: AtomicU64,
    blocking_reads: AtomicU64,
    websocket_tunnels: AtomicU64,
}

/// Process-wide ceilings for work whose callers do not carry a `Config`
/// reference (PCRE expression evaluation, password hashing and compression).
/// Keeping this separate from request-worker admission prevents HTTP/2 from
/// multiplying expensive work by its per-connection stream allowance.
pub const MAX_EXPENSIVE_OPS: u64 = 32;
pub const MAX_BLOCKING_READS: u64 = 32;
pub const MAX_H2_STREAMS: u64 = 256;
pub const MAX_REQUEST_RESIDENT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_RESPONSE_RESIDENT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_WEBSOCKET_TUNNELS: u64 = 64;

static EXPENSIVE_OPS: AtomicU64 = AtomicU64::new(0);

fn try_add(counter: &AtomicU64, amount: u64, limit: u64) -> bool {
    try_add_counter(counter, amount, limit)
}

/// Small abstraction over the atomic operation used by the production
/// budget.  Keeping the admission loop generic lets the exact production
/// algorithm run under Loom's deterministic scheduler in tests.
trait BudgetCounter {
    fn load_value(&self, order: Ordering) -> u64;
    fn compare_exchange_value(
        &self,
        current: u64,
        next: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64>;
}

impl BudgetCounter for AtomicU64 {
    fn load_value(&self, order: Ordering) -> u64 {
        self.load(order)
    }

    fn compare_exchange_value(
        &self,
        current: u64,
        next: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.compare_exchange_weak(current, next, success, failure)
    }
}

#[cfg(test)]
impl BudgetCounter for loom::sync::atomic::AtomicU64 {
    fn load_value(&self, order: Ordering) -> u64 {
        self.load(order)
    }

    fn compare_exchange_value(
        &self,
        current: u64,
        next: u64,
        success: Ordering,
        failure: Ordering,
    ) -> Result<u64, u64> {
        self.compare_exchange_weak(current, next, success, failure)
    }
}

fn try_add_counter<C: BudgetCounter>(counter: &C, amount: u64, limit: u64) -> bool {
    let mut current = counter.load_value(Ordering::Acquire);
    loop {
        if !vapache_verified::resource_budget_admit(current, amount, limit) {
            return false;
        }
        let Some(next) = current.checked_add(amount) else {
            return false;
        };
        match counter.compare_exchange_value(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

impl ResourceBudget {
    pub fn try_spool(self: &Arc<Self>, max_bytes: u64, max_files: u64) -> io::Result<SpoolLease> {
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

    pub fn try_h2_stream(self: &Arc<Self>) -> io::Result<H2StreamLease> {
        if !try_add(&self.h2_streams, 1, MAX_H2_STREAMS) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "process-wide HTTP/2 stream limit reached",
            ));
        }
        Ok(H2StreamLease {
            budget: self.clone(),
            active: true,
        })
    }

    pub fn try_request_bytes(self: &Arc<Self>) -> ResidentLease {
        ResidentLease::new(
            self.clone(),
            ResidentKind::Request,
            MAX_REQUEST_RESIDENT_BYTES,
        )
    }

    pub fn try_response_bytes(self: &Arc<Self>) -> ResidentLease {
        ResidentLease::new(
            self.clone(),
            ResidentKind::Response,
            MAX_RESPONSE_RESIDENT_BYTES,
        )
    }

    pub fn try_blocking_read(self: &Arc<Self>) -> io::Result<BlockingReadLease> {
        if !try_add(&self.blocking_reads, 1, MAX_BLOCKING_READS) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "process-wide blocking-read limit reached",
            ));
        }
        Ok(BlockingReadLease {
            budget: self.clone(),
            active: true,
        })
    }

    pub fn try_websocket(self: &Arc<Self>) -> io::Result<WebsocketLease> {
        if !try_add(&self.websocket_tunnels, 1, MAX_WEBSOCKET_TUNNELS) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "process-wide WebSocket tunnel limit reached",
            ));
        }
        Ok(WebsocketLease {
            budget: self.clone(),
            active: true,
        })
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn usage(&self) -> (u64, u64, u64) {
        (
            self.spool_bytes.load(Ordering::Acquire),
            self.spool_files.load(Ordering::Acquire),
            self.dynamic_requests.load(Ordering::Acquire),
        )
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn extended_usage(&self) -> (u64, u64, u64, u64) {
        (
            self.h2_streams.load(Ordering::Acquire),
            self.request_bytes.load(Ordering::Acquire),
            self.response_bytes.load(Ordering::Acquire),
            self.blocking_reads.load(Ordering::Acquire),
        )
    }

    #[cfg(any(test, feature = "fuzzing"))]
    pub fn websocket_usage(&self) -> u64 {
        self.websocket_tunnels.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug)]
enum ResidentKind {
    Request,
    Response,
}

#[derive(Debug)]
pub struct ResidentLease {
    budget: Arc<ResourceBudget>,
    kind: ResidentKind,
    bytes: u64,
    limit: u64,
}

impl ResidentLease {
    fn new(budget: Arc<ResourceBudget>, kind: ResidentKind, limit: u64) -> Self {
        Self {
            budget,
            kind,
            bytes: 0,
            limit,
        }
    }

    fn counter(&self) -> &AtomicU64 {
        match self.kind {
            ResidentKind::Request => &self.budget.request_bytes,
            ResidentKind::Response => &self.budget.response_bytes,
        }
    }

    pub fn reserve(&mut self, amount: u64) -> io::Result<()> {
        if amount == 0 {
            return Ok(());
        }
        if !try_add(self.counter(), amount, self.limit) {
            return Err(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "process-wide resident-byte limit reached",
            ));
        }
        self.bytes = self.bytes.saturating_add(amount);
        Ok(())
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for ResidentLease {
    fn drop(&mut self) {
        self.counter().fetch_sub(self.bytes, Ordering::AcqRel);
        self.bytes = 0;
    }
}

#[derive(Debug)]
pub struct H2StreamLease {
    budget: Arc<ResourceBudget>,
    active: bool,
}

impl Drop for H2StreamLease {
    fn drop(&mut self) {
        if self.active {
            self.budget.h2_streams.fetch_sub(1, Ordering::AcqRel);
            self.active = false;
        }
    }
}

#[derive(Debug)]
pub struct BlockingReadLease {
    budget: Arc<ResourceBudget>,
    active: bool,
}

#[derive(Debug)]
pub struct WebsocketLease {
    budget: Arc<ResourceBudget>,
    active: bool,
}

impl Drop for WebsocketLease {
    fn drop(&mut self) {
        if self.active {
            self.budget.websocket_tunnels.fetch_sub(1, Ordering::AcqRel);
            self.active = false;
        }
    }
}

impl Drop for BlockingReadLease {
    fn drop(&mut self) {
        if self.active {
            self.budget.blocking_reads.fetch_sub(1, Ordering::AcqRel);
            self.active = false;
        }
    }
}

#[derive(Debug)]
pub struct ExpensiveLease {
    active: bool,
}

pub fn try_expensive() -> Option<ExpensiveLease> {
    try_add(&EXPENSIVE_OPS, 1, MAX_EXPENSIVE_OPS).then_some(ExpensiveLease { active: true })
}

impl Drop for ExpensiveLease {
    fn drop(&mut self) {
        if self.active {
            EXPENSIVE_OPS.fetch_sub(1, Ordering::AcqRel);
            self.active = false;
        }
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
            self.budget.dynamic_requests.fetch_sub(1, Ordering::AcqRel);
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
    fn process_wide_stream_memory_and_blocking_leases_release() {
        let budget = Arc::new(ResourceBudget::default());
        let stream = budget.try_h2_stream().unwrap();
        let mut request = budget.try_request_bytes();
        let mut response = budget.try_response_bytes();
        let blocking = budget.try_blocking_read().unwrap();
        request.reserve(7).unwrap();
        response.reserve(11).unwrap();
        assert_eq!(budget.extended_usage(), (1, 7, 11, 1));
        drop((stream, request, response, blocking));
        assert_eq!(budget.extended_usage(), (0, 0, 0, 0));
    }

    #[test]
    fn process_wide_h2_stream_limit_is_enforced_and_recovers() {
        let budget = Arc::new(ResourceBudget::default());
        let leases: Vec<_> = (0..MAX_H2_STREAMS)
            .map(|_| budget.try_h2_stream().unwrap())
            .collect();
        assert!(budget.try_h2_stream().is_err());
        drop(leases);
        assert!(budget.try_h2_stream().is_ok());
    }

    #[test]
    fn process_wide_websocket_limit_is_enforced_and_recovers() {
        let budget = Arc::new(ResourceBudget::default());
        let leases: Vec<_> = (0..MAX_WEBSOCKET_TUNNELS)
            .map(|_| budget.try_websocket().unwrap())
            .collect();
        assert_eq!(budget.websocket_usage(), MAX_WEBSOCKET_TUNNELS);
        assert!(budget.try_websocket().is_err());
        drop(leases);
        assert_eq!(budget.websocket_usage(), 0);
        assert!(budget.try_websocket().is_ok());
    }

    #[test]
    fn resident_lease_rejects_overflow_and_global_expensive_work_releases() {
        let budget = Arc::new(ResourceBudget::default());
        let mut resident = ResidentLease::new(budget, ResidentKind::Request, 8);
        resident.reserve(8).unwrap();
        assert!(resident.reserve(1).is_err());
        let lease = try_expensive().expect("expensive slot");
        drop(lease);
        assert!(try_expensive().is_some());
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

    #[test]
    fn loom_explores_atomic_admission_and_release_interleavings() {
        loom::model(|| {
            use loom::sync::atomic::AtomicU64 as LoomAtomicU64;
            use loom::sync::Arc as LoomArc;

            let counter = LoomArc::new(LoomAtomicU64::new(0));
            let mut workers = Vec::new();
            for _ in 0..2 {
                let counter = counter.clone();
                workers.push(loom::thread::spawn(move || {
                    if try_add_counter(&*counter, 1, 1) {
                        assert!(counter.load(Ordering::Acquire) <= 1);
                        loom::thread::yield_now();
                        counter.fetch_sub(1, Ordering::AcqRel);
                    }
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
            assert_eq!(counter.load(Ordering::Acquire), 0);
        });
    }
}
