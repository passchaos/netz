//! Process-wide allocation telemetry for the opt-in Hyper benchmark build.
//!
//! The wrapper delegates directly to Rust's system allocator and uses only
//! atomic counters, so recording an allocation cannot recursively allocate.
//! Sizes are requested bytes and intentionally exclude allocator metadata or
//! platform size-class rounding.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

const BUCKET_LIMITS: [usize; 6] = [64, 256, 1024, 4096, 16 * 1024, 64 * 1024];
const BUCKET_LABELS: [&str; 7] = ["<=64", "<=256", "<=1K", "<=4K", "<=16K", "<=64K", ">64K"];

pub struct CountingAllocator {
    current_bytes: AtomicUsize,
    peak_bytes: AtomicUsize,
    total_allocated: AtomicUsize,
    total_freed: AtomicUsize,
    alloc_count: AtomicUsize,
    free_count: AtomicUsize,
    realloc_count: AtomicUsize,
    bucket_counts: [AtomicUsize; 7],
    bucket_bytes: [AtomicUsize; 7],
}

pub struct Snapshot {
    current_bytes: usize,
    peak_bytes: usize,
    total_allocated: usize,
    total_freed: usize,
    alloc_count: usize,
    free_count: usize,
    realloc_count: usize,
    bucket_counts: [usize; 7],
    bucket_bytes: [usize; 7],
}

impl CountingAllocator {
    pub const fn new() -> Self {
        Self {
            current_bytes: AtomicUsize::new(0),
            peak_bytes: AtomicUsize::new(0),
            total_allocated: AtomicUsize::new(0),
            total_freed: AtomicUsize::new(0),
            alloc_count: AtomicUsize::new(0),
            free_count: AtomicUsize::new(0),
            realloc_count: AtomicUsize::new(0),
            bucket_counts: [const { AtomicUsize::new(0) }; 7],
            bucket_bytes: [const { AtomicUsize::new(0) }; 7],
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            current_bytes: self.current_bytes.load(Ordering::Relaxed),
            peak_bytes: self.peak_bytes.load(Ordering::Relaxed),
            total_allocated: self.total_allocated.load(Ordering::Relaxed),
            total_freed: self.total_freed.load(Ordering::Relaxed),
            alloc_count: self.alloc_count.load(Ordering::Relaxed),
            free_count: self.free_count.load(Ordering::Relaxed),
            realloc_count: self.realloc_count.load(Ordering::Relaxed),
            bucket_counts: std::array::from_fn(|index| {
                self.bucket_counts[index].load(Ordering::Relaxed)
            }),
            bucket_bytes: std::array::from_fn(|index| {
                self.bucket_bytes[index].load(Ordering::Relaxed)
            }),
        }
    }

    fn record_alloc(&self, size: usize) {
        self.alloc_count.fetch_add(1, Ordering::Relaxed);
        self.total_allocated.fetch_add(size, Ordering::Relaxed);
        self.record_growth(size);
        let bucket = bucket_index(size);
        self.bucket_counts[bucket].fetch_add(1, Ordering::Relaxed);
        self.bucket_bytes[bucket].fetch_add(size, Ordering::Relaxed);
    }

    fn record_growth(&self, size: usize) {
        let current = self.current_bytes.fetch_add(size, Ordering::Relaxed) + size;
        self.peak_bytes.fetch_max(current, Ordering::Relaxed);
    }

    fn record_free(&self, size: usize) {
        self.free_count.fetch_add(1, Ordering::Relaxed);
        self.total_freed.fetch_add(size, Ordering::Relaxed);
        self.current_bytes.fetch_sub(size, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            self.record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc_zeroed(layout);
        if !ptr.is_null() {
            self.record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.record_free(layout.size());
        System.dealloc(ptr, layout);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let resized = System.realloc(ptr, layout, new_size);
        if resized.is_null() {
            return resized;
        }
        self.realloc_count.fetch_add(1, Ordering::Relaxed);
        if new_size >= layout.size() {
            let growth = new_size - layout.size();
            self.total_allocated.fetch_add(growth, Ordering::Relaxed);
            self.record_growth(growth);
        } else {
            let shrink = layout.size() - new_size;
            self.total_freed.fetch_add(shrink, Ordering::Relaxed);
            self.current_bytes.fetch_sub(shrink, Ordering::Relaxed);
        }
        resized
    }
}

impl Snapshot {
    pub fn print(&self) {
        println!("allocator stats");
        println!("  alloc count: {}", self.alloc_count);
        println!("  free count: {}", self.free_count);
        println!("  realloc count: {}", self.realloc_count);
        println!("  total allocated bytes: {}", self.total_allocated);
        println!("  total freed bytes: {}", self.total_freed);
        println!("  live bytes: {}", self.current_bytes);
        println!("  peak live bytes: {}", self.peak_bytes);
        println!("  allocation buckets:");
        for index in 0..BUCKET_LABELS.len() {
            println!(
                "    {}: count={}, bytes={}",
                BUCKET_LABELS[index], self.bucket_counts[index], self.bucket_bytes[index]
            );
        }
    }
}

fn bucket_index(size: usize) -> usize {
    BUCKET_LIMITS
        .iter()
        .position(|limit| size <= *limit)
        .unwrap_or(BUCKET_LIMITS.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_boundaries_are_stable() {
        assert_eq!(bucket_index(64), 0);
        assert_eq!(bucket_index(65), 1);
        assert_eq!(bucket_index(64 * 1024), 5);
        assert_eq!(bucket_index(64 * 1024 + 1), 6);
    }

    #[test]
    fn snapshots_track_live_and_peak_bytes() {
        let allocator = CountingAllocator::new();
        allocator.record_alloc(64);
        allocator.record_alloc(65);
        allocator.record_free(64);
        let snapshot = allocator.snapshot();
        assert_eq!(snapshot.alloc_count, 2);
        assert_eq!(snapshot.free_count, 1);
        assert_eq!(snapshot.current_bytes, 65);
        assert_eq!(snapshot.peak_bytes, 129);
    }
}
