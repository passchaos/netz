//! Process-wide requested-allocation telemetry for opt-in benchmark builds.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

pub struct CountingAllocator {
    current_bytes: AtomicUsize,
    peak_bytes: AtomicUsize,
    total_allocated: AtomicUsize,
    total_freed: AtomicUsize,
    alloc_count: AtomicUsize,
    free_count: AtomicUsize,
    realloc_count: AtomicUsize,
}

pub struct Snapshot {
    pub current_bytes: usize,
    pub peak_bytes: usize,
    pub total_allocated: usize,
    pub total_freed: usize,
    pub alloc_count: usize,
    pub free_count: usize,
    pub realloc_count: usize,
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
        }
    }

    fn record_growth(&self, size: usize) {
        let current = self.current_bytes.fetch_add(size, Ordering::Relaxed) + size;
        self.peak_bytes.fetch_max(current, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc(layout);
        if !pointer.is_null() {
            self.alloc_count.fetch_add(1, Ordering::Relaxed);
            self.total_allocated
                .fetch_add(layout.size(), Ordering::Relaxed);
            self.record_growth(layout.size());
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = System.alloc_zeroed(layout);
        if !pointer.is_null() {
            self.alloc_count.fetch_add(1, Ordering::Relaxed);
            self.total_allocated
                .fetch_add(layout.size(), Ordering::Relaxed);
            self.record_growth(layout.size());
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        self.free_count.fetch_add(1, Ordering::Relaxed);
        self.total_freed.fetch_add(layout.size(), Ordering::Relaxed);
        self.current_bytes
            .fetch_sub(layout.size(), Ordering::Relaxed);
        System.dealloc(pointer, layout);
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let resized = System.realloc(pointer, layout, new_size);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_track_requested_live_and_peak_bytes() {
        let allocator = CountingAllocator::new();
        allocator.record_growth(64);
        allocator.alloc_count.fetch_add(1, Ordering::Relaxed);
        allocator.total_allocated.fetch_add(64, Ordering::Relaxed);
        allocator.record_growth(128);
        allocator.alloc_count.fetch_add(1, Ordering::Relaxed);
        allocator.total_allocated.fetch_add(128, Ordering::Relaxed);
        allocator.current_bytes.fetch_sub(64, Ordering::Relaxed);
        allocator.free_count.fetch_add(1, Ordering::Relaxed);
        allocator.total_freed.fetch_add(64, Ordering::Relaxed);

        let snapshot = allocator.snapshot();
        assert_eq!(snapshot.alloc_count, 2);
        assert_eq!(snapshot.free_count, 1);
        assert_eq!(snapshot.total_allocated, 192);
        assert_eq!(snapshot.total_freed, 64);
        assert_eq!(snapshot.current_bytes, 128);
        assert_eq!(snapshot.peak_bytes, 192);
    }
}
