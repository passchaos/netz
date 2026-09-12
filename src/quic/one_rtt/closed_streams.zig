/// Compressed set of closed stream sequence numbers for one QUIC stream type.
///
/// Stream IDs of one initiator/direction differ by four, so callers store
/// `stream_id >> 2`. Adjacent closures coalesce and the number of disjoint
/// ranges is bounded by the still-open holes in normal bounded-concurrency use.
pub const Set = @import("../../internal/exact_range_set.zig").Set;
