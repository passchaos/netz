//! RFC 9530 HTTP Content-Digest/Repr-Digest and algorithm preferences.
//! Content bytes are transfer-decoded but retain Content-Encoding. Representation
//! verification requires the caller's complete selected representation data.
const std = @import("std");
const types = @import("digest/types.zig");
const fields = @import("digest/fields.zig");
const hash = @import("digest/hash.zig");

pub const Error = types.Error;
pub const Algorithm = types.Algorithm;
pub const Algorithms = types.Algorithms;
pub const Kind = types.Kind;
pub const Policy = types.Policy;
pub const ParseOptions = types.ParseOptions;
pub const Result = types.Result;
pub const Field = fields.Field;
pub const Preferences = fields.Preferences;
pub const Set = @import("digest/value.zig").Set;
pub const max_value_bytes = @import("digest/value.zig").max_value_bytes;
pub const Hasher = hash.Hasher;
pub const HasherOptions = hash.Options;
pub const compute = hash.compute;
pub const parse = fields.parse;
pub const parseMessage = fields.parseMessage;
pub const parsePreferences = fields.parsePreferences;
pub const parsePreferenceHeaders = fields.parsePreferenceHeaders;

/// Compare every supplied enabled algorithm with constant-time comparisons.
/// `computed` must cover exactly the same content/representation as `field`.
pub fn verifyComputed(field: Field, computed: Set, policy: Policy) Error!Result {
    try policy.algorithms.validate();
    if (!field.present) {
        if (policy.required) return if (field.kind == .content) error.MissingContentDigest else error.MissingRepresentationDigest;
        return .absent;
    }
    var checked256 = false;
    var checked512 = false;
    if (policy.algorithms.sha256) if (field.values.sha256) |expected| {
        const actual = computed.sha256 orelse return error.InvalidDigestPolicy;
        if (!std.crypto.timing_safe.eql([32]u8, expected, actual)) return error.DigestMismatch;
        checked256 = true;
    };
    if (policy.algorithms.sha512) if (field.values.sha512) |expected| {
        const actual = computed.sha512 orelse return error.InvalidDigestPolicy;
        if (!std.crypto.timing_safe.eql([64]u8, expected, actual)) return error.DigestMismatch;
        checked512 = true;
    };
    if (checked256 and checked512) return .sha256_and_sha512;
    if (checked256) return .sha256;
    if (checked512) return .sha512;
    if (policy.required) return error.NoSupportedDigest;
    return .unsupported;
}

pub fn verify(kind: Kind, content_or_representation: []const u8, headers: anytype, trailers: anytype, policy: Policy) Error!Result {
    try policy.algorithms.validate();
    const field = try parseMessage(kind, headers, trailers, policy.parse);
    const enabled: Algorithms = .{
        .sha256 = policy.algorithms.sha256 and field.values.sha256 != null,
        .sha512 = policy.algorithms.sha512 and field.values.sha512 != null,
    };
    if (!field.present or (!enabled.sha256 and !enabled.sha512)) {
        return verifyComputed(field, .{}, policy);
    }
    const computed = try compute(content_or_representation, enabled);
    return verifyComputed(field, computed, policy);
}

pub fn verifyContent(content: []const u8, headers: anytype, trailers: anytype, policy: Policy) Error!Result {
    return verify(.content, content, headers, trailers, policy);
}

test {
    _ = @import("digest/tests.zig");
    _ = @import("digest/response_tests.zig");
}
