//! RFC 9530 field names, algorithms, and caller policy.
pub const Error = error{
    InvalidDigestField,
    DigestFieldTooLarge,
    TooManyDigestMembers,
    MissingContentDigest,
    MissingRepresentationDigest,
    NoSupportedDigest,
    DigestMismatch,
    InvalidDigestPolicy,
    InvalidDigestState,
    DigestContentTooLarge,
    BufferTooShort,
};

pub const Algorithm = enum {
    sha256,
    sha512,

    pub fn name(self: Algorithm) []const u8 {
        return switch (self) {
            .sha256 => "sha-256",
            .sha512 => "sha-512",
        };
    }
};

pub const Kind = enum {
    content,
    representation,

    pub fn name(self: Kind) []const u8 {
        return switch (self) {
            .content => "content-digest",
            .representation => "repr-digest",
        };
    }

    pub fn preferenceName(self: Kind) []const u8 {
        return switch (self) {
            .content => "want-content-digest",
            .representation => "want-repr-digest",
        };
    }
};

pub const Algorithms = struct {
    sha256: bool = true,
    sha512: bool = true,

    pub fn validate(self: Algorithms) Error!void {
        if (!self.sha256 and !self.sha512) return error.InvalidDigestPolicy;
    }
};

pub const max_dictionary_members: usize = 64;

pub const ParseOptions = struct {
    /// Total matching field bytes across headers and trailers.
    max_field_bytes: usize = 16 * 1024,
    /// Includes repeated keys and unsupported algorithms. May lower the hard
    /// 64-member bound; fixed dictionary storage never allocates.
    max_members: usize = max_dictionary_members,
};

pub const Policy = struct {
    required: bool = true,
    /// Every provided, enabled digest must match. A good SHA-512 digest cannot
    /// hide a bad SHA-256 digest when both algorithms are enabled.
    algorithms: Algorithms = .{},
    parse: ParseOptions = .{},
};

pub const Result = enum {
    absent,
    unsupported,
    sha256,
    sha512,
    sha256_and_sha512,
};
