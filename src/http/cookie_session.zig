//! Single-owner CookieJar composition for the unified HTTP Pool.
//!
//! Cookie headers are derived afresh for every URI. Redirect responses commit
//! Set-Cookie before Location is followed, while the existing redirect engine
//! continues to own method replay, credential isolation, and deadline policy.

const std = @import("std");
const client = @import("client.zig");
const client_pool = @import("client_pool.zig");
const request_ops = @import("client_pool/requests.zig");
const redirect = @import("client/redirect.zig");
const uri_redirect = @import("../http1/runtime/redirect.zig");
const deadline_policy = @import("../internal/deadline.zig");
const cookies = @import("cookies/mod.zig");

pub const InitError = client_pool.Error || cookies.Error;
pub const Error = client_pool.OperationError || cookies.Error || error{
    CookieHeaderConflict,
};

pub const Options = struct {
    request_context: cookies.RequestContext = .{},
    store_context: cookies.StoreContext = .{},
    /// Without a registrable-domain callback, treating a new origin as
    /// cross-site is the conservative SameSite boundary. Set false only when
    /// the application has established that its redirect is same-site.
    cross_origin_is_cross_site: bool = true,
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    pool: client_pool.Pool,
    jar: cookies.Jar,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        pool_options: client_pool.Options,
        cookie_options: cookies.Config,
    ) InitError!Session {
        var pool = try client_pool.Pool.init(allocator, io, pool_options);
        errdefer pool.deinit();
        return .{
            .allocator = allocator,
            .io = io,
            .pool = pool,
            .jar = try cookies.Jar.init(allocator, cookie_options),
        };
    }

    pub fn deinit(self: *Session) void {
        self.pool.deinit();
        self.jar.deinit();
        self.* = undefined;
    }

    pub fn close(self: *Session) void {
        self.pool.close();
    }

    pub fn requestUri(
        self: *Session,
        uri_text: []const u8,
        request: client.RequestOptions,
        options: Options,
    ) Error!client.OwnedResponse {
        return self.requestBefore(
            uri_text,
            request,
            options,
            null,
            false,
            .{},
        );
    }

    pub fn requestUriWithTimeout(
        self: *Session,
        uri_text: []const u8,
        request: client.RequestOptions,
        options: Options,
        timeout: std.Io.Duration,
    ) Error!client.OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestUriWithDeadline(
            uri_text,
            request,
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestUriWithDeadline(
        self: *Session,
        uri_text: []const u8,
        request: client.RequestOptions,
        options: Options,
        deadline: std.Io.Clock.Timestamp,
    ) Error!client.OwnedResponse {
        return self.requestBefore(
            uri_text,
            request,
            options,
            try deadline_policy.usableAwake(self.io, deadline),
            false,
            .{},
        );
    }

    pub fn requestUriFollowingRedirects(
        self: *Session,
        uri_text: []const u8,
        request: client.RequestOptions,
        redirect_options: client.RedirectOptions,
        cookie_options: Options,
    ) Error!client.OwnedResponse {
        var result = try self.followDetailedBefore(
            uri_text,
            request,
            redirect_options,
            cookie_options,
            null,
        );
        return result.takeResponse();
    }

    pub fn requestUriFollowingRedirectsDetailed(
        self: *Session,
        uri_text: []const u8,
        request: client.RequestOptions,
        redirect_options: client.RedirectOptions,
        cookie_options: Options,
    ) Error!client.RedirectedResponse {
        return self.followDetailedBefore(
            uri_text,
            request,
            redirect_options,
            cookie_options,
            null,
        );
    }

    pub fn requestUriFollowingRedirectsWithTimeout(
        self: *Session,
        uri_text: []const u8,
        request: client.RequestOptions,
        redirect_options: client.RedirectOptions,
        cookie_options: Options,
        timeout: std.Io.Duration,
    ) Error!client.OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestUriFollowingRedirectsWithDeadline(
            uri_text,
            request,
            redirect_options,
            cookie_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestUriFollowingRedirectsWithDeadline(
        self: *Session,
        uri_text: []const u8,
        request: client.RequestOptions,
        redirect_options: client.RedirectOptions,
        cookie_options: Options,
        deadline: std.Io.Clock.Timestamp,
    ) Error!client.OwnedResponse {
        var result = try self.followDetailedBefore(
            uri_text,
            request,
            redirect_options,
            cookie_options,
            try deadline_policy.usableAwake(self.io, deadline),
        );
        return result.takeResponse();
    }

    pub fn requestUriFollowingRedirectsDetailedWithTimeout(
        self: *Session,
        uri_text: []const u8,
        request: client.RequestOptions,
        redirect_options: client.RedirectOptions,
        cookie_options: Options,
        timeout: std.Io.Duration,
    ) Error!client.RedirectedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestUriFollowingRedirectsDetailedWithDeadline(
            uri_text,
            request,
            redirect_options,
            cookie_options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestUriFollowingRedirectsDetailedWithDeadline(
        self: *Session,
        uri_text: []const u8,
        request: client.RequestOptions,
        redirect_options: client.RedirectOptions,
        cookie_options: Options,
        deadline: std.Io.Clock.Timestamp,
    ) Error!client.RedirectedResponse {
        return self.followDetailedBefore(
            uri_text,
            request,
            redirect_options,
            cookie_options,
            try deadline_policy.usableAwake(self.io, deadline),
        );
    }

    fn followDetailedBefore(
        self: *Session,
        uri_text: []const u8,
        request: client.RequestOptions,
        redirect_options: client.RedirectOptions,
        cookie_options: Options,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!client.RedirectedResponse {
        var driver = RedirectDriver{
            .allocator = self.allocator,
            .session = self,
            .options = cookie_options,
        };
        return redirect.followDetailed(
            Error,
            &driver,
            uri_text,
            request,
            redirect_options,
            deadline,
            RedirectAdapter,
        );
    }

    fn requestBefore(
        self: *Session,
        uri_text: []const u8,
        request: client.RequestOptions,
        options: Options,
        deadline: ?std.Io.Clock.Timestamp,
        crossed_origin: bool,
        redirect_policy: uri_redirect.Policy,
    ) Error!client.OwnedResponse {
        for (request.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "cookie") or
                std.ascii.eqlIgnoreCase(header.name, "cookie2"))
            {
                return error.CookieHeaderConflict;
            }
        }
        var request_context = contextForRedirect(
            options.request_context,
            crossed_origin,
            options.cross_origin_is_cross_site,
        );
        request_context.method = request.method;
        request_context.http_api = true;
        var store_context = storeContextForRedirect(
            options.store_context,
            crossed_origin,
            options.cross_origin_is_cross_site,
        );
        store_context.http_api = true;
        const before = std.Io.Clock.real.now(self.io).toSeconds();
        const cookie_value = try self.jar.cookieHeaderValueAlloc(
            self.allocator,
            uri_text,
            before,
            request_context,
        );
        defer self.allocator.free(cookie_value);

        var owned_headers: ?[]client.Header = null;
        defer if (owned_headers) |headers| self.allocator.free(headers);
        var effective_request = request;
        if (cookie_value.len != 0) {
            const headers = try self.allocator.alloc(
                client.Header,
                request.headers.len + 1,
            );
            @memcpy(headers[0..request.headers.len], request.headers);
            headers[request.headers.len] = .{
                .name = "cookie",
                .value = cookie_value,
                .never_indexed = true,
            };
            owned_headers = headers;
            effective_request.headers = headers;
        }

        var response = try request_ops.requestUriBefore(
            &self.pool,
            uri_text,
            effective_request,
            deadline,
            crossed_origin,
            redirect_policy.allow_cross_origin_client_identity,
        );
        errdefer response.deinit();
        _ = try self.jar.storeResponse(
            response,
            uri_text,
            std.Io.Clock.real.now(self.io).toSeconds(),
            store_context,
        );
        return response;
    }
};

const RedirectDriver = struct {
    allocator: std.mem.Allocator,
    session: *Session,
    options: Options,
};

const RedirectAdapter = struct {
    pub fn request(
        driver: *RedirectDriver,
        uri_text: []const u8,
        request_options: client.RequestOptions,
        deadline: ?std.Io.Clock.Timestamp,
        crossed_origin: bool,
        policy: uri_redirect.Policy,
    ) Error!client.OwnedResponse {
        return driver.session.requestBefore(
            uri_text,
            request_options,
            driver.options,
            deadline,
            crossed_origin,
            policy,
        );
    }

    pub fn clientIdentityConfigured(driver: *const RedirectDriver) bool {
        const pool = &driver.session.pool;
        if (pool.options.client.tls.client_identity != null) return true;
        return if (pool.options.http3) |options|
            options.handshake.handshake.client_identity != null
        else
            false;
    }
};

fn contextForRedirect(
    initial: cookies.RequestContext,
    crossed_origin: bool,
    conservative_cross_site: bool,
) cookies.RequestContext {
    var result = initial;
    if (crossed_origin and conservative_cross_site) result.site = .cross_site;
    return result;
}

fn storeContextForRedirect(
    initial: cookies.StoreContext,
    crossed_origin: bool,
    conservative_cross_site: bool,
) cookies.StoreContext {
    var result = initial;
    if (crossed_origin and conservative_cross_site) result.site = .cross_site;
    return result;
}
