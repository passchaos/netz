'use strict';
const assert = require('node:assert/strict');

function frame(payload) {
  const body = Buffer.from(payload);
  const prefix = Buffer.alloc(5);
  prefix.writeUInt32BE(body.length, 1);
  return Buffer.concat([prefix, body]);
}

// This peer uses Node's HTTP/2 framing and literal protobuf wire messages.
// The native client signals after checking all three fail-fast entry points,
// so the retry cannot become healthy before those checks complete.
class HealthGatePeer {
  constructor(fail) {
    this.fail = fail;
    this.watches = 0;
    this.calls = 0;
    this.resume = false;
    this.watch = null;
    this.connectionClosed = false;
    this.pendingChecked = false;
    this.controlPings = 0;
    this.closed = new Promise(resolve => { this.resolveClosed = resolve; });
  }

  allowRecovery() {
    this.resume = true;
    // Zero capacity keeps the next Watch from starting before the native
    // client has checked rejection in TRANSIENT_FAILURE.
    this.session.settings({maxConcurrentStreams:1});
  }

  allowServing() {
    this.pendingChecked = true;
    assert.ok(this.watch && !this.watch.headersSent);
    this.serve();
  }

  serve() {
    if (this.watch.headersSent) return;
    this.watch.respond({':status':200, 'content-type':'application/grpc'}, {waitForTrailers:true});
    this.watch.once('wantTrailers', () => this.watch.sendTrailers({'grpc-status':'12'}));
    this.watch.write(frame([8,1])); // HealthCheckResponse { status: SERVING }
  }

  handle(stream, headers) {
    const isWatch = headers[':path'] === '/grpc.health.v1.Health/Watch';
    const isCall = headers[':path'] === '/fixture.Health/Echo';
    if (!isWatch && !isCall) return false;
    const chunks = [];
    let size = 0;
    const expected = isWatch ? frame(Buffer.concat([Buffer.from([10,9]), Buffer.from('demo.Echo')])) : frame('ping');
    stream.on('error', () => {});
    stream.on('data', chunk => {
      size += chunk.length;
      if (size > expected.length) { this.fail(new Error('health request exceeded its exact wire length')); stream.close(1); }
      else chunks.push(chunk);
    });
    stream.on('end', () => {
      this.complete(stream, headers, isWatch, Buffer.concat(chunks), expected).catch(this.fail);
    });
    return true;
  }

  async complete(stream, headers, isWatch, body, expected) {
    assert.deepEqual(body, expected);
    assert.ok(['application/grpc', 'application/grpc+proto'].includes(headers['content-type']));
    if (isWatch) {
      assert.equal(headers['grpc-timeout'], undefined, 'Watch must not inherit a polling deadline');
      this.watches++;
      assert.ok(this.watches <= 2, 'disabled Watch was retried');
      if (this.watches === 1) {
        this.session = stream.session;
        this.session.on('ping', () => { this.controlPings++; });
        this.session.once('close', () => {
          this.connectionClosed = true;
          this.resolveClosed();
        });
        this.session.settings({maxConcurrentStreams:0});
        stream.respond({':status':200, 'content-type':'application/grpc', 'grpc-status':'14'}, {endStream:true});
      } else {
        assert.equal(stream.session, this.session, 'Watch retry must reuse its dedicated connection');
        this.watch = stream;
        assert.equal(this.resume, true, 'a new Watch started before fail-fast checks completed');
      }
      return;
    }
    this.calls++;
    assert.ok(this.calls <= 2, 'fail-fast health rejection reached the business peer');
    assert.ok(this.watch?.headersSent, 'business RPC preceded SERVING');
    assert.notEqual(stream.session, this.session, 'Watch and application readers need independent connections');
    if (this.calls === 2) {
      let timer;
      try {
        await Promise.race([this.closed, new Promise((_,reject) => { timer = setTimeout(() => reject(new Error('disabled Watch connection was retained')), 3000); })]);
      } finally { clearTimeout(timer); }
      assert.equal(stream.session, this.application, 'application calls must reuse their connection');
    } else this.application = stream.session;
    stream.respond({':status':200, 'content-type':'application/grpc'}, {waitForTrailers:true});
    stream.once('wantTrailers', () => stream.sendTrailers({'grpc-status':'0'}));
    stream.end(frame('pong'));
    if (this.calls === 1) this.watch.end(); // UNIMPLEMENTED retires the Watch owner.
  }

  verify() {
    assert.equal(this.watches, 2);
    assert.equal(this.calls, 2);
    assert.equal(this.connectionClosed, true);
    assert.equal(this.pendingChecked, true);
    assert.equal(this.controlPings, 0, 'capacity recovery must consume SETTINGS without probing');
    return {watchAttempts:2, businessRpcs:2, failFast:'unary+streaming+duplex', restartedConnecting:'unary+streaming+duplex-deadlines', zeroCapacityRecovered:true, controlPings:0, waitForReady:true, disabledConnectionClosed:true};
  }
}

module.exports = {HealthGatePeer};
