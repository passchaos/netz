'use strict';
const assert = require('node:assert/strict');
const http2 = require('node:http2');
const {spawn} = require('node:child_process');
const {NGHTTP2_CANCEL: CANCEL, NGHTTP2_REFUSED_STREAM: REFUSED} = http2.constants;

const names = [
  'head_cancels_loser', 'head_suppresses_later', 'head_unavailable_wins',
  'trailers_only_accelerates', 'informational_does_not_commit', 'call_wide_transparent_budget'
];
const holdMilliseconds = 350; // Native hedge delay is 75 ms.

function deferred() {
  let resolve;
  const promise = new Promise(done => {resolve = done;});
  return {promise, resolve};
}

async function bounded(promise, milliseconds, label) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(label + ' timeout')), milliseconds);
    })]);
  } finally {clearTimeout(timer);}
}

async function fixture(onFailure) {
  const states = new Map(names.map(name => [name, {
    name, requests: {A: [], B: []}, trace: [], readyA: deferred(), cancelA: deferred()
  }]));
  const sessions = new Set();
  const timers = new Set();
  function trace(state, event, record, extra = {}) {
    state.trace.push({order: state.trace.length, event, backend: record.backend, request: record.ordinal, ...extra});
  }
  function headers(state, stream, record) {
    trace(state, 'initial_headers', record);
    stream.respond({':status': 200, 'content-type': 'application/grpc'}, {waitForTrailers: true});
  }
  function finish(state, stream, record, status, body = '') {
    assert(!stream.destroyed, state.name + ' committed response was canceled');
    stream.once('wantTrailers', () => {
      try {
        trace(state, 'trailers', record, {status_code: status});
        stream.sendTrailers({'grpc-status': String(status)});
      } catch (error) {onFailure(error);}
    });
    record.status_code = status;
    record.body = body;
    trace(state, 'body', record, {body});
    if (body) {
      const payload = Buffer.from(body);
      const frame = Buffer.alloc(5 + payload.length);
      frame.writeUInt32BE(payload.length, 1);
      payload.copy(frame, 5);
      stream.end(frame);
    } else stream.end();
  }
  function trailersOnly(state, stream, record) {
    record.status_code = 14;
    trace(state, 'trailers_only', record, {status_code: 14});
    stream.respond({':status': 200, 'content-type': 'application/grpc', 'grpc-status': '14'}, {endStream: true});
  }
  function refuse(state, stream, record) {
    record.reset_sent = REFUSED;
    trace(state, 'refused_stream', record, {code: REFUSED});
    stream.close(REFUSED);
  }
  function later(callback) {
    const timer = setTimeout(() => {
      timers.delete(timer);
      try {callback();} catch (error) {onFailure(error);}
    }, holdMilliseconds);
    timers.add(timer);
  }
  async function respond(state, stream, record) {
    if (record.backend === 'A') {
      switch (state.name) {
        case 'head_cancels_loser': return;
        case 'informational_does_not_commit':
          trace(state, 'informational_headers', record, {status_code: 103});
          stream.additionalHeaders({':status': 103});
          return;
        case 'head_suppresses_later':
          headers(state, stream, record);
          later(() => finish(state, stream, record, 0, 'a-held'));
          return;
        case 'head_unavailable_wins':
          headers(state, stream, record);
          later(() => finish(state, stream, record, 14));
          return;
        case 'trailers_only_accelerates': return trailersOnly(state, stream, record);
        case 'call_wide_transparent_budget':
          assert(record.ordinal <= 2, 'A received an extra hedge');
          return refuse(state, stream, record);
      }
    }
    switch (state.name) {
      case 'head_suppresses_later':
      case 'head_unavailable_wins':
        assert.fail(state.name + ' sent a hedge after initial HEADERS');
        break;
      case 'head_cancels_loser':
      case 'informational_does_not_commit':
        await bounded(state.readyA.promise, 3000, state.name + ' original request');
        assert.equal(state.requests.A.length, 1, 'both hedges must be in flight');
        headers(state, stream, record);
        // B sends no DATA or trailers until the independent HTTP/2 peer A
        // observes the client's exact RST_STREAM(CANCEL).
        await bounded(state.cancelA.promise, 3000, state.name + ' loser CANCEL');
        return finish(state, stream, record, 0, state.name === 'head_cancels_loser' ? 'b-committed' : 'b-informational');
      case 'trailers_only_accelerates':
        headers(state, stream, record);
        return finish(state, stream, record, 0, 'b-accelerated');
      case 'call_wide_transparent_budget':
        if (record.ordinal === 1) {
          assert.equal(state.requests.A.length, 1, 'transparent replay must precede the second hedge');
          return trailersOnly(state, stream, record);
        }
        // The first replay repicks B under round_robin. The second logical
        // hedge repicks A and is refused. A per-hedge transparent budget would
        // wrongly issue this fourth physical request and return success.
        assert.equal(record.ordinal, 2, 'unbounded transparent replays');
        headers(state, stream, record);
        return finish(state, stream, record, 0, 'unexpected-replay');
    }
  }
  const servers = ['A', 'B'].map(backend => {
    const server = http2.createServer();
    server.on('error', onFailure);
    server.on('session', session => {
      sessions.add(session);
      session.on('close', () => sessions.delete(session));
      session.on('error', onFailure);
    });
    server.on('stream', (stream, requestHeaders) => {
      try {
        assert.equal(requestHeaders[':method'], 'POST');
        assert.equal(requestHeaders[':path'], '/fixture.Hedging/Unary');
        assert.equal(requestHeaders['x-preserved'], 'preserved');
        assert.equal(requestHeaders.te, 'trailers');
        assert.match(requestHeaders['content-type'], /^application\/grpc/);
        assert.match(requestHeaders['grpc-timeout'], /^\d+[HMSmun]$/);
        const state = states.get(requestHeaders['x-case']);
        assert(state, 'unknown fixture case');
        const record = {
          backend, ordinal: state.requests[backend].length + 1,
          previous_attempts: requestHeaders['grpc-previous-rpc-attempts'] ?? null,
          preserved_metadata: requestHeaders['x-preserved'], timeout: requestHeaders['grpc-timeout'],
          reset_sent: null, reset_observed: null, status_code: null, body: '', request_complete: false
        };
        state.requests[backend].push(record);
        const previous = state.name === 'call_wide_transparent_budget'
          ? (backend === 'A' && record.ordinal === 1 || backend === 'B' && record.ordinal === 1 ? null : '1')
          : (backend === 'A' ? null : '1');
        assert.equal(record.previous_attempts, previous);
        trace(state, 'request', record);
        stream.on('error', error => {
          if (stream.rstCode !== CANCEL && stream.rstCode !== record.reset_sent) onFailure(error);
        });
        stream.on('close', () => {
          record.reset_observed = stream.rstCode;
          trace(state, 'stream_closed', record, {code: stream.rstCode});
          if (backend === 'A' && stream.rstCode === CANCEL && record.reset_sent === null) state.cancelA.resolve();
        });
        const chunks = [];
        let length = 0;
        stream.on('data', chunk => {
          length += chunk.length;
          if (length > 4096) return onFailure(new Error('unbounded fixture request'));
          chunks.push(chunk);
        });
        stream.on('end', () => {
          try {
            const request = Buffer.concat(chunks);
            assert(request.length >= 5);
            assert.equal(request[0], 0, 'request compression changed');
            assert.equal(request.readUInt32BE(1), request.length - 5);
            assert.equal(request.subarray(5).toString(), state.name);
            record.request_complete = true;
            record.request_payload = request.subarray(5).toString();
            respond(state, stream, record).then(() => {
              if (backend === 'A') state.readyA.resolve();
            }).catch(onFailure);
          } catch (error) {onFailure(error);}
        });
      } catch (error) {onFailure(error); stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR);}
    });
    return server;
  });
  const ports = await Promise.all(servers.map(server => new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  })));
  return {
    ports, states,
    async close() {
      for (const timer of timers) clearTimeout(timer);
      for (const session of sessions) session.destroy();
      await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
    }
  };
}

function verify(peer, native) {
  const expected = [
    {counts: [1, 1], resets: [CANCEL, 0], status: 0, body: 'b-committed', tokens: 4000},
    {counts: [1, 0], resets: [0], status: 0, body: 'a-held', tokens: 4000},
    {counts: [1, 0], resets: [0], status: 14, body: '', tokens: 3000},
    {counts: [1, 1], resets: [0, 0], status: 0, body: 'b-accelerated', tokens: 4000},
    {counts: [1, 1], resets: [CANCEL, 0], status: 0, body: 'b-informational', tokens: 4000},
    {counts: [2, 1], resets: [REFUSED, REFUSED, 0], status: 14, body: '', tokens: 2000}
  ];
  assert.equal(native.length, names.length);
  return names.map((name, index) => {
    const state = peer.states.get(name), actual = native[index], wanted = expected[index];
    assert.equal(actual.name, name);
    assert.equal(actual.status_code, wanted.status);
    assert.equal(actual.body, wanted.body);
    assert.equal(actual.milli_tokens, wanted.tokens);
    assert.deepEqual([state.requests.A.length, state.requests.B.length], wanted.counts);
    const requests = [...state.requests.A, ...state.requests.B];
    assert(requests.every(request => request.request_complete));
    assert.deepEqual(requests.map(request => request.reset_observed), wanted.resets);
    if (index === 0 || index === 4) {
      const event = (type, backend) => state.trace.find(item => item.event === type && item.backend === backend).order;
      assert(event('initial_headers', 'B') < event('stream_closed', 'A'));
      assert(event('stream_closed', 'A') < event('body', 'B'));
      assert(event('stream_closed', 'A') < event('trailers', 'B'));
    }
    return {name, native: actual, backend_counts: {A: wanted.counts[0], B: wanted.counts[1]}, requests, events: state.trace};
  });
}

async function main(client) {
  let failure = null, child = null;
  const fail = error => {if (!failure) failure = error; if (child) child.kill();};
  const peer = await fixture(fail);
  try {
    let output = '';
    const code = await bounded(new Promise((resolve, reject) => {
      child = spawn(client, peer.ports.map(String));
      for (const stream of [child.stdout, child.stderr]) stream.on('data', chunk => {
        output += chunk;
        if (output.length > 1024 * 1024) fail(new Error('unbounded native output'));
      });
      child.on('error', reject);
      child.on('close', resolve);
    }), 35000, 'native hedging commitment gate');
    if (failure) throw failure;
    assert.equal(code, 0, output);
    const lines = output.split('\n');
    const native = lines.filter(line => line.startsWith('HEDGING_COMMIT_CASE ')).map(line => JSON.parse(line.slice(20)));
    const summary = lines.find(line => line.startsWith('HEDGING_COMMIT_RESULT '));
    assert(summary, output);
    assert.deepEqual(JSON.parse(summary.slice(22)), {status: 'passed', cases: 6, runtime: 'zio'});
    const results = verify(peer, native);
    console.log(JSON.stringify({status: 'passed', oracle: 'node:http2', runtime: 'zio', node_version: process.version,
      hold_milliseconds: holdMilliseconds, cancellation_gate: 'peer-observed RST_STREAM(CANCEL) before winner DATA/trailers', cases: results}));
  } finally {
    if (child && child.exitCode === null) child.kill();
    await peer.close();
  }
}

module.exports = {fixture, verify};
if (require.main === module) {
  if (process.argv.length !== 3) throw new Error('usage: node peer.js /absolute/path/to/native-client');
  main(process.argv[2]).catch(error => {console.error(error); process.exitCode = 1;});
}
