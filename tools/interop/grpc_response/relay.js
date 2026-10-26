'use strict';
const net = require('node:net');
const assert = require('node:assert/strict');

// Node may discard queued trailers when close(NO_ERROR) immediately follows
// sendTrailers(). Trigger that reset after observing the complete field block
// on TCP, before forwarding it to the client, and verify the actual wire order.
class Capture {
  constructor() {
    this.bytes = Buffer.alloc(0);
    this.pendingEndHeaders = new Set();
    this.resets = new Map();
    this.clientBytes = Buffer.alloc(0);
    this.clientPreface = true;
    this.clientFrames = [];
    this.serverFrames = [];
  }
  afterEndStream(id, callback) {
    assert.ok(!this.resets.has(id));
    let resolveReset;
    const completion = new Promise(resolve => {resolveReset = resolve;});
    this.resets.set(id, {callback, ended:false, seen:false, resolveReset});
    return completion;
  }
  consume(chunk) {
    this.bytes = Buffer.concat([this.bytes,chunk]);
    assert.ok(this.bytes.length <= 1024*1024, 'unbounded HTTP/2 wire capture');
    while (this.bytes.length >= 9) {
      const length = this.bytes.readUIntBE(0,3);
      if (this.bytes.length < 9+length) return;
      const type = this.bytes[3];
      const flags = this.bytes[4];
      const id = this.bytes.readUInt32BE(5) & 0x7fffffff;
      const reset = this.resets.get(id);
      this.serverFrames.push({type,flags,id,code:type===3?this.bytes.readUInt32BE(9):undefined});
      if (this.serverFrames.length > 16) this.serverFrames.shift();
      let endStream = type === 0 && (flags & 1) !== 0;
      if (type === 1 && (flags & 1) !== 0) {
        if ((flags & 4) !== 0) endStream = true;
        else this.pendingEndHeaders.add(id);
      }
      if (type === 9 && (flags & 4) !== 0 && this.pendingEndHeaders.delete(id)) endStream = true;
      if (reset && endStream && !reset.ended) {
        reset.ended = true;
        reset.callback();
      }
      if (reset && type === 3 && length === 4 && this.bytes.readUInt32BE(9) === 0) {
        assert.ok(reset.ended, 'NO_ERROR preceded the complete response');
        assert.ok(!reset.seen, 'duplicate server NO_ERROR');
        reset.seen = true;
        reset.resolveReset();
      }
      this.bytes = this.bytes.subarray(9+length);
    }
  }
  consumeClient(chunk) {
    this.clientBytes = Buffer.concat([this.clientBytes,chunk]);
    assert.ok(this.clientBytes.length <= 1024*1024, 'unbounded client HTTP/2 wire capture');
    if (this.clientPreface) {
      if (this.clientBytes.length < 24) return;
      this.clientBytes = this.clientBytes.subarray(24);
      this.clientPreface = false;
    }
    while (this.clientBytes.length >= 9) {
      const length = this.clientBytes.readUIntBE(0,3);
      if (this.clientBytes.length < 9+length) return;
      const type = this.clientBytes[3], flags = this.clientBytes[4], id = this.clientBytes.readUInt32BE(5)&0x7fffffff;
      this.clientFrames.push({type,flags,id,length,code:type===3?this.clientBytes.readUInt32BE(9):undefined});
      if (this.clientFrames.length > 16) this.clientFrames.shift();
      this.clientBytes = this.clientBytes.subarray(9+length);
    }
  }
}

class WireRelay {
  constructor(upstreamPort, onFailure) {
    this.captures = new Map();
    this.sockets = new Set();
    this.server = net.createServer(client => {
      const upstream = net.connect(upstreamPort,'127.0.0.1');
      const capture = new Capture();
      for (const socket of [client,upstream]) {
        this.sockets.add(socket);
        socket.on('error', error => {onFailure(error); client.destroy(); upstream.destroy();});
        socket.on('close', () => this.sockets.delete(socket));
      }
      upstream.on('connect', () => this.captures.set(upstream.localPort,capture));
      client.on('data', chunk => {capture.consumeClient(chunk); upstream.write(chunk);});
      client.on('end', () => upstream.end());
      upstream.on('data', chunk => {
        try {capture.consume(chunk); client.write(chunk);}
        catch (error) {onFailure(error); client.destroy(); upstream.destroy();}
      });
      upstream.on('end', () => client.end());
    });
  }
  async listen() {
    await new Promise(resolve => this.server.listen(0,'127.0.0.1',resolve));
    return this.server.address().port;
  }
  afterEndStream(upstreamPort, streamId, callback) {
    const capture = this.captures.get(upstreamPort);
    assert.ok(capture, 'missing HTTP/2 wire capture');
    return capture.afterEndStream(streamId,callback);
  }
  assertResets(expected) {
    let count = 0;
    for (const capture of this.captures.values()) for (const reset of capture.resets.values()) {
      assert.ok(reset.ended && reset.seen, 'server NO_ERROR was not observed after response END_STREAM');
      count++;
    }
    assert.equal(count,expected);
    return count;
  }
  async close() {
    for (const socket of this.sockets) socket.destroy();
    await new Promise(resolve => this.server.close(resolve));
  }
}
module.exports = {WireRelay};
