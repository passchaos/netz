'use strict';
const assert = require('node:assert/strict');

function frame(status) {
  return Buffer.from([0,0,0,0,2,8,status]);
}

class HealthReadPeer {
  constructor(fail) {
    this.fail = fail;
    this.watches = 0;
    this.reset = false;
    this.retained = false;
    this.stream = null;
  }

  handle(stream, headers) {
    if (headers['x-health-read-probe'] !== 'yes') return false;
    this.watches++;
    stream.on('error', this.fail);
    stream.on('aborted', () => { this.reset = true; });
    const chunks = [];
    let length = 0;
    stream.on('data', chunk => {
      length += chunk.length;
      if (length > 16) this.fail(new Error('Health read probe request exceeded its bound'));
      else chunks.push(chunk);
    });
    stream.on('end', () => {
      try {
        assert.equal(this.watches, 1, 'interrupted read replayed Health Watch');
        assert.equal(headers[':path'], '/grpc.health.v1.Health/Watch');
        assert.equal(headers['grpc-timeout'], undefined);
        assert.deepEqual(Buffer.concat(chunks), Buffer.concat([Buffer.from([0,0,0,0,11,10,9]),Buffer.from('demo.Echo')]));
        this.stream = stream;
        stream.respond({':status':200,'content-type':'application/grpc'}, {waitForTrailers:true});
        stream.once('wantTrailers', () => stream.sendTrailers({'grpc-status':'12'}));
        stream.write(frame(1));
      } catch (error) {this.fail(error);}
    });
    return true;
  }

  resume() {
    assert.ok(this.stream);
    assert.equal(this.reset, false, 'local read interruption reset the live Watch');
    this.retained = true;
    this.stream.end(frame(2));
  }

  verify() {
    assert.equal(this.watches, 1);
    assert.equal(this.reset, false);
    assert.equal(this.retained, true);
    return {watchAttempts:1, canceledReadRetained:true, executorReadRetained:true, statuses:'SERVING+NOT_SERVING', terminal:'UNIMPLEMENTED', resets:0};
  }
}

module.exports = {HealthReadPeer};
