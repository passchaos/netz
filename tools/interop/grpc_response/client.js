'use strict';
const grpc = require('@grpc/grpc-js');
const http2 = require('node:http2');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawn} = require('node:child_process');
const assert = require('node:assert/strict');
const {WireRelay} = require('./relay');
const {HealthGatePeer} = require('./health_gate');
const referenceVersion = require('@grpc/grpc-js/package.json').version;
assert.equal(referenceVersion, '1.14.0', 'the reference SDK must match the pinned fixture');

function frame(payload) {
  const bytes = Buffer.from(payload);
  const prefix = Buffer.alloc(5);
  prefix.writeUInt32BE(bytes.length, 1);
  return Buffer.concat([prefix, bytes]);
}

// Expected values follow the upstream HTTP-to-gRPC table and explicit-status
// precedence. The raw peer never uses grpc-js to encode the response.
const probes = [
  ...[[400,13], [401,16], [403,7], [404,12], [429,14], [500,2], [502,14], [503,14], [504,14]].map(([http,status]) => ({name:`http-${http}`, http, status, headers:{'content-type':'text/plain'}})),
  {name:'grpc-200-no-status', status:2, headers:{'content-type':'application/grpc'}},
  {name:'html-200-no-status', status:2, headers:{'content-type':'text/html'}},
  {name:'missing-type-explicit-status', status:16, headers:{'grpc-status':'16'}},
  {name:'http-503-explicit-status', http:503, status:7, headers:{'content-type':'text/plain','grpc-status':'7'}},
  {name:'plain-rich-error', status:7, details:true, headers:{'content-type':'text/plain','grpc-status':'7','grpc-status-details-bin':'CAc','grpc-encoding':'unknown-proxy-coding'}},
  {name:'missing-type-trailing-status', status:7, headers:{}, body:Buffer.alloc(0), trailers:{'grpc-status':'7'}},
  {name:'success-after-errors', status:0, messages:1, payload:'reply', headers:{'content-type':'application/grpc'}, body:frame('reply'), trailers:{'grpc-status':'0'}},
  // grpc-js 1.14.0 reports INTERNAL on DATA FIN without terminal status and
  // RESOURCE_EXHAUSTED when it interprets this HTML entity as a message size.
  // Record those differences explicitly; netz applies the documented UNKNOWN
  // fallback and does not deliver non-gRPC entities to application callbacks.
  {name:'data-fin-no-status', status:2, referenceStatus:13, messages:1, payload:'before', headers:{'content-type':'application/grpc'}, body:frame('before'), shared:true, readDelayMs:550},
  {name:'html-entity-no-status', status:2, referenceStatus:8, headers:{'content-type':'text/html'}, body:Buffer.from('<html>proxy error</html>')},
  {name:'proxy-grpc-type-error-entity', http:503, status:14, headers:{'content-type':'application/grpc'}, body:Buffer.from('proxy error')},
  ...[
    ['normalized-default-port','EXAMPLE.test','example.test:80'],
    ['normalized-percent-host','%65xample.test','example.test:80'],
    ['normalized-ipv6-host','[2001:DB8::1]','[2001:db8:0:0:0:0:0:1]:80'],
  ].map(([name,requestAuthority,requestHost]) => ({name,requestAuthority,requestHost,status:0,messages:1,payload:'reply',headers:{'content-type':'application/grpc'},body:frame('reply'),trailers:{'grpc-status':'0'}})),
  ...[false,true].map(earlyReset => ({name:earlyReset?'early-upload-no-error-reset':'early-upload-error',status:7,headers:{'content-type':'application/grpc'},body:Buffer.alloc(0),trailers:{'grpc-status':'7','grpc-message':'early%20denial','x-early':'yes'},requestPayload:'x'.repeat(32*1024),statusMessage:'early denial',early:true,earlyReset,unaryOnly:true})),
  {name:'success-after-early-upload',status:0,messages:1,payload:'reply',headers:{'content-type':'application/grpc'},body:frame('reply'),trailers:{'grpc-status':'0'},shared:true,readDelayMs:550},
  {name:'unprocessed-refusal-once',status:0,messages:1,payload:'reply',headers:{'content-type':'application/grpc'},body:frame('reply'),trailers:{'grpc-status':'0','x-early':'yes'},unaryOnly:true,refusedOnce:true},
];

async function reference(client, probe, index, relay) {
  const metadata = new grpc.Metadata();
  if (probe.requestHost) metadata.set('host',probe.requestHost);
  const call = client.makeServerStreamRequest(`/fixture.Response/Case${index}`, x=>x, x=>x, Buffer.from(probe.requestPayload ?? ''), metadata, {deadline:Date.now()+5000,host:probe.requestAuthority});
  const messages = [];
  call.on('data', message => messages.push(message));
  call.on('error', () => {});
  const status = await new Promise(resolve => call.on('status', resolve));
  assert.equal(status.code, probe.referenceStatus ?? probe.status, probe.name);
  assert.equal(messages.length, probe.messages ?? 0, probe.name);
  for (const message of messages) assert.equal(message.toString(), probe.payload, probe.name);
  if (probe.details) assert.deepEqual(status.metadata.get('grpc-status-details-bin'), [Buffer.from([8,7])]);
  if (probe.early) await relay.waitForClosed(index);
  return status.code;
}

function native(executable, port, manifest, health) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [String(port), manifest], {stdio:['ignore','pipe','pipe']});
    let output = '';
    const receive = chunk => {
      output += chunk;
      if (!health.resume && output.includes('netz grpc health retry rejected: unary+streaming+duplex')) health.allowRecovery();
      if (!health.pendingChecked && output.includes('netz grpc health restarted CONNECTING: unary+streaming+duplex-deadlines')) health.allowServing();
    };
    child.stdout.on('data', receive);
    child.stderr.on('data', receive);
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('native response-policy timeout')); }, 30000);
    child.on('error', error => {clearTimeout(timer); reject(error);});
    child.on('exit', code => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`native response-policy exit ${code}: ${output}`));
      else {
        try {
          assert.ok(output.includes('io=zio-std-io cases='+probes.length+' shared='+probes.filter(probe=>probe.shared).length+' shapes=unary+streaming+duplex+shared reuse=true'));
          assert.ok(output.includes('netz grpc health gate complete: retry+ready+disabled-close calls=2 reuse=true'));
          assert.ok(output.includes('netz grpc health restarted CONNECTING: unary+streaming+duplex-deadlines'));
          process.stdout.write(output);
          resolve();
        } catch (error) {reject(error);}
      }
    });
  });
}

async function main() {
  assert.equal(process.argv.length, 3);
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'netz-grpc-response-'));
  const server = http2.createServer({settings:{maxConcurrentStreams:1,initialWindowSize:1024}});
  const sessions = new Set();
  const counts = probes.map(() => 0);
  const closed = new Map();
  const refusals = new WeakSet();
  let transparentRetries = 0;
  let failure;
  let relay;
  let clientPort;
  const health = new HealthGatePeer(error => {failure ??= error;});
  server.on('session', session => { sessions.add(session); session.on('error', error => {failure ??= error;}); });
  server.on('stream', (stream, headers) => {
    if (health.handle(stream, headers)) return;
    const chunks = [];
    let size = 0;
    stream.on('error', () => {});
    try {
      const match = /^\/fixture.Response\/Case(\d+)$/.exec(headers[':path']);
      assert.ok(match);
      assert.equal(headers[':scheme'], 'http');
      const index = Number(match[1]);
      const probe = probes[index];
      assert.ok(probe);
      if (probe.refusedOnce) assert.equal(headers['grpc-previous-rpc-attempts'],undefined,'transparent retry must not increment configured attempt metadata');
      if (probe.early) {
        let resolveClosed;
        const completion = new Promise(resolve => {resolveClosed = resolve;});
        closed.set(index,completion);
        stream.once('close',resolveClosed);
      }
      assert.equal(headers[':authority'], probe.requestAuthority ?? `127.0.0.1:${clientPort}`);
      if (probe.requestHost) assert.equal(headers.host,probe.requestHost);
      const expected = frame(probe.requestPayload ?? '');
      const reply = () => {
        counts[index]++;
        const head = {':status':probe.http ?? 200, ...probe.headers};
        if (probe.trailers) {
          if (probe.earlyReset) closed.set(index,relay.afterEndStream(stream.session.socket.remotePort,stream.id,() => {
            assert.ok(!stream.destroyed, 'the large upload must still be open');
            stream.close(http2.constants.NGHTTP2_NO_ERROR);
            stream.resume();
          }));
          stream.respond(head, {waitForTrailers:true});
          stream.once('wantTrailers', () => {
            if (stream.destroyed) return;
            stream.sendTrailers(probe.trailers);
          });
          stream.end(probe.body);
        } else if (probe.body) {stream.respond(head); stream.end(probe.body);}
        else stream.respond(head, {endStream:true});
      };
      stream.on('data', chunk => {
        try {
          size += chunk.length;
          assert.ok(size <= expected.length, 'request payload was replayed');
          chunks.push(chunk);
          assert.deepEqual(Buffer.concat(chunks), expected.subarray(0,size));
        } catch (error) {failure ??= error; stream.close(1);}
      });
      stream.on('end', () => {
        try {
          if (!probe.early) {
            assert.deepEqual(Buffer.concat(chunks), expected);
            if (probe.refusedOnce && !refusals.has(stream.session)) {
              refusals.add(stream.session);
              transparentRetries++;
              counts[index]++;
              // Emit outside mem_recv so Node's own stream map is retired
              // before either client immediately creates a transparent retry.
              setImmediate(() => stream.close(http2.constants.NGHTTP2_REFUSED_STREAM));
            } else reply();
          }
        } catch (error) {failure ??= error; stream.close(1);}
      });
      // Respond before consuming DATA. The unary message exceeds the peer's
      // bounded stream window; completion and NO_ERROR never require the
      // client to finish uploading an entity that was already rejected.
      if (probe.early) {if (probe.earlyReset) stream.pause(); reply();}
    } catch (error) {failure ??= error; stream.close(1);}
  });
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    relay = new WireRelay(server.address().port,error => {failure ??= error;});
    relay.waitForClosed = index => {
      const completion = closed.get(index);
      assert.ok(completion);
      return new Promise((resolve,reject) => {
        const timer = setTimeout(() => reject(new Error(`reference request stream ${index} did not close`)),5000);
        completion.then(() => {clearTimeout(timer); resolve();});
      });
    };
    const port = clientPort = await relay.listen();
    const client = new grpc.Client(`127.0.0.1:${port}`, grpc.credentials.createInsecure());
    const observed = [];
    try { for (let i=0; i<probes.length; i++) observed.push(await reference(client, probes[i], i, relay)); }
    finally {client.close();}
    const manifest = path.join(work, 'cases.json');
    fs.writeFileSync(manifest, JSON.stringify(probes.map((probe,i) => ({path:`/fixture.Response/Case${i}`, status:probe.status, messages:probe.messages ?? 0, payload:probe.payload ?? '', details:probe.details ?? false, authority:probe.requestAuthority ?? null, host:probe.requestHost ?? null, request_payload:probe.requestPayload ?? '', unary_only:probe.unaryOnly ?? false, status_message:probe.statusMessage ?? null,shared_probe:probe.shared ?? false,read_delay_ms:probe.readDelayMs ?? 0}))));
    try {await native(process.argv[2], port, manifest, health);}
    catch (error) {throw new Error(`${error.message}; peer=${failure?.message ?? 'none'}; counts=${JSON.stringify(counts)}; connections=${sessions.size}; frames=${JSON.stringify([...relay.captures.values()].map(capture=>({client:capture.clientFrames,server:capture.serverFrames})))}`);}
    if (failure) throw failure;
    assert.deepEqual(counts, probes.map(probe=>(probe.refusedOnce?4:probe.unaryOnly?2:4)+(probe.shared?1:0)));
    assert.equal(sessions.size, 5, 'original clients plus one dedicated health connection and one reused business connection');
    const healthGate = health.verify();
    const noErrorAfterEndStream = relay.assertResets(2);
    assert.equal(transparentRetries,2);
    const differences = probes.flatMap((probe,i) => observed[i] === probe.status ? [] : [{case:probe.name, netz:probe.status, grpcJs:observed[i]}]);
    process.stdout.write(JSON.stringify({reference:`grpc-js-${referenceVersion}`, cases:probes.length, nativeRpcs:probes.reduce((total,probe)=>total+(probe.unaryOnly?1:3)+(probe.shared?1:0),0)+2, sharedRpcs:probes.filter(probe=>probe.shared).length, sharedReadAfterRpcDeadline:true, transparentRetries, maxConcurrentStreams:1, noErrorAfterEndStream, healthGate, differences})+'\n');
  } finally {
    if (relay) await relay.close();
    for (const session of sessions) session.destroy();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(work, {recursive:true, force:true});
  }
}
main().catch(error => {console.error(error); process.exitCode=1;});
