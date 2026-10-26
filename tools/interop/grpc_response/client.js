'use strict';
const grpc = require('@grpc/grpc-js');
const http2 = require('node:http2');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawn} = require('node:child_process');
const assert = require('node:assert/strict');
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
  {name:'data-fin-no-status', status:2, referenceStatus:13, messages:1, payload:'before', headers:{'content-type':'application/grpc'}, body:frame('before')},
  {name:'html-entity-no-status', status:2, referenceStatus:8, headers:{'content-type':'text/html'}, body:Buffer.from('<html>proxy error</html>')},
  {name:'proxy-grpc-type-error-entity', http:503, status:14, headers:{'content-type':'application/grpc'}, body:Buffer.from('proxy error')},
];

async function reference(client, probe, index) {
  const call = client.makeServerStreamRequest(`/fixture.Response/Case${index}`, x=>x, x=>x, Buffer.alloc(0), {deadline:Date.now()+5000});
  const messages = [];
  call.on('data', message => messages.push(message));
  call.on('error', () => {});
  const status = await new Promise(resolve => call.on('status', resolve));
  assert.equal(status.code, probe.referenceStatus ?? probe.status, probe.name);
  assert.equal(messages.length, probe.messages ?? 0, probe.name);
  for (const message of messages) assert.equal(message.toString(), probe.payload, probe.name);
  if (probe.details) assert.deepEqual(status.metadata.get('grpc-status-details-bin'), [Buffer.from([8,7])]);
  return status.code;
}

function native(executable, port, manifest) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, [String(port), manifest], {stdio:['ignore','pipe','pipe']});
    let output = '';
    child.stdout.on('data', chunk => {output += chunk;});
    child.stderr.on('data', chunk => {output += chunk;});
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('native response-policy timeout')); }, 30000);
    child.on('error', error => {clearTimeout(timer); reject(error);});
    child.on('exit', code => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(`native response-policy exit ${code}: ${output}`));
      else {
        try {
          assert.match(output, new RegExp(`io=zio-std-io cases=${probes.length} shapes=unary\\+streaming\\+duplex reuse=true`));
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
  const server = http2.createServer({settings:{maxConcurrentStreams:1}});
  const sessions = new Set();
  const counts = probes.map(() => 0);
  let failure;
  server.on('session', session => { sessions.add(session); session.on('error', error => {failure ??= error;}); });
  server.on('stream', (stream, headers) => {
    const chunks = [];
    let size = 0;
    stream.on('error', () => {});
    stream.on('data', chunk => {size += chunk.length; if (size > 5) {failure ??= new Error('unexpected request size'); stream.close(1);} else chunks.push(chunk);});
    stream.on('end', () => {
      try {
        assert.deepEqual(Buffer.concat(chunks), Buffer.alloc(5));
        const match = /^\/fixture.Response\/Case(\d+)$/.exec(headers[':path']);
        assert.ok(match);
        const index = Number(match[1]);
        const probe = probes[index];
        assert.ok(probe);
        counts[index]++;
        const head = {':status':probe.http ?? 200, ...probe.headers};
        if (probe.trailers) {
          stream.respond(head, {waitForTrailers:true});
          stream.once('wantTrailers', () => {if (!stream.destroyed) stream.sendTrailers(probe.trailers);});
          stream.end(probe.body);
        } else if (probe.body) {stream.respond(head); stream.end(probe.body);}
        else stream.respond(head, {endStream:true});
      } catch (error) {failure ??= error; stream.close(1);}
    });
  });
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;
    const client = new grpc.Client(`127.0.0.1:${port}`, grpc.credentials.createInsecure());
    const observed = [];
    try { for (let i=0; i<probes.length; i++) observed.push(await reference(client, probes[i], i)); }
    finally {client.close();}
    const manifest = path.join(work, 'cases.json');
    fs.writeFileSync(manifest, JSON.stringify(probes.map((probe,i) => ({path:`/fixture.Response/Case${i}`, status:probe.status, messages:probe.messages ?? 0, payload:probe.payload ?? '', details:probe.details ?? false}))));
    try {await native(process.argv[2], port, manifest);}
    catch (error) {throw new Error(`${error.message}; peer=${failure?.message ?? 'none'}; counts=${JSON.stringify(counts)}; connections=${sessions.size}`);}
    if (failure) throw failure;
    assert.deepEqual(counts, probes.map(()=>4));
    assert.equal(sessions.size, 2, 'each client must reuse its one HTTP/2 connection');
    const differences = probes.flatMap((probe,i) => observed[i] === probe.status ? [] : [{case:probe.name, netz:probe.status, grpcJs:observed[i]}]);
    process.stdout.write(JSON.stringify({reference:`grpc-js-${referenceVersion}`, cases:probes.length, nativeRpcs:probes.length*3, maxConcurrentStreams:1, differences})+'\n');
  } finally {
    for (const session of sessions) session.destroy();
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(work, {recursive:true, force:true});
  }
}
main().catch(error => {console.error(error); process.exitCode=1;});
