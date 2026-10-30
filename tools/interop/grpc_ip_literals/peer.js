'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http2 = require('node:http2');
const {promisify} = require('node:util');
const {execFile} = require('node:child_process');
const run = promisify(execFile);
const grpc = require('../grpc_response/node_modules/@grpc/grpc-js');
const referenceVersion = require('../grpc_response/node_modules/@grpc/grpc-js/package.json').version;
assert.equal(referenceVersion, '1.14.0');

function frame(bytes) {
  const prefix = Buffer.alloc(5);
  prefix.writeUInt32BE(bytes.length, 1);
  return Buffer.concat([prefix, bytes]);
}

function reference(client, reject, tls) {
  return new Promise((resolve, rejectPromise) => {
    client.makeUnaryRequest('/fixture.Numeric/Unary', bytes => bytes, bytes => bytes,
      Buffer.from('numeric'), new grpc.Metadata(), {deadline:Date.now()+5000}, (error, message) => {
        try {
          if (tls && error && /options.servername.*TLS ServerName.*IP address/.test(error.details)) {
            assert.equal(error.code, grpc.status.UNAVAILABLE);
            resolve({numericSniUnavailable:true});
            return;
          }
          if (reject) {
            assert.equal(error?.code, grpc.status.UNAVAILABLE);
            assert.match(error.details, /certificate|IP address|altnames|hostname/i);
          } else {
            assert.ifError(error);
            assert.equal(message.toString(), 'numeric');
          }
          resolve({numericSniUnavailable:false});
        } catch (error) { rejectPromise(error); }
      });
  });
}

// The standard TLS verifier still checks the URL's numeric hostname against
// iPAddress SANs. An empty servername suppresses only RFC 6066 SNI; CA and
// hostname verification retain their defaults.
async function nodeTls(authority, caPath, reject) {
  const session = http2.connect(`https://${authority}`, {ca:fs.readFileSync(caPath), servername:''});
  try {
    const ready = await new Promise((resolve, rejectPromise) => {
      session.once('connect', () => resolve(true));
      session.once('error', error => {
        if (reject && error.code === 'ERR_TLS_CERT_ALTNAME_INVALID') resolve(false);
        else rejectPromise(error);
      });
    });
    if (reject) { assert.equal(ready, false); return; }
    assert.equal(ready, true);
    for (let i=0; i<2; i++) await new Promise((resolve, rejectPromise) => {
      const stream = session.request({':method':'POST', ':path':'/fixture.Numeric/Unary', ':authority':authority,
        'content-type':'application/grpc', 'te':'trailers', 'x-fixture-client':'node-tls'});
      const chunks = [];
      let trailers = false;
      stream.on('error', rejectPromise);
      stream.on('response', headers => {
        try { assert.equal(headers[':status'], 200); assert.equal(headers['content-type'], 'application/grpc'); }
        catch (error) { rejectPromise(error); }
      });
      stream.on('data', chunk => chunks.push(chunk));
      stream.on('trailers', headers => {
        try { assert.equal(headers['grpc-status'], '0'); trailers = true; }
        catch (error) { rejectPromise(error); }
      });
      stream.on('end', () => {
        try { assert.equal(trailers, true); assert.deepEqual(Buffer.concat(chunks), frame(Buffer.from('numeric'))); resolve(); }
        catch (error) { rejectPromise(error); }
      });
      stream.end(frame(Buffer.from('numeric')));
    });
  } finally { session.destroy(); }
}

async function scenario(executable, host, mode, key, cert, caPath, reject) {
  const tls = mode !== 'cleartext';
  const version = mode === 'tls12' ? 'TLSv1.2' : 'TLSv1.3';
  const server = tls ? http2.createSecureServer({key, cert, minVersion:version, maxVersion:version}) : http2.createServer();
  const sessions = new Map();
  const sockets = new Set();
  const drained = new Set();
  server.on('connection', socket => {
    sockets.add(socket);
    socket.once('close', () => {
      sockets.delete(socket);
      if (sockets.size === 0) for (const resolve of drained) resolve();
    });
  });
  const waitForSocketRetirement = () => sockets.size === 0 ? Promise.resolve() : new Promise((resolve, rejectPromise) => {
    const timer = setTimeout(() => { drained.delete(done); rejectPromise(new Error('peer sockets did not retire')); }, 5000);
    const done = () => { clearTimeout(timer); drained.delete(done); resolve(); };
    drained.add(done);
  });
  let failure;
  server.on('tlsClientError', () => {});
  server.on('session', session => {
    sessions.set(session, {requests:0, client:null, sni:tls ? session.socket.servername : null});
    session.on('error', error => { if (!reject) failure ??= error; });
  });
  let authority;
  const expected = frame(Buffer.from('numeric'));
  server.on('stream', (stream, headers) => {
    stream.on('error', error => { failure ??= error; });
    try {
      assert.equal(reject, false, 'an IP certificate mismatch must fail before HTTP/2 admission');
      assert.equal(headers[':path'], '/fixture.Numeric/Unary');
      assert.equal(headers[':authority'], authority);
      assert.equal(headers[':scheme'], tls ? 'https' : 'http');
      const session = sessions.get(stream.session);
      session.client ??= headers['x-fixture-client'] ?? 'grpc-js';
      session.requests++;
      if (tls) {
        assert.equal(stream.session.socket.alpnProtocol, 'h2');
        assert.equal(stream.session.socket.getProtocol(), version);
        if (session.client === 'netz') assert.equal(session.sni, false, 'RFC 6066 forbids numeric SNI');
      }
      const chunks = [];
      stream.on('data', chunk => chunks.push(chunk));
      stream.on('end', () => {
        try {
          assert.deepEqual(Buffer.concat(chunks), expected);
          stream.respond({':status':200, 'content-type':'application/grpc'}, {waitForTrailers:true});
          stream.once('wantTrailers', () => stream.sendTrailers({'grpc-status':'0'}));
          stream.end(expected);
        } catch (error) { failure ??= error; stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR); }
      });
    } catch (error) { failure ??= error; stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR); }
  });
  await new Promise(resolve => server.listen(0, host, resolve));
  const port = server.address().port;
  authority = `${host === '::1' ? '[::1]' : host}:${port}`;
  const client = new grpc.Client(authority, tls ? grpc.credentials.createSsl(fs.readFileSync(caPath)) : grpc.credentials.createInsecure(), {'grpc.enable_retries':0});
  try {
    const referenceResult = await reference(client, reject, tls);
    if (!reject && !referenceResult.numericSniUnavailable) await reference(client, false, tls);
    client.close();
    if (tls) await nodeTls(authority, caPath, reject);
    await waitForSocketRetirement();
    const referenceSessionCount = sessions.size;
    const result = await run(executable, [host, String(port), mode, caPath, reject ? 'reject' : 'accept'], {timeout:45000, maxBuffer:1024*1024});
    const connections = (host === '::1' ? 3 : 1) * (tls ? 10 : 7);
    assert.equal(result.stdout.trim(), `io=zio-std-io mode=${mode} rejected=${reject} connections=${connections} rpcs=${reject ? 0 : connections*2}`);
    await waitForSocketRetirement();
    if (failure) throw failure;
    if (reject) {
      // Node performs the IP identity check after the cryptographic handshake;
      // the server may allocate an idle session for that reference socket.
      // Native verification must reject before any additional H2 admission.
      assert.equal(sessions.size, referenceSessionCount);
      for (const row of sessions.values()) assert.equal(row.requests, 0);
    }
    else {
      assert.equal(sessions.size, connections+(referenceResult.numericSniUnavailable ? 0 : 1)+(tls ? 1 : 0));
      assert.equal([...sessions.values()].filter(row => row.client === 'netz').length, connections);
      for (const row of sessions.values()) assert.equal(row.requests, 2, 'each client must reuse its HTTP/2 connection');
    }
    return {host, mode, reject, nativeConnections:connections, nativeRpcs:reject ? 0 : connections*2,
      referenceResult, nodeTlsIdentityVerified:tls,
      referenceRejectedTlsSessions:reject ? referenceSessionCount : 0,
      referenceSni:[...sessions.values()].filter(row => row.client === 'grpc-js').map(row => row.sni)};
  } catch (error) {
    throw new Error(`${host}/${mode}/reject=${reject}: ${error.stack}; peer=${failure?.stack ?? 'none'}`);
  } finally {
    client.close();
    for (const session of sessions.keys()) session.destroy();
    await new Promise(resolve => server.close(resolve));
  }
}

async function main() {
  assert.equal(process.argv.length, 7);
  const [executable, keyPath, certPath, caPath, badCertPath] = process.argv.slice(2);
  const key = fs.readFileSync(keyPath);
  const cert = fs.readFileSync(certPath);
  const badCert = fs.readFileSync(badCertPath);
  const rows = [];
  for (const host of ['127.0.0.1', '::1']) {
    for (const mode of ['cleartext', 'tls12', 'tls13']) rows.push(await scenario(executable, host, mode, key, cert, caPath, false));
    for (const mode of ['tls12', 'tls13']) rows.push(await scenario(executable, host, mode, key, badCert, caPath, true));
  }
  process.stdout.write(JSON.stringify({reference:`grpc-js-${referenceVersion}`, node:process.version, rows})+'\n');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
