'use strict';
const assert = require('node:assert/strict');
const net = require('node:net');
const http2 = require('node:http2');
const fs = require('node:fs');
const {promisify} = require('node:util');
const run = promisify(require('node:child_process').execFile);
const grpc = require('../grpc_response/node_modules/@grpc/grpc-js');
const version = require('../grpc_response/node_modules/@grpc/grpc-js/package.json').version;
assert.equal(version, '1.14.0');

function frame(text) {
  const data = Buffer.from(text);
  const prefix = Buffer.alloc(5); prefix.writeUInt32BE(data.length, 1);
  return Buffer.concat([prefix, data]);
}
function reference(client) {
  return new Promise((resolve, reject) => client.makeUnaryRequest('/fixture.Race/Unary', bytes=>bytes, bytes=>bytes,
    Buffer.from('ping'), new grpc.Metadata(), {deadline:Date.now()+2000}, (error, message) => {
      try { assert.ifError(error); assert.equal(message.toString(), 'pong'); resolve(); } catch(error) { reject(error); }
    }));
}
async function matrix(executable, mode, key, cert, caPath) {
  const sockets = new Set();
  const drained = new Set();
  const retire = () => sockets.size === 0 ? Promise.resolve() : new Promise((resolve, reject) => {
    const timer = setTimeout(()=>{drained.delete(done);reject(new Error('connection race sockets did not retire'));},5000);
    const done=()=>{clearTimeout(timer);drained.delete(done);resolve();}; drained.add(done);
  });
  const track = socket => {
    sockets.add(socket); socket.on('error',()=>{});
    socket.once('close',()=>{sockets.delete(socket);if(sockets.size===0)for(const done of drained)done();});
  };
  const accepts = [0,0];
  const stalled = accepts.map((_,i)=>net.createServer(socket=>{accepts[i]++;track(socket);socket.resume();}));
  for (const server of stalled) await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const tlsVersion = mode==='tls12' ? 'TLSv1.2' : 'TLSv1.3';
  const server = mode==='h2c' ? http2.createServer() : http2.createSecureServer({key,cert,minVersion:tlsVersion,maxVersion:tlsVersion});
  server.on('connection',track);
  const sessions = [];
  let failure;
  server.on('session',session=>{const row={session,requests:0,client:null};sessions.push(row);session.on('error',error=>{failure??=error;});});
  server.on('stream',(stream,headers)=>{
    stream.on('error',error=>{failure??=error;});
    try {
      assert.equal(headers[':path'],'/fixture.Race/Unary');
      assert.equal(headers[':authority'],'fixture.test');
      assert.equal(headers[':scheme'],mode==='h2c'?'http':'https');
      const row=sessions.find(row=>row.session===stream.session);
      row.client??=headers['x-fixture-client']??'grpc-js'; row.requests++;
      if(mode!=='h2c'){assert.equal(stream.session.socket.alpnProtocol,'h2');assert.equal(stream.session.socket.servername,'fixture.test');assert.equal(stream.session.socket.getProtocol(),tlsVersion);}
      const data=[];stream.on('data',bytes=>data.push(bytes));
      stream.on('end',()=>{
        try {
          assert.deepEqual(Buffer.concat(data),frame('ping'));
          stream.respond({':status':200,'content-type':'application/grpc'},{waitForTrailers:true});
          stream.once('wantTrailers',()=>stream.sendTrailers({'grpc-status':'0'}));stream.end(frame('pong'));
        }catch(error){failure??=error;stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR);}
      });
    }catch(error){failure??=error;stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR);}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const ports=[...stalled.map(server=>server.address().port),server.address().port];
  const client=new grpc.Client('ipv4:'+ports.map(port=>'127.0.0.1:'+port).join(','),mode==='h2c'?grpc.credentials.createInsecure():grpc.credentials.createSsl(fs.readFileSync(caPath)),
    {'grpc.default_authority':'fixture.test','grpc.ssl_target_name_override':'fixture.test','grpc.enable_retries':0});
  const rows=[];
  try {
    await reference(client);await reference(client);client.close();
    let pendingAfterReferenceClose = 0;
    try { await retire(); }
    catch(error) {
      assert.equal(error.message,'connection race sockets did not retire');
      pendingAfterReferenceClose=sockets.size;
      assert.ok(pendingAfterReferenceClose>0);
      // Keep the upstream close boundary in the result. Retire only this
      // reference cohort before starting strict native cleanup checks.
      for(const socket of sockets)socket.destroy();
      await retire();
    }
    assert.deepEqual(accepts,[1,1]);assert.equal(sessions.length,1);assert.equal(sessions[0].requests,2);
    rows.push({mode,client:'grpc-js',stalled:[...accepts],rpcs:2,pendingAfterReferenceClose});
    for(const phase of ['stagger','ordered','deadline','immediate','shared_reset']){
      const before=[...accepts],sessionsBefore=sessions.length;
      const result=await run(executable,[mode,phase,...ports.map(String),caPath],{timeout:15000,maxBuffer:1024*1024});
      await retire();if(failure)throw failure;
      const record=JSON.parse(result.stdout);const rpcs=phase==='stagger'||phase==='immediate'||phase==='shared_reset'?2:0;
      assert.deepEqual(record,{io:'zio-std-io',mode,phase,rpcs});
      const attempted=accepts.map((value,i)=>value-before[i]);
      assert.deepEqual(attempted,phase==='stagger'?[1,1]:phase==='immediate'||phase==='shared_reset'?[0,0]:[1,0]);
      assert.equal(sessions.length-sessionsBefore,rpcs?1:0);
      if(rpcs)assert.equal(sessions.at(-1).requests,2);
      rows.push({...record,client:'netz',stalled:attempted,allSocketsRetired:true});
    }
    return rows;
  }catch(error){throw new Error(`${mode}: ${error.stack}; peer=${failure?.stack??'none'}`);}
  finally{client.close();for(const socket of sockets)socket.destroy();for(const row of sessions)row.session.destroy();await Promise.all([server,...stalled].map(server=>new Promise(resolve=>server.close(resolve))));}
}
async function main(){
  assert.equal(process.argv.length,6);
  const [executable,keyPath,certPath,caPath]=process.argv.slice(2);
  const rows=[];for(const mode of ['h2c','tls12','tls13'])rows.push(...await matrix(executable,mode,fs.readFileSync(keyPath),fs.readFileSync(certPath),caPath));
  process.stdout.write(JSON.stringify({reference:'grpc-js-'+version,node:process.version,rows})+'\n');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
