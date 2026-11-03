'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const {spawn} = require('node:child_process');
const grpc = require('../grpc_locality/node_modules/@grpc/grpc-js');
const loader = require('../grpc_locality/node_modules/@grpc/proto-loader');
const protobuf = require('../grpc_locality/node_modules/protobufjs');
const deps = path.resolve(__dirname, '../grpc_locality/node_modules/@grpc/grpc-js-xds/deps');
const includes = ['envoy-api', 'xds', 'googleapis', 'protoc-gen-validate'].map(value => path.join(deps, value));
const definition = loader.loadSync('envoy/service/discovery/v3/ads.proto', {includeDirs: includes, keepCase: true, defaults: true, longs: String, enums: String});
const adsService = grpc.loadPackageDefinition(definition).envoy.service.discovery.v3.AggregatedDiscoveryService.service;
const root = new protobuf.Root();
root.resolvePath = (_origin, target) => {
  for (const directory of includes) { const candidate = path.join(directory, target); if (require('node:fs').existsSync(candidate)) return candidate; }
  return target;
};
root.loadSync('envoy/config/endpoint/v3/endpoint.proto', {keepCase: true}); root.resolveAll();
const assignmentType = root.lookupType('envoy.config.endpoint.v3.ClusterLoadAssignment');
const typeUrl = 'type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment';
const {EndpointResourceType} = require('../grpc_locality/node_modules/@grpc/grpc-js-xds/build/src/xds-resource-type/endpoint-resource-type');
assert.equal(EndpointResourceType.get().allResourcesRequiredInSotW(), false);
const counts = [0,0,0,0]; const sessions = Array.from({length: 4}, () => new Set());
const servers = []; const transcript = [];
const unary = {path: '/fixture.Eds/Unary', requestStream: false, responseStream: false, requestSerialize: x=>x, requestDeserialize: x=>x, responseSerialize: x=>x, responseDeserialize: x=>x};
function endpoint(port, health = 1) { return {endpoint: {address: {socket_address: {address: '127.0.0.1', port_value: port}}}, health_status: health}; }
function resource(ports, reversed = false, unhealthy = false, duplicate = false) {
  const a = {locality: {region: 'a'}, load_balancing_weight: {value: reversed ? 3 : 1}, lb_endpoints: [endpoint(ports[0], unhealthy ? 2 : 1), endpoint(ports[1], unhealthy ? 2 : 1)]};
  const b = {locality: {region: 'b'}, load_balancing_weight: {value: reversed ? 1 : 3}, lb_endpoints: [endpoint(ports[2], unhealthy ? 2 : 1)]};
  const fallback = {locality: {region: 'fallback'}, priority: 1, load_balancing_weight: {value: 1}, lb_endpoints: [endpoint(ports[3])]};
  return {cluster_name: 'backend', endpoints: duplicate ? [a, {...a, lb_endpoints: [endpoint(ports[2])]}, fallback] : [a,b,fallback]};
}
(async () => {
  const ports = [];
  for (const [index, label] of ['a1','a2','b','fallback'].entries()) {
    const server = new grpc.Server();
    server.addService({Unary: unary}, {Unary(call, callback) { assert.equal(call.request.toString(), 'request'); counts[index]++; sessions[index].add(call.call.stream.session); callback(null, Buffer.from(label)); }});
    servers.push(server);
    ports.push(await new Promise((resolve,reject)=>server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error,port)=>error?reject(error):resolve(port))));
  }
  const control = new grpc.Server(); servers.push(control); let step = 0;
  control.addService(adsService, {StreamAggregatedResources(call) {
    const send = (version, nonce, value) => call.write({type_url: typeUrl, version_info: version, nonce, resources: value ? [{type_url: typeUrl, value: assignmentType.encode(assignmentType.create(value)).finish()}] : []});
    call.on('error', ()=>{});
    call.on('data', request => {
      transcript.push({version: request.version_info, nonce: request.response_nonce, names: request.resource_names, nack: request.error_detail?.message ?? ''});
      if (step===0) { assert.equal(request.node.id,'netz-eds-node'); send('v1','n1',resource(ports)); }
      else if (step===1) { assert.equal(request.version_info,'v1'); assert.equal(request.response_nonce,'n1'); }
      else if (step===2) { assert(request.resource_names.includes('phase-bad')); send('bad','bad-nonce',resource(ports,false,false,true)); }
      else if (step===3) { assert.equal(request.version_info,'v1'); assert.equal(request.response_nonce,'bad-nonce'); assert.equal(request.error_detail.code,3); send('v2','n2',resource(ports,false,true)); }
      else if (step===4) { assert.equal(request.version_info,'v2'); assert.equal(request.response_nonce,'n2'); }
      else if (step===5) { assert(request.resource_names.includes('phase-restore')); send('v3','n3',resource(ports,true)); }
      else if (step===6) { assert.equal(request.version_info,'v3'); assert.equal(request.response_nonce,'n3'); }
      else if (step===7) { assert(request.resource_names.includes('phase-omit')); send('v4','n4',null); }
      else if (step===8) { assert.equal(request.version_info,'v4'); assert.equal(request.response_nonce,'n4'); }
      else if (step===9) { assert(request.resource_names.includes('phase-unrelated')); send('v5','n5',{cluster_name:'other',endpoints:[]}); }
      else if (step===10) { assert.equal(request.version_info,'v5'); assert.equal(request.response_nonce,'n5'); }
      else if (step===11) { assert(request.resource_names.includes('phase-empty')); send('v6','n6',{cluster_name:'backend',endpoints:[]}); }
      else if (step===12) { assert.equal(request.version_info,'v6'); assert.equal(request.response_nonce,'n6'); call.end(); }
      else assert.fail('unexpected ADS request');
      step++;
    });
  }});
  const port = await new Promise((resolve,reject)=>control.bindAsync('127.0.0.1:0',grpc.ServerCredentials.createInsecure(),(error,p)=>error?reject(error):resolve(p)));
  const result = await new Promise((resolve,reject)=>{
    const child=spawn(process.argv[2],[String(port)]); let output=''; const timer=setTimeout(()=>{child.kill();reject(new Error('native EDS timeout'));},30000);
    child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);child.on('error',e=>{clearTimeout(timer);reject(e);});
    child.on('exit',code=>{clearTimeout(timer);if(code!==0)return reject(new Error(output));const line=output.split('\n').find(x=>x.startsWith('EDS_RESULT '));if(!line)return reject(new Error(output));resolve(JSON.parse(line.slice(11)));});
  });
  assert.equal(step,13); const nativeCounts=result.before.map((value,index)=>value+result.fallback[index]+result.after[index]+result.retained[index]); assert.deepEqual(counts,nativeCounts);
  assert.deepEqual(sessions.map(value=>value.size),[1,1,1,1]);
  console.log(JSON.stringify({...result,sotw_omission_is_deletion:false,wire_counts:counts,sessions:sessions.map(value=>value.size),transcript,grpc_js:require('../grpc_locality/node_modules/@grpc/grpc-js/package.json').version}));
})().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>servers.forEach(server=>server.forceShutdown()));
