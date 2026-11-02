'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const {spawn} = require('node:child_process');
const grpc = require('../grpc_locality/node_modules/@grpc/grpc-js');
const loader = require('../grpc_locality/node_modules/@grpc/proto-loader');
const deps = path.resolve(__dirname, '../grpc_locality/node_modules/@grpc/grpc-js-xds/deps');
const definition = loader.loadSync('envoy/service/discovery/v3/ads.proto', {
  includeDirs: ['envoy-api', 'xds', 'googleapis', 'protoc-gen-validate'].map(name => path.join(deps, name)),
  keepCase: true, defaults: true, longs: String, enums: String, oneofs: true
});
const service = grpc.loadPackageDefinition(definition).envoy.service.discovery.v3.AggregatedDiscoveryService.service;
const cds = 'type.googleapis.com/envoy.config.cluster.v3.Cluster';
const eds = 'type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment';
let streams = 0;
let requests = 0;
const sessions = new Set();
const transcripts = [];
function response(call, type, version, nonce, resourceType = type) {
  call.write({type_url: type, version_info: version, nonce,
    resources: [{type_url: resourceType, value: Buffer.from([10, 1, 97])}]});
}
const server = new grpc.Server();
server.addService(service, {StreamAggregatedResources(call) {
  const epoch = ++streams;
  sessions.add(call.call.stream.session);
  let step = 0;
  call.on('error', () => {});
  call.on('data', request => {
    requests++;
    transcripts.push({epoch, version: request.version_info, type_url: request.type_url,
      names: request.resource_names, nonce: request.response_nonce, nack: request.error_detail?.message ?? '', node: !!request.node});
    if (step === 0) {
      assert.equal(request.node.id, 'netz-ads-node');
      assert.equal(request.node.cluster, 'interop-client');
      assert.equal(request.node.metadata.fields.role.boolValue, true);
      assert.deepEqual(request.node.locality, {region: 'region', zone: 'zone', sub_zone: 'sub'});
      assert.equal(request.node.user_agent_name, 'netz');
      assert(request.node.client_features.includes('envoy.lb.does_not_support_overprovisioning'));
    } else assert.equal(request.node, null);
    if (epoch === 1) {
      if (step === 0) { assert.equal(request.type_url, cds); assert.deepEqual(request.resource_names, ['a']); assert.equal(request.version_info, ''); }
      else if (step === 1) { assert.equal(request.type_url, eds); assert.equal(request.version_info, ''); response(call, cds, 'c1', 'c-n1'); response(call, eds, 'e1', 'e-n1'); }
      else if (step === 2) { assert.equal(request.type_url, cds); assert.equal(request.version_info, 'c1'); assert.equal(request.response_nonce, 'c-n1'); assert.deepEqual(request.resource_names, ['a', 'b']); }
      else if (step === 3) { assert.equal(request.type_url, eds); assert.equal(request.version_info, 'e1'); assert.equal(request.response_nonce, 'e-n1'); response(call, cds, 'bad', 'c-bad', eds); }
      else if (step === 4) { assert.equal(request.type_url, cds); assert.equal(request.version_info, 'c1'); assert.equal(request.response_nonce, 'c-bad'); assert.equal(request.error_detail.code, 3); assert.equal(request.error_detail.message, 'resource type mismatch'); response(call, cds, 'c2', 'c-n2'); response(call, cds, 'c3', 'c-n3'); }
      else if (step === 5) { assert.equal(request.type_url, cds); assert.equal(request.version_info, 'c3'); assert.equal(request.response_nonce, 'c-n3'); call.emit('error', {code: grpc.status.UNAVAILABLE, details: 'restart'}); }
      else assert.fail('extra request on first stream');
    } else {
      assert.equal(epoch, 2);
      if (step === 0) { assert.equal(request.type_url, cds); assert.equal(request.version_info, 'c3'); assert.equal(request.response_nonce, ''); assert.deepEqual(request.resource_names, ['a', 'b']); }
      else if (step === 1) { assert.equal(request.type_url, eds); assert.equal(request.version_info, 'e1'); assert.equal(request.response_nonce, ''); assert.equal(request.error_detail, null); setTimeout(() => response(call, eds, 'e2', 'e-n2'), 100); }
      else if (step === 2) { assert.equal(request.type_url, eds); assert.equal(request.version_info, 'e2'); assert.equal(request.response_nonce, 'e-n2'); call.end(); }
      else assert.fail('extra request on second stream');
    }
    step++;
  });
}});
(async () => {
  const port = await new Promise((resolve, reject) => server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, port) => error ? reject(error) : resolve(port)));
  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.argv[2], [String(port)]);
    let output = '';
    const timer = setTimeout(() => {child.kill(); reject(new Error('ADS native client timeout'));}, 15000);
    child.stdout.on('data', data => output += data);
    child.stderr.on('data', data => output += data);
    child.on('error', error => {clearTimeout(timer); reject(error);});
    child.on('exit', code => {clearTimeout(timer); if (code !== 0) return reject(new Error(output)); const line = output.split('\n').find(value => value.startsWith('ADS_RESULT ')); if (!line) return reject(new Error(output)); resolve(JSON.parse(line.slice(11)));});
  });
  assert.equal(streams, 2); assert.equal(sessions.size, 1); assert.equal(requests, 9);
  console.log(JSON.stringify({...result, streams, sessions: sessions.size, requests, transcripts,
    grpc_js: require('../grpc_locality/node_modules/@grpc/grpc-js/package.json').version}));
})().catch(error => {console.error(error); process.exitCode = 1;}).finally(() => server.forceShutdown());
