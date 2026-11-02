'use strict';
const assert = require('node:assert/strict');
const net = require('node:net');
const {spawn} = require('node:child_process');
const grpc = require('../grpc_locality/node_modules/@grpc/grpc-js');
const registry = require('../grpc_locality/node_modules/@grpc/grpc-js/build/src/load-balancer');
require('../grpc_locality/node_modules/@grpc/grpc-js-xds/build/src/load-balancer-xds-cluster-manager').setup();

// Execute the upstream manager and its picker with deterministic fake child
// pickers, independently of the native path ownership and network tests.
class LabelConfig {
  constructor(value) { this.label = value.label; }
  static createFromJson(value) { return new LabelConfig(value); }
  getLoadBalancerName() { return 'netz_oracle_label'; }
  toJsonObject() { return {netz_oracle_label: {label: this.label}}; }
}
class LabelPolicy {
  constructor(helper) { this.helper = helper; }
  updateAddressList(_endpoints, config) {
    this.helper.updateState(grpc.connectivityState.READY, {pick: () => ({label: config.label})}, null);
    return true;
  }
  destroy() {}
  resetBackoff() {}
  exitIdle() {}
}
registry.registerLoadBalancerType('netz_oracle_label', LabelPolicy, LabelConfig);
let picker;
const noop = () => {};
const helper = {createSubchannel: noop, updateState: (_state, next) => picker = next,
  requestReresolution: noop, addChannelzChild: noop, removeChannelzChild: noop};
const raw = {xds_cluster_manager: {children: {
  a: {child_policy: [{netz_oracle_label: {label: 'a'}}]},
  b: {child_policy: [{netz_oracle_label: {label: 'b'}}]}
}}};
const config = registry.parseLoadBalancingConfig(raw);
const oracle = registry.createLoadBalancer(config, helper);
assert.equal(oracle.updateAddressList({ok: true, value: []}, config, {}, ''), true);
for (const cluster of ['a', 'b']) assert.equal(picker.pick({extraPickInfo: {cluster}}).label, cluster);
for (const extraPickInfo of [{}, {cluster: 'missing'}]) assert.equal(picker.pick({extraPickInfo}).status.code, grpc.status.INTERNAL);
const removedConfig = registry.parseLoadBalancingConfig({xds_cluster_manager: {children: {b: raw.xds_cluster_manager.children.b}}});
oracle.updateAddressList({ok: true, value: []}, removedConfig, {}, '');
assert.equal(picker.pick({extraPickInfo: {cluster: 'a'}}).status.code, grpc.status.INTERNAL);
assert.equal(picker.pick({extraPickInfo: {cluster: 'b'}}).label, 'b');
oracle.destroy();

const unary = {path: '/fixture.Cluster/Unary', requestStream: false, responseStream: false,
  requestSerialize: x => x, requestDeserialize: x => x, responseSerialize: x => x, responseDeserialize: x => x};
const duplex = {...unary, path: '/fixture.Cluster/Duplex', requestStream: true, responseStream: true};
function execute(binary, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, args);
    let output = '';
    const timer = setTimeout(() => {child.kill(); reject(new Error('native cluster manager timeout'));}, 30000);
    child.stdout.on('data', bytes => output += bytes);
    child.stderr.on('data', bytes => output += bytes);
    child.on('error', error => {clearTimeout(timer); reject(error);});
    child.on('exit', code => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(output));
      const line = output.split('\n').find(value => value.startsWith('CLUSTER_RESULT '));
      if (!line) return reject(new Error(output));
      resolve(JSON.parse(line.slice('CLUSTER_RESULT '.length)));
    });
  });
}
async function run(binary, mode) {
  const counts = [0, 0, 0];
  const sessions = [new Set(), new Set(), new Set()];
  const servers = [];
  const failed = net.createServer(socket => socket.destroy());
  await new Promise(resolve => failed.listen(0, '127.0.0.1', resolve));
  const refusedPort = failed.address().port;
  await new Promise(resolve => failed.close(resolve));
  try {
    const ports = [];
    for (const [index, label] of ['a1', 'a2', 'b'].entries()) {
      const check = call => {
        for (const field of ['xds-cluster', 'xds_cluster', 'grpc.internal.cluster']) assert.equal(call.metadata.get(field).length, 0);
        sessions[index].add(call.call.stream.session);
      };
      const server = new grpc.Server();
      server.addService({Unary: unary, Duplex: duplex}, {
        Unary(call, callback) { check(call); assert.equal(call.request.toString(), 'request'); counts[index]++; callback(null, Buffer.from(label)); },
        Duplex(call) { check(call); let messages = 0; call.on('data', data => { assert.equal(data.toString(), 'request'); messages++; }); call.on('end', () => { assert.equal(messages, 1); counts[index]++; call.write(Buffer.from(label)); call.end(); }); }
      });
      servers.push(server);
      ports.push(await new Promise((resolve, reject) => server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, port) => error ? reject(error) : resolve(port))));
    }
    const result = await execute(binary, [mode, ...ports.map(String), String(refusedPort)]);
    assert.deepEqual(counts, result.counts);
    assert.deepEqual(sessions.map(value => value.size), [1, 1, 1]);
    assert(result.unknown_cluster && result.duplex);
    if (mode === 'shared') assert(result.queue_isolation && result.removed_restored);
    return {...result, wire_counts: counts, sessions: sessions.map(value => value.size), selector_headers_absent: true};
  } finally {servers.forEach(server => server.forceShutdown());}
}
(async () => {
  const results = [];
  for (const mode of ['ordinary', 'shared']) results.push(await run(process.argv[2], mode));
  console.log(JSON.stringify({status: 'passed', grpc_js: require('../grpc_locality/node_modules/@grpc/grpc-js/package.json').version,
    grpc_js_xds: require('../grpc_locality/node_modules/@grpc/grpc-js-xds/package.json').version,
    official_picker: {routes: ['a', 'b'], unknown_status: grpc.status.INTERNAL, removed_status: grpc.status.INTERNAL, surviving_cluster: 'b'}, results}));
})().catch(error => {console.error(error); process.exitCode = 1;});
