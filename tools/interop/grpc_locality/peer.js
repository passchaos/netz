'use strict';
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const grpc = require('@grpc/grpc-js');
const registry = require('@grpc/grpc-js/build/src/load-balancer');
const {localityToName} = require('@grpc/grpc-js-xds/build/src/load-balancer-cds');
require('@grpc/grpc-js-xds/build/src/load-balancer-xds-wrr-locality').setup();

// Capture the config emitted by the actual upstream locality LB. Its child
// remains a probe so this checks transformation independently of wire tests.
const snapshots = [];
class CaptureConfig {
  constructor(value) { this.value = value; }
  static createFromJson(value) { return new CaptureConfig(value); }
  getLoadBalancerName() { return 'weighted_target'; }
  toJsonObject() { return {weighted_target: this.value}; }
}
class CaptureBalancer {
  updateAddressList(endpoints, config) { snapshots.push(config.value); return true; }
  destroy() {}
  exitIdle() {}
  resetBackoff() {}
}
registry.registerLoadBalancerType('weighted_target', CaptureBalancer, CaptureConfig);
const noop = () => {};
const helper = {createSubchannel: noop, updateState: noop, requestReresolution: noop, addChannelzChild: noop, removeChannelzChild: noop};
const policy = registry.parseLoadBalancingConfig({xds_wrr_locality: {child_policy: [{round_robin: {}}]}});
const oracle = registry.createLoadBalancer(policy, helper);
function oracleTargets(a, b) {
  const endpoints = ['a', 'a', 'b'].map((region, index) => ({
    addresses: [{host: '127.0.0.1', port: 1000 + index}], locality: {region, zone: '', sub_zone: ''},
    localityPath: [region], localityWeight: region === 'a' ? a : b
  }));
  assert.equal(oracle.updateAddressList({ok: true, value: endpoints}, policy, {}, ''), true);
  const actual = snapshots.at(-1).targets;
  assert.equal(actual[localityToName(endpoints[0].locality)].weight, a);
  assert.equal(actual[localityToName(endpoints[2].locality)].weight, b);
  return {a: actual[localityToName(endpoints[0].locality)].weight,
          b: actual[localityToName(endpoints[2].locality)].weight};
}
const expected = [oracleTargets(1, 3), oracleTargets(3, 1)];
oracle.destroy();

const definition = {Unary: {path: '/fixture.Locality/Unary', requestStream: false, responseStream: false,
  requestSerialize: value => value, requestDeserialize: value => value,
  responseSerialize: value => value, responseDeserialize: value => value}};
function execute(binary, args) {
  return new Promise((resolve, reject) => {
    const process = spawn(binary, args);
    let output = '';
    const timer = setTimeout(() => { process.kill(); reject(new Error('native locality gate timed out')); }, 30000);
    process.stdout.on('data', data => output += data);
    process.stderr.on('data', data => output += data);
    process.on('error', error => { clearTimeout(timer); reject(error); });
    process.on('exit', code => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(output));
      const line = output.split('\n').find(line => line.startsWith('LOCALITY_RESULT '));
      if (!line) return reject(new Error(output));
      resolve(JSON.parse(line.slice('LOCALITY_RESULT '.length)));
    });
  });
}
async function run(binary, mode) {
  const counts = [0, 0, 0];
  const sessions = [new Set(), new Set(), new Set()];
  const servers = [];
  try {
    const ports = [];
    for (const [index, name] of ['a1', 'a2', 'b'].entries()) {
      const server = new grpc.Server();
      server.addService(definition, {Unary(call, callback) {
        assert.equal(call.request.toString(), 'request');
        counts[index]++;
        sessions[index].add(call.call.stream.session);
        callback(null, Buffer.from(name));
      }});
      servers.push(server);
      ports.push(await new Promise((resolve, reject) => server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, port) => error ? reject(error) : resolve(port))));
    }
    const result = await execute(binary, [mode, ...ports.map(String)]);
    assert.deepEqual(result.generated_before, [expected[0].a, expected[0].b]);
    assert.deepEqual(result.generated_after, mode === 'shared' ? [expected[1].a, expected[1].b] : [expected[0].a, expected[0].b]);
    const totals = result.before.map((value, index) => value + result.after[index] + result.removed[index] + result.restored[index]);
    assert.deepEqual(counts, totals);
    assert.deepEqual(sessions.map(value => value.size), [1, 1, 1]);
    if (mode === 'shared') {
      assert.deepEqual(result.removed, [0, 0, 20]);
      assert(result.after[0] + result.after[1] > 240);
      assert(result.restored[0] + result.restored[1] > 50);
    }
    return {...result, wire_counts: counts, sessions: sessions.map(value => value.size)};
  } finally { servers.forEach(server => server.forceShutdown()); }
}
(async () => {
  const results = [];
  for (const mode of ['ordinary', 'shared']) results.push(await run(process.argv[2], mode));
  console.log(JSON.stringify({status: 'passed', grpc_js: require('@grpc/grpc-js/package.json').version,
    grpc_js_xds: require('@grpc/grpc-js-xds/package.json').version, upstream_generated_weights: expected, results}));
})().catch(error => { console.error(error); process.exitCode = 1; });
