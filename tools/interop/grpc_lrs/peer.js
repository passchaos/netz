'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const {createHash} = require('node:crypto');
const {spawn} = require('node:child_process');
const grpc = require('../grpc_locality/node_modules/@grpc/grpc-js');
const loader = require('../grpc_locality/node_modules/@grpc/proto-loader');
const deps = path.resolve(__dirname, '../grpc_locality/node_modules/@grpc/grpc-js-xds/deps');
const includes = ['envoy-api', 'xds', 'googleapis', 'protoc-gen-validate'].map(name => path.join(deps, name));
const definition = loader.loadSync('envoy/service/load_stats/v3/lrs.proto', {
  includeDirs: includes, keepCase: true, defaults: true, longs: String, enums: String
});
const service = grpc.loadPackageDefinition(definition).envoy.service.load_stats.v3.LoadReportingService.service;
const method = service.StreamLoadStats;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

function metric(count, value) {
  return {num_requests_finished_with_metric: String(count), total_metric_value: value};
}
function named(name, count, value) {
  return {metric_name: name, ...metric(count, value)};
}
function counters(successful, inProgress, errors, issued) {
  return {total_successful_requests: String(successful), total_requests_in_progress: String(inProgress),
    total_error_requests: String(errors), total_issued_requests: String(issued)};
}
function endpoint(host, port, counts) {
  return {address: {socket_address: {address: host, port_value: port}}, ...counts};
}

// These official-schema messages are independent inputs to the native request
// decoder. The native encoder constructs matching reports separately.
const officialRequest = {cluster_stats: [
  {
    cluster_name: 'a', cluster_service_name: 'eds-a', total_dropped_requests: '1',
    dropped_requests: [{category: 'throttle', dropped_count: '1'}],
    load_report_interval: {seconds: '0', nanos: 100000000},
    upstream_locality_stats: [{
      locality: {region: 'r', zone: 'z', sub_zone: ''}, ...counters(1, 0, 1, 1),
      cpu_utilization: metric(1, 0.5), mem_utilization: metric(2, 0.25), application_utilization: metric(3, 1.0),
      load_metric_stats: [named('load', 4, 2.0), named('other', 1, 3.0)],
      upstream_endpoint_stats: [endpoint('127.0.0.1', 1001, counters(1, 0, 0, 1))]
    }]
  },
  {
    cluster_name: 'a', cluster_service_name: 'eds-other', total_dropped_requests: '2',
    dropped_requests: [{category: 'circuit', dropped_count: '2'}],
    load_report_interval: {seconds: '0', nanos: 200000000},
    upstream_locality_stats: [{
      locality: {region: 'r', zone: 'z-alt', sub_zone: 'sub'}, ...counters(2, 1, 2, 4),
      cpu_utilization: metric(5, 1.25), mem_utilization: metric(6, 1.5), application_utilization: metric(7, 3.5),
      load_metric_stats: [named('load', 8, 4.5), named('other', 9, 5.5)],
      upstream_endpoint_stats: [endpoint('127.0.0.2', 1002, counters(2, 1, 2, 4))]
    }]
  }
]};

function assertMetric(actual, expected) {
  assert(actual, 'missing official metric field');
  assert.equal(actual.num_requests_finished_with_metric, expected.num_requests_finished_with_metric);
  assert.equal(actual.total_metric_value, expected.total_metric_value);
  if (expected.metric_name !== undefined) assert.equal(actual.metric_name, expected.metric_name);
}
function assertCounters(actual, expected) {
  for (const name of ['total_successful_requests', 'total_requests_in_progress', 'total_error_requests', 'total_issued_requests']) {
    assert.equal(actual[name], expected[name], name);
  }
}
function assertReport(request) {
  assert(!request.node);
  assert.equal(request.cluster_stats.length, 2);
  for (let index = 0; index < 2; index++) {
    const actual = request.cluster_stats[index], expected = officialRequest.cluster_stats[index];
    assert.equal(actual.cluster_name, expected.cluster_name);
    assert.equal(actual.cluster_service_name, expected.cluster_service_name);
    assert.equal(actual.total_dropped_requests, expected.total_dropped_requests);
    assert.deepEqual(actual.load_report_interval, expected.load_report_interval);
    assert.deepEqual(actual.dropped_requests, expected.dropped_requests);
    assert.equal(actual.upstream_locality_stats.length, 1);
    const locality = actual.upstream_locality_stats[0], wanted = expected.upstream_locality_stats[0];
    assert.deepEqual(locality.locality, wanted.locality);
    assertCounters(locality, wanted);
    for (const field of ['cpu_utilization', 'mem_utilization', 'application_utilization']) assertMetric(locality[field], wanted[field]);
    assert.equal(locality.load_metric_stats.length, 2);
    for (let metricIndex = 0; metricIndex < 2; metricIndex++) assertMetric(locality.load_metric_stats[metricIndex], wanted.load_metric_stats[metricIndex]);
    assert.equal(locality.upstream_endpoint_stats.length, 1);
    const actualEndpoint = locality.upstream_endpoint_stats[0], expectedEndpoint = wanted.upstream_endpoint_stats[0];
    assert.equal(actualEndpoint.address.socket_address.address, expectedEndpoint.address.socket_address.address);
    assert.equal(actualEndpoint.address.socket_address.port_value, expectedEndpoint.address.socket_address.port_value);
    assertCounters(actualEndpoint, expectedEndpoint);
  }
}

const decoderBytes = method.requestSerialize(officialRequest);
// Sanity-check the pinned official field names before handing the actual
// serialized bytes to the production native decoder.
assertReport(method.requestDeserialize(decoderBytes));
const decoderFixture = {
  byte_count: decoderBytes.length, sha256: digest(decoderBytes),
  cluster_identities: officialRequest.cluster_stats.map(cluster => ({cluster_name: cluster.cluster_name, cluster_service_name: cluster.cluster_service_name})),
  utilization_fields: {cpu_utilization: 12, mem_utilization: 13, application_utilization: 14},
  named_metric_field: 5, request: officialRequest
};

async function main(client) {
  const transcript = [];
  let step = 0, outboundReport = null, failure = null, child = null;
  const fail = error => {if (!failure) failure = error; if (child) child.kill();};
  const control = new grpc.Server();
  try {
    control.addService(service, {StreamLoadStats(call) {
      call.on('error', () => {});
      call.on('data', request => {
        try {
          transcript.push({step, node: request.node ? request.node.id : '',
            features: request.node ? request.node.client_features ?? [] : [],
            clusters: (request.cluster_stats ?? []).map(cluster => ({cluster_name: cluster.cluster_name, cluster_service_name: cluster.cluster_service_name}))});
          if (step === 0) {
            assert.equal(request.node?.id, 'netz-lrs');
            assert((request.node?.client_features ?? []).includes('envoy.lrs.supports_send_all_clusters'));
            assert.deepEqual(request.cluster_stats ?? [], []);
            call.write({clusters: ['a', 'b'], load_reporting_interval: {seconds: '0', nanos: 100000000}, report_endpoint_granularity: true});
            step += 1;
            return;
          }
          if (step === 1) {
            assertReport(request);
            outboundReport = request;
            call.write({clusters: [], send_all_clusters: true});
            call.end();
            step += 1;
            return;
          }
          assert.fail('unexpected LRS request');
        } catch (error) {fail(error);}
      });
    }});
    const port = await new Promise((resolve, reject) => control.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, value) => error ? reject(error) : resolve(value)));
    const result = await new Promise((resolve, reject) => {
      child = spawn(client, [String(port), decoderBytes.toString('base64')]);
      let output = '';
      const timer = setTimeout(() => {child.kill(); reject(new Error('native LRS gate timeout\n' + output));}, 30000);
      for (const stream of [child.stdout, child.stderr]) stream.on('data', bytes => {
        output += bytes;
        if (output.length > 1024 * 1024) fail(new Error('unbounded native LRS output'));
      });
      child.on('error', error => {clearTimeout(timer); reject(error);});
      child.on('close', code => {
        clearTimeout(timer);
        if (failure) return reject(failure);
        if (code !== 0) return reject(new Error(output));
        const line = output.split('\n').find(value => value.startsWith('LRS_RESULT '));
        if (!line) return reject(new Error(output));
        try {resolve(JSON.parse(line.slice(11)));} catch (error) {reject(error);}
      });
    });
    assert.equal(step, 2);
    for (const contract of ['initial_subscription', 'report_counters', 'send_all', 'clean_terminal', 'request_decoder', 'request_encoder', 'utilization_metrics', 'named_metrics', 'distinct_service_identities']) assert.equal(result[contract], true, contract);
    assert.equal(result.report_cluster_count, 2);
    assert.equal(result.named_metrics_per_locality, 2);
    console.log(JSON.stringify({...result, endpoint_granularity: true, transcript, decoder_fixture: decoderFixture,
      outbound_report: outboundReport, grpc_js: require('../grpc_locality/node_modules/@grpc/grpc-js/package.json').version}));
  } finally {
    if (child && child.exitCode === null) child.kill();
    control.forceShutdown();
  }
}

if (process.argv[2] === '--schema-check') {
  console.log(JSON.stringify({status: 'passed', decoder_fixture: decoderFixture}));
} else {
  if (process.argv.length !== 3) throw new Error('usage: node peer.js <native-client> | --schema-check');
  main(process.argv[2]).catch(error => {console.error(error); process.exitCode = 1;});
}
