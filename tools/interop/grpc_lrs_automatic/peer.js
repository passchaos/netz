'use strict';
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {createHash} = require('node:crypto');
const schema = require('./schema');
const {Relay} = require('./relay');
const {grpc, urls} = schema;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const unary = path => ({path, requestStream: false, responseStream: false,
  requestSerialize: value => value, requestDeserialize: value => value,
  responseSerialize: value => value, responseDeserialize: value => value});
const barrierService = {Barrier: unary('/fixture.Automatic/Barrier')};
const appService = {Eligible: unary('/fixture.Automatic/Eligible'), Ignored: unary('/fixture.Automatic/Ignored')};
const emptyTotals = () => ({issued: 0, successful: 0, failed: 0, dropped: 0, in_progress: 0,
  cpu: {count: 0, sum: 0}, memory: {count: 0, sum: 0}, application: {count: 0, sum: 0}, load: {count: 0, sum: 0}});

async function main(client) {
  const servers = [], events = [], applications = [], pending = [];
  const sources = Object.fromEntries(['A', 'B', 'C'].map(name => [name, {name, ads: [], raw_ads: [], lrs: [], initial_messages: [], initial_requests: 0, totals: emptyTotals()}]));
  let failure = null, child = null, held = null, cachedVerified = false, nackSeen = false, replacementSent = false, relay = null, nativeOutput = '';
  const fail = error => {if (!failure) failure = error; if (child) child.kill();};
  const trace = (event, data = {}) => events.push({order: events.length, event, ...data});
  function barrierState(label) {
    const check = (name, actual, expected) => ({name, actual, expected, matches: actual === expected});
    switch (label) {
      case 'held-entered': return [check('held_application_present', held !== null, true)];
      case 'cached-source-a': return [check('A.successful', sources.A.totals.successful, 2), check('A.issued', sources.A.totals.issued, 3),
        check('A.cpu.count', sources.A.totals.cpu.count, 2), check('B.initial_requests', sources.B.initial_requests, 0), check('A.in_progress', sources.A.totals.in_progress, 1)];
      case 'send-b-replacement': return [check('NACK_observed', nackSeen, true)];
      case 'release-held-after-b-report': return [check('B.failed', sources.B.totals.failed, 1), check('B.cpu.count', sources.B.totals.cpu.count, 1), check('A.successful', sources.A.totals.successful, 2)];
      case 'final-source-reports': return [check('A.successful', sources.A.totals.successful, 3), check('A.cpu.count', sources.A.totals.cpu.count, 3), check('B.failed', sources.B.totals.failed, 1)];
      default: return [];
    }
  }
  const sourceReport = source => ({ads: source.ads, raw_ads: source.raw_ads, lrs: source.lrs, initial_messages: source.initial_messages,
    initial_requests: source.initial_requests, report_requests: source.lrs.length, lrs_request_count: source.initial_requests + source.lrs.length, totals: source.totals});
  function notify() {
    for (let index = 0; index < pending.length;) {
      const wait = pending[index];
      try {
        if (!wait.ready()) {index++; continue;}
        pending.splice(index, 1);
        clearTimeout(wait.timer);
        wait.run();
      } catch (error) {fail(error); return;}
    }
  }
  function wait(label, ready, run) {
    if (ready()) return run();
    const item = {label, ready, run, timer: setTimeout(() => fail(new Error('barrier timeout: ' + label)), 4500)};
    pending.push(item);
  }
  function metric(total, actual) {
    if (!actual) return;
    total.count += Number(actual.num_requests_finished_with_metric);
    total.sum += actual.total_metric_value;
  }
  function consumeLrs(source, request) {
    // Preserve even the message that fails an assertion for diagnosis.
    source.lrs.push(request);
    assert(!request.node);
    for (const cluster of request.cluster_stats) {
      assert.equal(cluster.cluster_name, 'eligible', 'ineligible CDS must never be reported');
      assert.equal(cluster.cluster_service_name, 'eds-eligible');
      assert.equal(cluster.upstream_locality_stats.length, 1);
      assert.equal(Number(cluster.total_dropped_requests), 0);
      assert.deepEqual(cluster.dropped_requests, []);
      assert(Number(cluster.load_report_interval.seconds) > 0 || cluster.load_report_interval.nanos > 0);
      const local = cluster.upstream_locality_stats[0], totals = source.totals;
      assert.deepEqual(local.locality, {region: 'r', zone: 'z', sub_zone: ''});
      const counts = {issued: Number(local.total_issued_requests), successful: Number(local.total_successful_requests), failed: Number(local.total_error_requests)};
      totals.issued += counts.issued;
      totals.successful += counts.successful;
      totals.failed += counts.failed;
      totals.in_progress = Number(local.total_requests_in_progress);
      metric(totals.cpu, local.cpu_utilization);
      metric(totals.memory, local.mem_utilization);
      metric(totals.application, local.application_utilization);
      for (const named of local.load_metric_stats) {
        assert.equal(named.metric_name, 'named_metrics.load', 'CDS propagation key must survive into LRS');
        metric(totals.load, named);
      }
      if (counts.issued || counts.successful || counts.failed) {
        assert.equal(local.upstream_endpoint_stats.length, 1);
        const endpoint = local.upstream_endpoint_stats[0];
        assert.equal(endpoint.address.socket_address.address, '127.0.0.1');
        assert.equal(endpoint.address.socket_address.port_value, appPort);
        assert.equal(Number(endpoint.total_issued_requests), counts.issued);
        assert.equal(Number(endpoint.total_successful_requests), counts.successful);
        assert.equal(Number(endpoint.total_error_requests), counts.failed);
      }
    }
    trace('lrs_report', {source: source.name, totals: JSON.parse(JSON.stringify(source.totals))});
    notify();
  }
  function finishApp(call, callback, label, eligible) {
    const metadata = new grpc.Metadata();
    metadata.set('endpoint-load-metrics-bin', schema.orca(label === 'new', !eligible));
    trace('application_completed', {label, status: label === 'new' ? 14 : 0});
    if (label === 'new') callback({code: grpc.status.UNAVAILABLE, details: 'source B application failure'}, null, metadata);
    else callback(null, Buffer.from(label), metadata);
  }
  const app = new grpc.Server();
  servers.push(app);
  const handle = eligible => (call, callback) => {
    try {
      const label = call.request.toString();
      assert.equal(call.metadata.get('x-call')[0], label);
      assert(Number.isFinite(Number(call.getDeadline())));
      applications.push({label, eligible, metadata: call.metadata.getMap(), deadline_ms: Number(call.getDeadline())});
      trace('application_started', {label, eligible});
      if (label === 'held') {assert.equal(held, null); held = {call, callback}; notify(); return;}
      finishApp(call, callback, label, eligible);
    } catch (error) {fail(error);}
  };
  app.addService(appService, {Eligible: handle(true), Ignored: handle(false)});
  const listen = server => new Promise((resolve, reject) => server.bindAsync('127.0.0.1:0', grpc.ServerCredentials.createInsecure(), (error, port) => error ? reject(error) : resolve(port)));
  const appPort = await listen(app);
  const cdsImages = schema.clusters();
  const assignmentImages = schema.assignments(appPort);
  const controls = {};
  const send = (source, type, version, resources) => {
    assert(source.call, 'missing managed ADS stream');
    trace('discovery_response', {source: source.name, type, version, resource_sha256: resources.map(resource => hash(resource.value))});
    source.call.write({type_url: type, version_info: version, nonce: version, resources});
  };
  function gate(source, call, callback) {
    const label = call.request.toString();
    const respond = () => {trace('barrier_completed', {source: source.name, label}); callback(null, Buffer.from(label));};
    try {
      switch (label) {
        case 'held-entered': return wait(label, () => held !== null, respond);
        case 'cached-source-a':
          return wait(label, () => sources.A.totals.successful === 2 && sources.A.totals.issued === 3 && sources.A.totals.cpu.count === 2, () => {
            assert.equal(sources.B.initial_requests, 0);
            assert.equal(sources.A.totals.in_progress, 1);
            cachedVerified = true; respond();
          });
        case 'send-b-nack':
          assert(cachedVerified);
          send(sources.B, urls.cds, 'c-bad', schema.clusters(true));
          return respond();
        case 'send-b-replacement':
          return wait(label, () => nackSeen, () => {replacementSent = true; send(sources.B, urls.cds, 'c-b', cdsImages); respond();});
        case 'release-held-after-b-report':
          return wait(label, () => sources.B.totals.failed === 1 && sources.B.totals.cpu.count === 1, () => {
            assert.equal(sources.A.totals.successful, 2);
            assert(held); trace('held_released_after_b_report');
            finishApp(held.call, held.callback, 'held', true);
            respond();
          });
        case 'final-source-reports':
          return wait(label, () => sources.A.totals.successful === 3 && sources.A.totals.cpu.count === 3 && sources.B.totals.failed === 1, respond);
        default: assert.fail('unknown barrier ' + label);
      }
    } catch (error) {fail(error);}
  }
  for (const name of ['A', 'B', 'C']) {
    const source = sources[name], control = new grpc.Server();
    servers.push(control);
    controls[name] = control;
    control.addService(schema.adsService, {StreamAggregatedResources(call) {
      try {
        assert.equal(call.metadata.get('x-source')[0], name);
        assert(!source.call, 'unexpected managed ADS reconnect');
        source.call = call;
        call.on('error', () => {});
        call.on('data', request => {
          try {
            source.raw_ads.push(request);
            source.ads.push({type: request.type_url, version: request.version_info, nonce: request.response_nonce, names: request.resource_names,
              node: request.node?.id ?? '', nack: request.error_detail?.message ?? ''});
            trace('discovery_request', {source: name, ...source.ads.at(-1)});
            if (request.node) assert.equal(request.node.id, 'managed-automatic-node');
            if (request.error_detail) {
              assert.equal(name, 'B'); assert.equal(request.type_url, urls.cds);
              assert.equal(request.version_info, 'c-a'); assert.equal(request.response_nonce, 'c-bad');
              assert.equal(request.error_detail.code, 3); assert.equal(request.error_detail.message, 'UnsupportedCdsFeature');
              nackSeen = true; notify(); return;
            }
            if (request.response_nonce) {
              const suffix = name.toLowerCase();
              const accepted = name === 'B' && request.type_url === urls.cds ? 'c-b' : (request.type_url === urls.lds ? 'l-' : request.type_url === urls.cds ? 'c-' : 'e-') + suffix;
              assert.equal(request.version_info, accepted); assert.equal(request.response_nonce, accepted);
              return;
            }
            if (request.type_url === urls.lds) {
              assert.deepEqual(request.resource_names, ['frontend']);
              if (name !== 'B') send(source, urls.lds, 'l-' + name.toLowerCase(), [schema.listener()]);
              else assert.equal(request.version_info, 'l-a');
            } else if (request.type_url === urls.cds) {
              assert.deepEqual([...request.resource_names].sort(), ['eligible', 'ignored']);
              if (name === 'C') {assert.equal(relay.connections, 1); relay.stopListening(); trace('lrs_listener_closed_before_cds');}
              if (name !== 'B') send(source, urls.cds, 'c-' + name.toLowerCase(), cdsImages);
              else assert.equal(request.version_info, 'c-a');
            } else if (request.type_url === urls.eds) {
              assert.deepEqual([...request.resource_names].sort(), ['eds-eligible', 'eds-ignored']);
              if (name === 'B') assert.equal(request.version_info, 'e-a');
              send(source, urls.eds, 'e-' + name.toLowerCase(), assignmentImages);
            } else assert.fail('unexpected ADS resource type');
          } catch (error) {fail(error);}
        });
      } catch (error) {fail(error);}
    }});
    control.addService(schema.lrsService, {StreamLoadStats(call) {
      try {
        assert.notEqual(name, 'C', 'refused new LRS connection reached raw control server');
        assert.equal(call.metadata.get('x-source')[0], name);
        if (name === 'B') assert(replacementSent, 'cached CDS incorrectly selected source B');
        call.on('error', () => {});
        call.on('data', request => {
          try {
            if (request.node) {
              source.initial_messages.push(request);
              source.initial_requests++;
              assert.equal(source.initial_requests, 1, 'automatic source owner restarted');
              assert.equal(request.node.id, 'managed-automatic-node');
              assert(request.node.client_features.includes('fixture.automatic_lrs'));
              assert(request.node.client_features.includes('envoy.lrs.supports_send_all_clusters'));
              assert.deepEqual(request.cluster_stats, []);
              trace('lrs_initial_request', {source: name, metadata: call.metadata.getMap(), node: request.node});
              // Even requesting both clusters must never collect the ignored one.
              call.write({clusters: ['eligible', 'ignored'], load_reporting_interval: {seconds: '0', nanos: 100000000}, report_endpoint_granularity: true});
            } else consumeLrs(source, request);
          } catch (error) {fail(error);}
        });
        call.on('cancelled', () => trace('lrs_stream_canceled', {source: name}));
      } catch (error) {fail(error);}
    }});
    control.addService(barrierService, {Barrier: (call, callback) => gate(source, call, callback)});
  }
  const aPort = await listen(controls.A), bPort = await listen(controls.B), cUpstream = await listen(controls.C);
  relay = new Relay(cUpstream, fail);
  const cPort = await relay.listen();
  try {
    const code = await new Promise((resolve, reject) => {
      child = spawn(client, [String(aPort), String(bPort), String(cPort)]);
      const timer = setTimeout(() => {child.kill(); reject(new Error('automatic LRS native timeout\n' + nativeOutput));}, 35000);
      for (const stream of [child.stdout, child.stderr]) stream.on('data', bytes => {nativeOutput += bytes; if (nativeOutput.length > 1024 * 1024) fail(new Error('unbounded native output'));});
      child.on('error', error => {clearTimeout(timer); reject(error);});
      child.on('close', value => {clearTimeout(timer); resolve(value);});
    });
    if (failure) throw failure;
    assert.equal(code, 0, nativeOutput);
    const record = prefix => {const line = nativeOutput.split('\n').find(value => value.startsWith(prefix)); assert(line, nativeOutput); return JSON.parse(line.slice(prefix.length));};
    const summary = record('AUTOMATIC_LRS_RESULT '), provenance = record('AUTOMATIC_LRS_PROVENANCE '), refused = record('AUTOMATIC_LRS_REFUSED ');
    assert.equal(summary.status, 'passed'); assert.equal(summary.mode, 'sotw');
    assert.notEqual(provenance.source_a, provenance.source_b);
    assert.notEqual(refused.source_key, provenance.source_a); assert.notEqual(refused.source_key, provenance.source_b);
    assert.equal(provenance.explicit_lrs_options, false);
    assert.deepEqual(sources.A.totals, {...emptyTotals(), issued: 3, successful: 3, cpu: {count: 3, sum: 1.5}, memory: {count: 3, sum: 0.75}, application: {count: 3, sum: 3}, load: {count: 3, sum: 6}});
    assert.deepEqual(sources.B.totals, {...emptyTotals(), issued: 1, failed: 1, cpu: {count: 1, sum: 0.75}, memory: {count: 1, sum: 0.5}, application: {count: 1, sum: 1.5}, load: {count: 1, sum: 4.5}});
    assert.equal(sources.A.initial_requests, 1); assert.equal(sources.B.initial_requests, 1); assert.equal(sources.C.initial_requests, 0);
    assert.deepEqual(applications.map(item => item.label), ['first', 'ignored-a', 'held', 'cached', 'new', 'ignored-b', 'refused-lrs-published']);
    for (const source of Object.values(sources)) assert.equal(source.ads.length, 6, source.name + ' ACK/NACK transcript');
    assert(relay.stopped); assert.equal(relay.connections, 1);
    assert.equal(refused.collection_issued, 1); assert.equal(refused.collection_successful, 1);
    const order = predicate => {const event = events.find(predicate); assert(event, 'missing ordered event'); return event.order;};
    assert(order(event => event.event === 'discovery_response' && event.source === 'B' && event.version === 'c-b') < order(event => event.event === 'lrs_initial_request' && event.source === 'B'));
    assert(order(event => event.event === 'lrs_report' && event.source === 'B' && event.totals.failed === 1) < order(event => event.event === 'held_released_after_b_report'));
    assert(order(event => event.event === 'lrs_listener_closed_before_cds') < order(event => event.event === 'discovery_response' && event.source === 'C' && event.version === 'c-c'));
    const sourceReports = Object.fromEntries(Object.entries(sources).map(([name, source]) => [name, sourceReport(source)]));
    console.log(JSON.stringify({...summary, provenance, refused_network: {...refused, existing_ads_connections: relay.connections, listener_closed_before_cds: true},
      source_reports: sourceReports, application_calls: applications, events, schema: schema.sanity(),
      identical_cds_sha256: cdsImages.map(resource => hash(resource.value)),
      grpc_js: require('../grpc_locality/node_modules/@grpc/grpc-js/package.json').version}));
  } catch (error) {
    const diagnostic = {status: 'failed', reason: String(error), stack: error.stack,
      pending_barriers: pending.map(item => ({label: item.label, checks: barrierState(item.label)})),
      source_reports: Object.fromEntries(Object.entries(sources).map(([name, source]) => [name, sourceReport(source)])),
      application_calls: applications, events, native_output: nativeOutput,
      relay: {connections: relay.connections, listener_stopped: relay.stopped},
      phase: {cached_verified: cachedVerified, nack_seen: nackSeen, replacement_sent: replacementSent, held_present: held !== null},
      schema: schema.sanity()};
    console.error('AUTOMATIC_LRS_FAILURE ' + JSON.stringify(diagnostic));
    throw error;
  } finally {
    if (child && child.exitCode === null) child.kill();
    for (const item of pending) clearTimeout(item.timer);
    for (const server of servers) server.forceShutdown();
    await relay.close();
  }
}
if (process.argv[2] === '--schema-check') console.log(JSON.stringify(schema.sanity()));
else {
  if (process.argv.length !== 3) throw new Error('usage: node peer.js <native-client> | --schema-check');
  main(process.argv[2]).catch(error => {console.error(error); process.exitCode = 1;});
}
