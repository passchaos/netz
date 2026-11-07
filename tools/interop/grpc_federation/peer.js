'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http2 = require('node:http2');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');
const schema = require('./schema');
const {grpc, urls, names} = schema;
const unary = {path: '/fixture.Federation/Barrier', requestStream: false, responseStream: false,
  requestSerialize: x => x, requestDeserialize: x => x, responseSerialize: x => x, responseDeserialize: x => x};
const expectedCalls = [
  ['B', 'initial-b'], ['A', 'initial-canary-a'], ['B', 'held-b'], ['B', 'b-omission'],
  ['B', 'a-omission-b'], ['A', 'restored-canary-a'], ['B', 'nack-b'],
  ['B', 'pending-rds-b'], ['B', 'pending-cds-b'], ['A', 'replacement-a']
];
const allowed = {A: {lds: [names.listener], rds: [], cds: [names.canary, names.mainA], eds: [names.canaryEds, names.mainAEds]},
  B: {lds: [], rds: [names.route], cds: [names.mainB], eds: [names.mainBEds]}};
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');

async function main(native, mode, directory) {
  assert(['sotw', 'delta'].includes(mode));
  const sources = Object.fromEntries(['A', 'B'].map(name => [name, {name, requests: [], responses: [], lrs: [],
    initials: [], watches: {lds: [], rds: [], cds: [], eds: []}, sent: new Set(), accepted: {}, decisions: {}, totals: {}}]));
  const events = [], applications = [], waits = [], servers = [], backends = [], sessions = new Set();
  let child, held, failure, nativeOutput = '', phase = 'initial';
  const trace = (event, value = {}) => events.push({order: events.length, event, ...value});
  function fail(error) {
    if (!failure) {failure = error; trace('failure', {message: String(error)});}
    if (child && child.exitCode === null) child.kill();
  }
  function notify() {
    for (let index = 0; index < waits.length;) {
      const item = waits[index];
      try {
        if (!item.ready()) {index++; continue;}
        waits.splice(index, 1); clearTimeout(item.timer); item.run();
      } catch (error) {fail(error); return;}
    }
  }
  function wait(label, ready, run) {
    if (ready()) return run();
    waits.push({label, ready, run, timer: setTimeout(() => fail(new Error('barrier deadline: ' + label)), 4500)});
  }
  function frame(payload) {
    const header = Buffer.alloc(5); header.writeUInt32BE(payload.length, 1); return Buffer.concat([header, payload]);
  }
  function finishCall(call) {
    assert(!call.finished); call.finished = true;
    trace('application_completed', {source: call.source, label: call.label});
    call.stream.respond({':status': 200, 'content-type': 'application/grpc'}, {waitForTrailers: true});
    call.stream.on('wantTrailers', () => call.stream.sendTrailers({'grpc-status': '0'}));
    call.stream.end(frame(Buffer.from(call.source + ':' + call.label)));
  }
  const ports = {};
  for (const source of ['A', 'B']) {
    const backend = http2.createServer(); backends.push(backend);
    backend.on('session', session => {
      sessions.add(session); session.on('close', () => sessions.delete(session)); session.on('error', fail);
    });
    backend.on('stream', (stream, headers) => {
      const chunks = [];
      stream.on('error', fail);
      stream.on('data', bytes => chunks.push(bytes));
      stream.on('end', () => {
        try {
          const body = Buffer.concat(chunks);
          assert.equal(body[0], 0); assert.equal(body.readUInt32BE(1), body.length - 5);
          assert.equal(headers[':method'], 'POST'); assert.equal(headers[':authority'], 'service');
          assert(headers['content-type'].startsWith('application/grpc'));
          const label = body.subarray(5).toString();
          const expected = expectedCalls[applications.length];
          assert.deepEqual([source, label], expected, 'data-plane route/source/order mismatch');
          assert.equal(headers[':path'], label.includes('canary') ? '/fixture.Federation/Canary' : '/fixture.Federation/Main');
          const call = {source, label, stream, finished: false};
          applications.push({source, label, authority: headers[':authority'], path: headers[':path'], request_sha256: hash(body)});
          trace('application_started', {source, label});
          if (label === 'held-b') {assert(!held); held = call; notify();}
          else {finishCall(call); notify();}
        } catch (error) {fail(error);}
      });
    });
    await new Promise((resolve, reject) => {backend.once('error', reject); backend.listen(0, '127.0.0.1', resolve);});
    ports[source] = backend.address().port;
  }
  const canaryCds = () => schema.cluster(names.canary, names.canaryEds);
  const bCds = () => schema.cluster(names.mainB, names.mainBEds);
  const canaryEds = () => schema.assignment(names.canaryEds, ports.A);
  const bEds = () => schema.assignment(names.mainBEds, ports.B);
  function send(source, kind, version, resources, removed = []) {
    assert(source.call, 'missing ADS stream for ' + source.name);
    const value = {source: source.name, kind, version, names: resources.map(item => item.name), removed,
      sha256: resources.map(item => hash(item.value))};
    source.responses.push(value); trace('discovery_response', value);
    const payloads = resources.map(({type_url, value}) => ({type_url, value}));
    if (mode === 'sotw') source.call.write({type_url: urls[kind], version_info: version, nonce: version, resources: payloads});
    else source.call.write({type_url: urls[kind], system_version_info: version, nonce: version, removed_resources: removed,
      resources: resources.map((item, index) => ({name: item.name, version, resource: payloads[index]}))});
  }
  function total(source, name) {return sources[source].totals[name] ?? {issued: 0, successful: 0, failed: 0, in_progress: 0};}
  function finalCounts() {
    const b = total('B', names.mainB), canary = total('A', names.canary), a = total('A', names.mainA);
    return b.issued === 7 && b.successful === 7 && b.failed === 0 && b.in_progress === 0 &&
      canary.issued === 2 && canary.successful === 2 && canary.failed === 0 && canary.in_progress === 0 &&
      a.issued === 1 && a.successful === 1 && a.failed === 0 && a.in_progress === 0;
  }
  function barrier(source, call, callback) {
    const label = call.request.toString();
    const respond = () => {trace('barrier_completed', {source: source.name, label}); callback(null, Buffer.from(label));};
    try {
      switch (label) {
        case 'held-entered':
          assert.equal(source.name, 'B'); return wait(label, () => !!held && total('A', names.canary).successful === 1 &&
            total('B', names.mainB).issued === 2 && total('B', names.mainB).successful === 1 &&
            total('B', names.mainB).in_progress === 1, respond);
        case 'omit-b':
          assert.equal(source.name, 'B'); assert.equal(phase, 'initial'); phase = 'b-omitted';
          send(source, 'cds', 'c-b-omit', [], mode === 'delta' ? [names.mainB] : []); return respond();
        case 'omit-a':
          assert.equal(source.name, 'A'); assert.equal(phase, 'b-omitted'); phase = 'a-omitted';
          send(source, 'cds', 'c-a-omit', [], mode === 'delta' ? [names.canary] : []); return respond();
        case 'restore-a':
          assert.equal(source.name, 'A'); assert.equal(phase, 'a-omitted'); phase = 'a-restored';
          send(source, 'cds', 'c-a2', [canaryCds()]); send(source, 'eds', 'e-a2', [canaryEds()]); return respond();
        case 'malformed-a':
          assert.equal(source.name, 'A'); assert.equal(phase, 'a-restored'); phase = 'a-malformed';
          send(source, 'cds', 'c-a-bad', [schema.cluster(names.canary, names.canaryEds, true)]); return respond();
        case 'switch-route':
          assert.equal(source.name, 'B'); assert.equal(phase, 'a-malformed');
          return wait(label, () => sources.A.nackSeen === true, () => {
            phase = 'a-pending'; send(source, 'rds', 'r-b2', [schema.route(names.mainA)]); respond();
          });
        case 'complete-a-cds':
          assert.equal(source.name, 'A'); assert.equal(phase, 'a-pending');
          return wait(label, () => source.watches.cds.includes(names.mainA), () => {
            phase = 'a-cds'; send(source, 'cds', 'c-a3', [canaryCds(), schema.cluster(names.mainA, names.mainAEds)]); respond();
          });
        case 'complete-a-eds':
          assert.equal(source.name, 'A'); assert.equal(phase, 'a-cds');
          return wait(label, () => source.watches.eds.includes(names.mainAEds), () => {
            phase = 'a-complete'; send(source, 'eds', 'e-a3', [canaryEds(), schema.assignment(names.mainAEds, ports.A)]); respond();
          });
        case 'release-held':
          assert.equal(source.name, 'B'); assert.equal(phase, 'a-complete');
          return wait(label, () => applications.some(item => item.label === 'replacement-a') &&
            total('A', names.mainA).successful === 1 && total('B', names.mainB).successful === 6 &&
            total('B', names.mainB).issued === 7 && total('B', names.mainB).in_progress === 1, () => {
            assert(held && !held.finished); trace('held_released_after_a_replacement'); finishCall(held); phase = 'held-released'; respond();
          });
        case 'final-reports':
          assert.equal(source.name, 'B'); assert.equal(phase, 'held-released');
          return wait(label, () => finalCounts() && (mode === 'sotw' ||
            sources.B.watches.cds.length === 0 && sources.B.watches.eds.length === 0), respond);
        default: assert.fail('unexpected barrier: ' + label);
      }
    } catch (error) {fail(error);}
  }
  const listen = server => new Promise((resolve, reject) => server.bindAsync('127.0.0.1:0',
    grpc.ServerCredentials.createInsecure(), (error, port) => error ? reject(error) : resolve(port)));
  const controlPorts = {};
  for (const source of Object.values(sources)) {
    const server = new grpc.Server(); servers.push(server);
    const connect = call => {
      try {
        assert(!source.call, 'unexpected ADS reconnect'); source.call = call;
        call.on('error', () => {});
        call.on('data', request => {
          try {
            const kind = Object.keys(urls).find(kind => urls[kind] === request.type_url);
            assert(kind, 'unexpected ADS type');
            if (request.node) assert.equal(request.node.id, 'netz-federation');
            if (mode === 'sotw') source.watches[kind] = [...request.resource_names].sort();
            else {
              const watches = new Set(source.watches[kind]);
              for (const name of request.resource_names_subscribe) watches.add(name);
              for (const name of request.resource_names_unsubscribe) watches.delete(name);
              source.watches[kind] = [...watches].sort();
              assert.deepEqual(request.initial_resource_versions, {}, 'unexpected delta reconnect state');
            }
            for (const name of source.watches[kind]) assert(allowed[source.name][kind].includes(name), 'cross-authority watch: ' + name);
            const record = {source: source.name, kind, names: [...source.watches[kind]],
              subscribe: request.resource_names_subscribe ?? null, unsubscribe: request.resource_names_unsubscribe ?? null,
              version: request.version_info ?? null, nonce: request.response_nonce, error: request.error_detail ?? null,
              node: request.node?.id ?? null};
            source.requests.push(record); trace('discovery_request', record);
            if (request.response_nonce) {
              const response = source.responses.find(value => value.version === request.response_nonce && value.kind === kind);
              assert(response, 'ACK/NACK did not identify an emitted response');
              const decisionKey = kind + '\0' + request.response_nonce;
              const decision = {version: request.version_info ?? null, error: request.error_detail ?? null};
              // Subscription updates carry the latest response nonce. They must
              // preserve the original decision instead of inventing another ACK.
              if (source.decisions[decisionKey]) assert.deepEqual(decision, source.decisions[decisionKey]);
              else source.decisions[decisionKey] = decision;
              if (request.error_detail) {
                assert.equal(source.name, 'A'); assert.equal(kind, 'cds'); assert.equal(request.response_nonce, 'c-a-bad');
                assert.equal(request.error_detail.code, 3); assert.equal(request.error_detail.message, 'UnsupportedCdsFeature');
                if (mode === 'sotw') assert.equal(request.version_info, 'c-a2');
                source.nackSeen = true;
              } else {
                if (mode === 'sotw') assert.equal(request.version_info, request.response_nonce);
                source.accepted[kind] = request.response_nonce;
              }
            } else assert(!request.error_detail);
            if (phase === 'initial' && source.watches[kind].length && !source.sent.has(kind)) {
              source.sent.add(kind);
              if (kind === 'lds') {assert.equal(source.name, 'A'); assert.deepEqual(source.watches.lds, [names.listener]); send(source, kind, 'l-a1', [schema.listener()]);}
              else if (kind === 'rds') {assert.equal(source.name, 'B'); assert.deepEqual(source.watches.rds, [names.route]); send(source, kind, 'r-b1', [schema.route(names.mainB)]);}
              else if (kind === 'cds') send(source, kind, source.name === 'A' ? 'c-a1' : 'c-b1', [source.name === 'A' ? canaryCds() : bCds()]);
              else send(source, kind, source.name === 'A' ? 'e-a1' : 'e-b1', [source.name === 'A' ? canaryEds() : bEds()]);
            }
            notify();
          } catch (error) {fail(error);}
        });
      } catch (error) {fail(error);}
    };
    server.addService(schema.adsService, {
      StreamAggregatedResources(call) {if (mode !== 'sotw') return fail(new Error('unexpected SotW ADS')); connect(call);},
      DeltaAggregatedResources(call) {if (mode !== 'delta') return fail(new Error('unexpected delta ADS')); connect(call);}
    });
    server.addService({Barrier: unary}, {Barrier: (call, callback) => barrier(source, call, callback)});
    server.addService(schema.lrsService, {StreamLoadStats(call) {
      call.on('error', () => {});
      let initial = true;
      call.on('data', request => {
        try {
          if (initial) {
            initial = false; assert(request.node); assert.equal(request.node.id, 'netz-federation');
            assert(request.node.client_features.includes('envoy.lrs.supports_send_all_clusters'));
            assert.deepEqual(request.cluster_stats, []); source.initials.push(request);
            call.write({send_all_clusters: true, load_reporting_interval: {seconds: '0', nanos: 100000000}});
          } else {
            assert(!request.node); source.lrs.push(request);
            for (const cluster of request.cluster_stats) {
              const expected = source.name === 'B' ? {[names.mainB]: names.mainBEds} : {[names.canary]: names.canaryEds, [names.mainA]: names.mainAEds};
              assert.equal(cluster.cluster_service_name, expected[cluster.cluster_name], 'LRS reached wrong source/identity');
              assert.equal(Number(cluster.total_dropped_requests), 0);
              const total = source.totals[cluster.cluster_name] ??= {issued: 0, successful: 0, failed: 0, in_progress: 0};
              let inProgress = 0;
              for (const local of cluster.upstream_locality_stats) {
                assert.deepEqual(local.locality, {region: 'r', zone: 'z', sub_zone: ''});
                total.issued += Number(local.total_issued_requests); total.successful += Number(local.total_successful_requests);
                total.failed += Number(local.total_error_requests); inProgress += Number(local.total_requests_in_progress);
              }
              total.in_progress = inProgress;
            }
          }
          trace('lrs_request', {source: source.name, initial: !!request.node, totals: JSON.parse(JSON.stringify(source.totals))}); notify();
        } catch (error) {fail(error);}
      });
    }});
    controlPorts[source.name] = await listen(server);
  }
  const server = (name, ignore) => ({server_uri: '127.0.0.1:' + controlPorts[name], channel_creds: [{type: 'insecure'}],
    server_features: ['xds_v3', ...(ignore ? ['ignore_resource_deletion'] : [])]});
  const bootstrapPath = path.join(directory, 'bootstrap.json');
  fs.writeFileSync(bootstrapPath, JSON.stringify({node: {id: 'netz-federation'}, xds_servers: [server('A', false)],
    authorities: {A: {xds_servers: [server('A', false)]}, B: {xds_servers: [server('B', true)]}}}, null, 2) + '\n');
  const provenance = schema.provenance();
  const report = () => ({status: failure ? 'failed' : 'passed', mode, failure: failure ? String(failure) : null,
    stack: failure?.stack, pending_barriers: waits.map(item => item.label), phase,
    sources: Object.fromEntries(Object.entries(sources).map(([key, value]) => [key, {
      requests: value.requests, responses: value.responses, watches: value.watches, accepted: value.accepted,
      lrs: value.lrs, lrs_initials: value.initials, totals: value.totals
    }])), applications, events, native_output: nativeOutput, ...provenance});
  try {
    const code = await new Promise((resolve, reject) => {
      child = spawn(native, [bootstrapPath, String(controlPorts.A), String(controlPorts.B), mode]);
      const timer = setTimeout(() => {fail(new Error('native federation deadline exceeded'));}, 45000);
      for (const stream of [child.stdout, child.stderr]) stream.on('data', bytes => {
        nativeOutput += bytes;
        if (nativeOutput.length > 1024 * 1024) fail(new Error('native output limit exceeded'));
      });
      child.on('error', error => {clearTimeout(timer); reject(error);});
      child.on('close', code => {clearTimeout(timer); resolve(code);});
    });
    if (failure) throw failure;
    assert.equal(code, 0, nativeOutput);
    const line = nativeOutput.split('\n').find(value => value.startsWith('FEDERATION_RESULT '));
    assert(line, nativeOutput); const nativeResult = JSON.parse(line.slice('FEDERATION_RESULT '.length));
    assert.equal(nativeResult.status, 'passed'); assert.equal(nativeResult.mode, mode);
    assert.equal(nativeResult.manual_subscription_routing, false); assert.notEqual(nativeResult.source_a, nativeResult.source_b);
    assert.deepEqual(applications.map(item => [item.source, item.label]), expectedCalls);
    assert(finalCounts()); assert(held.finished);
    for (const source of Object.values(sources)) {
      for (const response of source.responses) {
        const decision = source.decisions[response.kind + '\0' + response.version];
        assert(decision, 'missing ACK/NACK decision for ' + response.version);
        assert.equal(!!decision.error, response.version === 'c-a-bad');
      }
      assert(source.initials.length >= 1 && source.initials.length <= (source.name === 'A' ? 2 : 1),
        'unexpected automatic source LRS stream count');
    }
    const expectedWatches = {A: {lds: [[names.listener]], rds: [],
      cds: [[names.canary], [names.canary, names.mainA].sort()],
      eds: [[names.canaryEds], [names.canaryEds, names.mainAEds].sort()]},
    B: {lds: [], rds: [[names.route]], cds: mode === 'sotw' ? [[names.mainB]] : [[names.mainB], []],
      eds: mode === 'sotw' ? [[names.mainBEds]] : [[names.mainBEds], []]}};
    for (const source of Object.values(sources)) for (const kind of Object.keys(urls)) {
      const transitions = [];
      for (const request of source.requests.filter(value => value.kind === kind)) {
        if (!transitions.length || JSON.stringify(transitions.at(-1)) !== JSON.stringify(request.names)) transitions.push(request.names);
      }
      assert.deepEqual(transitions, expectedWatches[source.name][kind], 'exact watch transitions for ' + source.name + '/' + kind);
    }
    const records = nativeOutput.split('\n').filter(value => value.startsWith('FEDERATION_EVENT ')).map(value => JSON.parse(value.slice('FEDERATION_EVENT '.length)));
    assert.equal(records.length, 14); assert.equal(records.filter(value => value.rejected).length, 1);
    for (const record of records) {
      const response = sources[record.authority].responses.find(value => value.version === record.nonce);
      assert(response); assert.equal(urls[response.kind], record.type_url);
    }
    const order = predicate => {const value = events.find(predicate); assert(value); return value.order;};
    assert(order(value => value.event === 'application_started' && value.label === 'replacement-a') <
      order(value => value.event === 'held_released_after_a_replacement'));
    assert(order(value => value.event === 'held_released_after_a_replacement') <
      order(value => value.event === 'application_completed' && value.label === 'held-b'));
    const result = {...report(), native: nativeResult, native_events: records};
    fs.writeFileSync(path.join(directory, 'wire.json'), JSON.stringify(result, null, 2) + '\n');
    console.log(JSON.stringify(result));
  } catch (error) {
    failure ??= error;
    fs.writeFileSync(path.join(directory, 'wire.json'), JSON.stringify(report(), null, 2) + '\n');
    console.error(error.stack); process.exitCode = 1;
  } finally {
    if (child && child.exitCode === null) child.kill();
    waits.forEach(item => clearTimeout(item.timer)); servers.forEach(server => server.forceShutdown());
    sessions.forEach(session => session.destroy()); backends.forEach(server => server.close());
  }
}
if (process.argv.length !== 5) throw new Error('usage: node peer.js <prebuilt-native> <sotw|delta> <artifact-directory>');
main(process.argv[2], process.argv[3], process.argv[4]).catch(error => {console.error(error.stack); process.exitCode = 1;});
