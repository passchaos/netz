'use strict';
// JS only serves official Envoy protobufs and raw HTTP/2. C-Core resolves URIs.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http2 = require('node:http2');
const net = require('node:net');
const crypto = require('node:crypto');
const readline = require('node:readline');
const modules = path.resolve(__dirname, '../grpc_locality/node_modules');
const grpc = require(path.join(modules, '@grpc/grpc-js'));
const loader = require(path.join(modules, '@grpc/proto-loader'));
const protobuf = require(path.join(modules, 'protobufjs'));
const deps = path.join(modules, '@grpc/grpc-js-xds/deps');
const includes = ['envoy-api', 'xds', 'googleapis', 'protoc-gen-validate'].map(name => path.join(deps, name));
includes.push(path.join(modules, 'protobufjs'));
const definition = loader.loadSync('envoy/service/discovery/v3/ads.proto', {
  includeDirs: includes, keepCase: true, defaults: true, longs: String, enums: String
});
const service = grpc.loadPackageDefinition(definition).envoy.service.discovery.v3.AggregatedDiscoveryService.service;
const root = new protobuf.Root();
root.resolvePath = (_origin, target) => includes.map(dir => path.join(dir, target)).find(file => fs.existsSync(file)) ?? target;
root.loadSync(['envoy/service/discovery/v3/ads.proto', 'envoy/config/listener/v3/listener.proto', 'envoy/config/cluster/v3/cluster.proto',
  'envoy/config/endpoint/v3/endpoint.proto', 'envoy/extensions/filters/http/router/v3/router.proto',
  'envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto'], {keepCase: true});
root.resolveAll();
const urls = {
  lds: 'type.googleapis.com/envoy.config.listener.v3.Listener',
  cds: 'type.googleapis.com/envoy.config.cluster.v3.Cluster',
  eds: 'type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment'
};
const hcmUrl = 'type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager';
const digest = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function moduleCodeDigest(directory) {
  const files = [];
  const visit = folder => {
    for (const entry of fs.readdirSync(folder, {withFileTypes: true})) {
      const file = path.join(folder, entry.name);
      if (entry.isDirectory()) visit(file);
      else if (/\.(?:js|cjs|mjs|json|node)$/.test(entry.name)) files.push(file);
    }
  };
  visit(directory);
  const hash = crypto.createHash('sha256');
  for (const file of files.sort()) hash.update(path.relative(directory, file)).update('\0').update(fs.readFileSync(file)).update('\0');
  return hash.digest('hex');
}
function canonicalJson(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort()
    .map(key => JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
function schemaProvenance() {
  const proto_sha256 = {}, builtin_proto_provenance = {};
  for (const name of [...new Set(root.files)].sort()) {
    if (Object.hasOwn(protobuf.common, name)) {
      // Root loads these descriptors from common.js without reading a .proto.
      // Preserve the consumed descriptor and the code that defines/loads it.
      const descriptor_sha256 = crypto.createHash('sha256')
        .update(canonicalJson(protobuf.common[name])).digest('hex');
      const package_source_sha256 = {};
      for (const source of ['src/common.js', 'src/root.js', 'package.json']) {
        package_source_sha256['protobufjs/' + source] = digest(path.join(modules, 'protobufjs', source));
      }
      const key = 'protobufjs-builtin:' + name;
      proto_sha256[key] = descriptor_sha256;
      builtin_proto_provenance[key] = {kind: 'protobufjs-builtin', logical_name: name,
        descriptor_encoding: 'canonical-json', descriptor_sha256, package_source_sha256};
      continue;
    }
    const resolved = path.isAbsolute(name) ? name : root.resolvePath('', name);
    const file = [resolved, path.join(modules, 'protobufjs', name)]
      .find(candidate => fs.existsSync(candidate) && fs.statSync(candidate).isFile());
    assert(file, 'missing consumed protobuf schema: ' + name);
    proto_sha256[path.relative(modules, file)] = digest(file);
  }
  return {proto_sha256, builtin_proto_provenance};
}
const encode = (name, value) => {
  const type = root.lookupType(name);
  const error = type.verify(value);
  assert.equal(error, null, error ?? '');
  return Buffer.from(type.encode(type.create(value)).finish());
};
function resource(kind, name, port) {
  let value;
  if (kind === 'lds') {
    const hcm = {
      route_config: {name: 'inline', virtual_hosts: [{name: 'backend', domains: ['*'], routes: [
        {match: {prefix: '/fixture.Target/'}, route: {cluster: 'backend'}}
      ]}]},
      http_filters: [{name: 'router', typed_config: {
        type_url: 'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router', value: Buffer.alloc(0)
      }}]
    };
    value = {name, api_listener: {api_listener: {type_url: hcmUrl,
      value: encode('envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager', hcm)}}};
  } else if (kind === 'cds') {
    value = {name, type: 3, connect_timeout: {seconds: 1}, lb_policy: 0,
      eds_cluster_config: {eds_config: {ads: {}, resource_api_version: 2}, service_name: 'backend-eds'}};
  } else {
    value = {cluster_name: name, endpoints: [{locality: {region: 'local'}, load_balancing_weight: {value: 1},
      lb_endpoints: [{health_status: 1, endpoint: {address: {socket_address: {
        address: '127.0.0.1', port_value: port
      }}}}]}]};
  }
  return {type_url: urls[kind], value: encode(urls[kind].slice('type.googleapis.com/'.length), value)};
}

const controls = [], sessions = new Set(), tcpConnections = [];
const transcript = {requests: [], backend_calls: [], errors: [], session_errors: []};
let backend, proxy, finished = false, watchdog;
const outputPath = process.argv[3];
function finish(code = 0) {
  if (finished) return;
  finished = true;
  clearTimeout(watchdog);
  transcript.tcp_captures = tcpConnections.map(connection => ({id: connection.id,
    client_base64: Buffer.concat(connection.client).toString('base64'),
    server_base64: Buffer.concat(connection.server).toString('base64'), socket_errors: connection.errors}));
  if (outputPath) fs.writeFileSync(outputPath, JSON.stringify(transcript, null, 2) + '\n');
  controls.forEach(server => server.forceShutdown());
  sessions.forEach(session => session.destroy());
  tcpConnections.forEach(connection => {connection.downstream.destroy(); connection.upstream.destroy();});
  if (proxy) proxy.close();
  if (backend) backend.close();
  process.exitCode = code;
}
process.on('SIGTERM', () => finish());
process.on('SIGINT', () => finish());
(async () => {
  const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  watchdog = setTimeout(() => {transcript.errors.push('peer watchdog expired'); finish(1);}, config.peer_timeout_ms);
  backend = http2.createServer();
  backend.on('session', session => {
    sessions.add(session);
    session.on('close', () => sessions.delete(session));
    session.on('error', error => {
      transcript.errors.push('HTTP/2 session: ' + error.message);
      transcript.session_errors.push({code: error.code, errno: error.errno ?? null, message: error.message});
    });
  });
  backend.on('stream', (stream, headers) => {
    const chunks = [];
    stream.on('error', error => transcript.errors.push('HTTP/2 stream: ' + error.message));
    stream.on('data', bytes => chunks.push(bytes));
    stream.on('end', () => {
      try {
        const body = Buffer.concat(chunks);
        transcript.backend_calls.push({authority: headers[':authority'], path: headers[':path'],
          method: headers[':method'], content_type: headers['content-type'], request_base64: body.toString('base64')});
        assert.equal(headers[':method'], 'POST');
        assert.equal(headers[':path'], '/fixture.Target/Unary');
        assert(headers['content-type'].startsWith('application/grpc'));
        assert.equal(body.toString('hex'), '000000000c' + Buffer.from('target-probe').toString('hex'));
        stream.respond({':status': 200, 'content-type': 'application/grpc'}, {waitForTrailers: true});
        stream.on('wantTrailers', () => stream.sendTrailers({'grpc-status': '0'}));
        stream.end(body);
      } catch (error) {
        transcript.errors.push(error.stack);
        stream.close(http2.constants.NGHTTP2_INTERNAL_ERROR);
      }
    });
  });
  await new Promise((resolve, reject) => {
    backend.once('error', reject);
    backend.listen(0, '127.0.0.1', resolve);
  });
  // Capture byte-for-byte before nghttp2 validates :authority. The proxy does
  // not parse or alter HTTP/2; an independently pinned HPACK decoder reads it.
  proxy = net.createServer(downstream => {
    const upstream = net.connect({host: '127.0.0.1', port: backend.address().port});
    const connection = {id: tcpConnections.length + 1, downstream, upstream,
      client: [], server: [], clientBytes: 0, serverBytes: 0, errors: []};
    tcpConnections.push(connection);
    if (tcpConnections.length > 8) {
      transcript.errors.push('TCP capture exceeded connection limit'); downstream.destroy(); upstream.destroy(); return;
    }
    const capture = (direction, bytes) => {
      connection[direction + 'Bytes'] += bytes.length;
      if (connection[direction + 'Bytes'] > 256 * 1024) {
        transcript.errors.push('TCP capture exceeded byte limit'); downstream.destroy(); upstream.destroy(); return;
      }
      connection[direction].push(Buffer.from(bytes));
    };
    downstream.on('data', bytes => capture('client', bytes));
    upstream.on('data', bytes => capture('server', bytes));
    downstream.on('error', error => {connection.errors.push({side: 'client', code: error.code, message: error.message}); upstream.destroy();});
    upstream.on('error', error => {connection.errors.push({side: 'server', code: error.code, message: error.message}); downstream.destroy();});
    downstream.on('close', () => upstream.destroy());
    upstream.on('close', () => downstream.destroy());
    downstream.pipe(upstream); upstream.pipe(downstream);
  });
  await new Promise((resolve, reject) => {proxy.once('error', reject); proxy.listen(0, '127.0.0.1', resolve);});
  const ports = {};
  for (const scope of config.scopes) {
    const control = new grpc.Server();
    controls.push(control);
    let streamSequence = 0;
    control.addService(service, {StreamAggregatedResources(call) {
      const stream = ++streamSequence;
      const sent = new Set();
      call.on('error', () => {});
      call.on('data', request => {
        const kind = Object.keys(urls).find(key => urls[key] === request.type_url);
        transcript.requests.push({scope, stream, type_url: request.type_url,
          names: request.resource_names, version: request.version_info, nonce: request.response_nonce,
          node_id: request.node?.id ?? null, error: request.error_detail?.message ?? null});
        if (request.error_detail) transcript.errors.push('ADS NACK: ' + request.error_detail.message);
        if (!kind) {transcript.errors.push('unexpected ADS type: ' + request.type_url); return;}
        const key = kind + '\0' + JSON.stringify(request.resource_names);
        if (!request.resource_names.length || sent.has(key)) return;
        sent.add(key);
        if (kind === 'cds' && (request.resource_names.length !== 1 || request.resource_names[0] !== 'backend')) {
          transcript.errors.push('unexpected CDS subscription'); return;
        }
        if (kind === 'eds' && (request.resource_names.length !== 1 || request.resource_names[0] !== 'backend-eds')) {
          transcript.errors.push('unexpected EDS subscription'); return;
        }
        const version = 'v1-' + kind;
        call.write({type_url: urls[kind], version_info: version, nonce: version,
          resources: request.resource_names.map(name => resource(kind, name, proxy.address().port))});
      });
    }, DeltaAggregatedResources(call) {
      transcript.errors.push('unexpected delta ADS stream'); call.end();
    }});
    ports[scope] = await new Promise((resolve, reject) => control.bindAsync('127.0.0.1:0',
      grpc.ServerCredentials.createInsecure(), (error, port) => error ? reject(error) : resolve(port)));
  }
  // Hash the actual protobuf import closure, including ADS and well-known types.
  Object.assign(transcript, schemaProvenance());
  transcript.dependencies = {};
  for (const name of ['@grpc/grpc-js', '@grpc/grpc-js-xds', '@grpc/proto-loader', 'protobufjs']) {
    const file = path.join(modules, name, 'package.json');
    transcript.dependencies[name] = {version: JSON.parse(fs.readFileSync(file)).version, package_sha256: digest(file),
      module_code_sha256: moduleCodeDigest(path.join(modules, name))};
  }
  console.log(JSON.stringify({status: 'ready', ports, backend_port: proxy.address().port,
    validated_backend_port: backend.address().port, node: process.version}));
  const input = readline.createInterface({input: process.stdin});
  input.on('line', line => {if (line === 'stop') {input.close(); finish();}});
  input.on('close', () => finish());
})().catch(error => {transcript.errors.push(error.stack); console.error(error.stack); finish(1);});
