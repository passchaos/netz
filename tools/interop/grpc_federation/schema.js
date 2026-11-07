'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const modules = path.resolve(__dirname, '../grpc_locality/node_modules');
const grpc = require(path.join(modules, '@grpc/grpc-js'));
const loader = require(path.join(modules, '@grpc/proto-loader'));
const protobuf = require(path.join(modules, 'protobufjs'));
const deps = path.join(modules, '@grpc/grpc-js-xds/deps');
const includes = ['envoy-api', 'xds', 'googleapis', 'protoc-gen-validate'].map(name => path.join(deps, name));
includes.push(path.join(modules, 'protobufjs'));
const definition = loader.loadSync(['envoy/service/discovery/v3/ads.proto', 'envoy/service/load_stats/v3/lrs.proto'],
  {includeDirs: includes, keepCase: true, defaults: true, longs: String, enums: String});
const official = grpc.loadPackageDefinition(definition).envoy.service;
const root = new protobuf.Root();
root.resolvePath = (_origin, target) => includes.map(dir => path.join(dir, target)).find(file => fs.existsSync(file)) ?? target;
root.loadSync(['envoy/service/discovery/v3/ads.proto', 'envoy/service/load_stats/v3/lrs.proto',
  'envoy/service/status/v3/csds.proto',
  'envoy/config/listener/v3/listener.proto', 'envoy/config/route/v3/route.proto',
  'envoy/config/cluster/v3/cluster.proto', 'envoy/config/endpoint/v3/endpoint.proto',
  'envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto'], {keepCase: true});
root.resolveAll();
const csdsType = root.lookupType('envoy.service.status.v3.ClientStatusResponse');
function decodeCsds(bytes) {
  return csdsType.toObject(csdsType.decode(bytes), {defaults: true, longs: String, enums: String, bytes: Buffer});
}
const typeNames = {lds: 'envoy.config.listener.v3.Listener', rds: 'envoy.config.route.v3.RouteConfiguration',
  cds: 'envoy.config.cluster.v3.Cluster', eds: 'envoy.config.endpoint.v3.ClusterLoadAssignment'};
const urls = Object.fromEntries(Object.entries(typeNames).map(([key, name]) => [key, 'type.googleapis.com/' + name]));
const names = {listener: 'xdstp://A/envoy.config.listener.v3.Listener/service',
  route: 'xdstp://B/envoy.config.route.v3.RouteConfiguration/routes',
  canary: 'xdstp://A/envoy.config.cluster.v3.Cluster/canary',
  mainA: 'xdstp://A/envoy.config.cluster.v3.Cluster/main', mainB: 'xdstp://B/envoy.config.cluster.v3.Cluster/main',
  canaryEds: 'xdstp://A/envoy.config.endpoint.v3.ClusterLoadAssignment/canary',
  mainAEds: 'xdstp://A/envoy.config.endpoint.v3.ClusterLoadAssignment/main',
  mainBEds: 'xdstp://B/envoy.config.endpoint.v3.ClusterLoadAssignment/main'};
function encode(typeName, value) {
  const type = root.lookupType(typeName);
  assert.equal(type.verify(value), null);
  return Buffer.from(type.encode(type.create(value)).finish());
}
function resource(kind, value) {return {name: value.name ?? value.cluster_name, type_url: urls[kind], value: encode(typeNames[kind], value)};}
function listener() {
  const hcmName = 'envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager';
  return resource('lds', {name: names.listener, api_listener: {api_listener: {
    type_url: 'type.googleapis.com/' + hcmName, value: encode(hcmName, {
      rds: {config_source: {ads: {}, resource_api_version: 2}, route_config_name: names.route},
      http_filters: [{name: 'router', typed_config: {
        type_url: 'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router', value: Buffer.alloc(0)
      }}]
    })
  }}});
}
function route(main) {
  return resource('rds', {name: names.route, virtual_hosts: [{name: 'backend', domains: ['service'], routes: [
    {match: {path: '/fixture.Federation/Canary'}, route: {cluster: names.canary}},
    {match: {prefix: '/fixture.Federation/'}, route: {cluster: main}}
  ]}]});
}
function cluster(name, service, bad = false) {
  const value = {name, type: 3, lb_policy: 0, lrs_server: {self: {}},
    eds_cluster_config: {eds_config: {ads: {}, resource_api_version: 2}, service_name: service}};
  if (bad) value.transport_socket = {name: 'fixture.unsupported'};
  return resource('cds', value);
}
function assignment(name, port) {
  return resource('eds', {cluster_name: name, endpoints: [{locality: {region: 'r', zone: 'z'},
    load_balancing_weight: {value: 1}, lb_endpoints: [{health_status: 1, endpoint: {address: {socket_address: {
      address: '127.0.0.1', port_value: port
    }}}}]}]});
}
const digest = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
function canonicalJson(value) {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort()
    .map(key => JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
function provenance() {
  const proto_sha256 = {}, builtin_proto_provenance = {};
  for (const name of [...new Set(root.files)].sort()) {
    if (Object.hasOwn(protobuf.common, name)) {
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
  const dependencies = {};
  for (const name of ['@grpc/grpc-js', '@grpc/grpc-js-xds', '@grpc/proto-loader', 'protobufjs']) {
    const file = path.join(modules, name, 'package.json');
    dependencies[name] = {version: JSON.parse(fs.readFileSync(file)).version, package_sha256: digest(file)};
  }
  return {proto_sha256, builtin_proto_provenance, dependencies, node: process.version};
}
module.exports = {grpc, urls, names, listener, route, cluster, assignment, provenance, decodeCsds,
  adsService: official.discovery.v3.AggregatedDiscoveryService.service,
  lrsService: official.load_stats.v3.LoadReportingService.service};
