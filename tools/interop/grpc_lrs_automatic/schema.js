'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const grpc = require('../grpc_locality/node_modules/@grpc/grpc-js');
const loader = require('../grpc_locality/node_modules/@grpc/proto-loader');
const protobuf = require('../grpc_locality/node_modules/protobufjs');
const deps = path.resolve(__dirname, '../grpc_locality/node_modules/@grpc/grpc-js-xds/deps');
const includes = ['envoy-api', 'xds', 'googleapis', 'protoc-gen-validate'].map(name => path.join(deps, name));
includes.push(path.dirname(require.resolve('../grpc_locality/node_modules/protobufjs/package.json')));
const definition = loader.loadSync(['envoy/service/discovery/v3/ads.proto', 'envoy/service/load_stats/v3/lrs.proto'], {
  includeDirs: includes, keepCase: true, defaults: true, longs: String, enums: String
});
const official = grpc.loadPackageDefinition(definition).envoy.service;
const root = new protobuf.Root();
root.resolvePath = (_origin, target) => includes.map(dir => path.join(dir, target)).find(file => fs.existsSync(file)) ?? target;
root.loadSync(['envoy/config/listener/v3/listener.proto', 'envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto',
  'envoy/config/cluster/v3/cluster.proto', 'envoy/config/endpoint/v3/endpoint.proto',
  path.resolve(__dirname, '../grpc_locality/node_modules/@grpc/grpc-js/proto/xds/xds/data/orca/v3/orca_load_report.proto')], {keepCase: true});
root.resolveAll();
const types = {
  lds: root.lookupType('envoy.config.listener.v3.Listener'), hcm: root.lookupType('envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager'),
  cds: root.lookupType('envoy.config.cluster.v3.Cluster'), eds: root.lookupType('envoy.config.endpoint.v3.ClusterLoadAssignment'),
  orca: root.lookupType('xds.data.orca.v3.OrcaLoadReport')
};
const urls = {lds: 'type.googleapis.com/envoy.config.listener.v3.Listener', cds: 'type.googleapis.com/envoy.config.cluster.v3.Cluster',
  eds: 'type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment'};
function encode(type, value) {return Buffer.from(type.encode(type.create(value)).finish());}
function resource(type, value) {return {type_url: urls[type], value: encode(types[type], value)};}
function listener() {
  const hcm = {
    http_filters: [{name: 'router', typed_config: {type_url: 'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router', value: Buffer.alloc(0)}}],
    route_config: {name: 'inline', virtual_hosts: [{name: 'backend', domains: ['backend.test'], routes: [
      {match: {prefix: '/fixture.Automatic/Eligible'}, route: {cluster: 'eligible'}},
      {match: {prefix: '/fixture.Automatic/Ignored'}, route: {cluster: 'ignored'}}
    ]}]}
  };
  return resource('lds', {name: 'frontend', api_listener: {api_listener: {
    type_url: 'type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager', value: encode(types.hcm, hcm)
  }}});
}
function clusters(bad = false) {
  return ['eligible', 'ignored'].map(name => {
    const value = {name, type: 3, eds_cluster_config: {eds_config: {ads: {}, resource_api_version: 2}, service_name: 'eds-' + name}};
    if (name === 'eligible') {
      value.lrs_server = {self: {}};
      value.lrs_report_endpoint_metrics = ['cpu_utilization', 'mem_utilization', 'application_utilization', 'named_metrics.load'];
      if (bad) value.transport_socket = {name: 'unsupported'};
    }
    return resource('cds', value);
  });
}
function assignments(port) {
  return ['eligible', 'ignored'].map(name => resource('eds', {cluster_name: 'eds-' + name, endpoints: [{
    locality: {region: 'r', zone: 'z'}, load_balancing_weight: {value: 1}, lb_endpoints: [{
      endpoint: {address: {socket_address: {address: '127.0.0.1', port_value: port}}}, health_status: 1
    }]
  }]}));
}
function orca(newSource = false, ignored = false) {
  const value = {cpu_utilization: ignored ? 99 : newSource ? 0.75 : 0.5, mem_utilization: newSource ? 0.5 : 0.25,
    application_utilization: ignored ? 99 : newSource ? 1.5 : 1};
  const report = types.orca.create(value);
  report.named_metrics = {load: ignored ? 99 : newSource ? 4.5 : 2, unselected: 100};
  return encode(types.orca, report);
}
function sanity() {
  assert.equal(types.cds.fields.lrs_server.id, 42);
  assert.equal(types.cds.fields.lrs_report_endpoint_metrics.id, 57);
  const images = clusters();
  assert(types.cds.decode(images[0].value).lrs_server.self);
  assert.equal(types.cds.decode(images[1].value).lrs_server, null);
  assert.equal(types.orca.decode(orca()).named_metrics.load, 2);
  assert.equal(types.orca.decode(orca(true)).mem_utilization, 0.5);
  assert(types.lds.decode(listener().value).api_listener);
  return {status: 'passed', self_field: 42, propagation_field: 57, named_metric_key: 'named_metrics.load',
    resource_bytes: {lds: listener().value.length, cds: images.map(item => item.value.length), orca: orca().length}};
}
module.exports = {grpc, urls, types, listener, clusters, assignments, orca, sanity,
  adsService: official.discovery.v3.AggregatedDiscoveryService.service,
  lrsService: official.load_stats.v3.LoadReportingService.service};
if (require.main === module) console.log(JSON.stringify(sanity()));
