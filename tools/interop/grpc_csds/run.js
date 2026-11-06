#!/usr/bin/env node
'use strict';

// Decode the netz CSDS response with the official Envoy schema shipped by the
// pinned grpc-js-xds dependency and verify every emitted field.

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const emitter = process.argv[2];
if (!emitter) {
  console.error('usage: run.js <emitter-executable>');
  process.exit(2);
}

const root = path.join(__dirname, '..', 'grpc_locality', 'node_modules');
const protobuf = require(path.join(root, 'protobufjs'));
const includes = [
  path.join(root, '@grpc/grpc-js-xds/deps/envoy-api'),
  path.join(root, '@grpc/grpc-js-xds/deps/googleapis'),
  path.join(root, '@grpc/grpc-js-xds/deps/xds'),
  path.join(root, '@grpc/grpc-js-xds/deps/protoc-gen-validate'),
  // protobufjs ships the google/protobuf well-known protos.
  path.join(root, 'protobufjs'),
];

const run = spawnSync(emitter, [], { encoding: 'utf8' });
if (run.status !== 0) {
  console.error(run.stderr || run.stdout);
  process.exit(run.status ?? 1);
}
const lines = (run.stdout + run.stderr).trim().split('\n').filter(Boolean);
if (lines.length < 2) {
  console.error('emitter produced fewer than two responses');
  process.exit(1);
}
const [base64, excludedBase64] = lines.slice(-2);

const schema = new protobuf.Root();
schema.resolvePath = (_origin, target) => {
  for (const dir of includes) {
    const file = path.join(dir, target);
    if (fs.existsSync(file)) return file;
  }
  return target;
};
schema.loadSync('envoy/service/status/v3/csds.proto', { keepCase: true });
schema.resolveAll();
const Response = schema.lookupType('envoy.service.status.v3.ClientStatusResponse');
const decode = (bytes) =>
  Response.toObject(Response.decode(Buffer.from(bytes, 'base64')), {
    enums: String,
    longs: String,
    defaults: true,
  });
const response = decode(base64);
const excludedResponse = decode(excludedBase64);

function fail(message) {
  console.error(`CSDS_RESULT {"status":"failed","error":${JSON.stringify(message)}}`);
  process.exit(1);
}

if (response.config.length !== 1) fail(`config count ${response.config.length}`);
const client = response.config[0];
if (client.node.id !== 'node-1') fail(`node id ${JSON.stringify(client.node.id)}`);
if (client.client_scope !== 'grpc') fail(`client scope ${JSON.stringify(client.client_scope)}`);
if (client.generic_xds_configs.length !== 3) {
  fail(`generic config count ${client.generic_xds_configs.length}`);
}

const expected = [
  {
    type_url: 'type.googleapis.com/envoy.config.listener.v3.Listener',
    name: 'frontend',
    version_info: 'v1',
    client_status: 'ACKED',
    wire: Buffer.from('\x0a\x08frontend').toString('hex'),
  },
  {
    type_url: 'type.googleapis.com/envoy.config.cluster.v3.Cluster',
    name: 'a',
    version_info: 'v2',
    client_status: 'ACKED',
    wire: Buffer.from('\x0a\x01a').toString('hex'),
  },
  {
    type_url: 'type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment',
    name: 'eds-a',
    version_info: '',
    client_status: 'REQUESTED',
    wire: null,
  },
];

for (const want of expected) {
  const got = client.generic_xds_configs.find(
    (entry) => entry.type_url === want.type_url && entry.name === want.name,
  );
  if (!got) fail(`missing ${want.type_url} ${want.name}`);
  if ((got.version_info ?? '') !== want.version_info) {
    fail(`${want.name} version ${JSON.stringify(got.version_info)}`);
  }
  if (got.client_status !== want.client_status) {
    fail(`${want.name} status ${JSON.stringify(got.client_status)}`);
  }
  const wire = got.xds_config?.value;
  const gotHex = wire == null ? null : Buffer.from(wire).toString('hex');
  if (gotHex !== want.wire) fail(`${want.name} wire ${JSON.stringify(gotHex)}`);
  if (want.wire !== null && got.xds_config.type_url !== want.type_url) {
    fail(`${want.name} any type ${JSON.stringify(got.xds_config.type_url)}`);
  }
}

// exclude_resource_contents keeps type/name/version/status but removes wire.
const excludedClient = excludedResponse.config[0];
if (excludedClient.generic_xds_configs.length !== 3) {
  fail(`excluded config count ${excludedClient.generic_xds_configs.length}`);
}
for (const want of expected) {
  const got = excludedClient.generic_xds_configs.find(
    (entry) => entry.type_url === want.type_url && entry.name === want.name,
  );
  if (!got) fail(`excluded missing ${want.type_url} ${want.name}`);
  if ((got.version_info ?? '') !== want.version_info) {
    fail(`excluded ${want.name} version ${JSON.stringify(got.version_info)}`);
  }
  if (got.client_status !== want.client_status) {
    fail(`excluded ${want.name} status ${JSON.stringify(got.client_status)}`);
  }
  if (got.xds_config != null) fail(`excluded ${want.name} kept xds_config`);
}

console.log(
  `CSDS_RESULT {"status":"passed","configs":${client.generic_xds_configs.length},"excluded":${excludedClient.generic_xds_configs.length},"node":${JSON.stringify(client.node.id)},"scope":${JSON.stringify(client.client_scope)}}`,
);
