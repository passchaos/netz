'use strict';
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const path = require('node:path');
const modules = path.resolve(__dirname, '../grpc_locality/node_modules');
const grpc = require(path.join(modules, '@grpc/grpc-js'));
const loader = require(path.join(modules, '@grpc/proto-loader'));

function startServer(binary) {
  const child = spawn(binary, [], {stdio: ['ignore', 'pipe', 'pipe']});
  let output = '';
  let settled = false;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error('Channelz server did not start')), 20000);
    function finish(error, port) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        child.kill();
        return reject(error);
      }
      resolve({child, port});
    }
    const consume = data => {
      output += data;
      const match = output.match(/CHANNELZ_PORT (\d+)/);
      if (match) finish(null, Number(match[1]));
    };
    child.stdout.on('data', consume);
    child.stderr.on('data', consume);
    child.on('error', error => finish(error));
    child.on('exit', code => finish(new Error(`Channelz server exited ${code}: ${output}`)));
  });
}

function unary(client, method, request) {
  return new Promise((resolve, reject) => {
    client[method](request, (error, response) => error ? reject(error) : resolve(response));
  });
}

async function main() {
  const binary = process.argv[2];
  assert(binary, 'native Channelz server binary is required');
  const {child, port} = await startServer(binary);
  try {
    const definition = loader.loadSync(path.join(modules, '@grpc/grpc-js/proto/channelz.proto'), {
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
      includeDirs: [modules, path.join(modules, 'protobufjs'), path.join(modules, '@grpc/grpc-js/proto')],
    });
    const pkg = grpc.loadPackageDefinition(definition).grpc.channelz.v1;
    const client = new pkg.Channelz(`127.0.0.1:${port}`, grpc.credentials.createInsecure());
    try {
      const top = await unary(client, 'getTopChannels', {start_channel_id: 0, max_results: 0});
      assert.equal(top.channel.length, 1);
      const channel = top.channel[0];
      assert.equal(channel.ref.channel_id, '1');
      assert.equal(channel.ref.name, 'frontend');
      assert.equal(channel.data.state.state, 'READY');
      assert.equal(channel.data.target, 'dns:///frontend.example');
      assert.equal(channel.data.calls_started, '2');
      assert.equal(channel.data.calls_succeeded, '1');
      assert.equal(channel.data.calls_failed, '0');
      assert(channel.data.last_call_started_timestamp);
      assert.equal(channel.data.trace.num_events_logged, '2');
      assert.equal(channel.data.trace.events.length, 2);
      assert.equal(channel.data.trace.events[0].description, 'created');
      assert.equal(channel.data.trace.events[0].severity, 'CT_INFO');
      assert(channel.data.trace.creation_timestamp);
      assert.equal(channel.subchannel_ref.length, 1);
      assert.equal(channel.subchannel_ref[0].subchannel_id, '1');
      assert.equal(channel.subchannel_ref[0].name, 'backend-child');

      const servers = await unary(client, 'getServers', {start_server_id: 0, max_results: 0});
      assert.equal(servers.server.length, 1);
      const server = servers.server[0];
      assert.equal(server.ref.server_id, '1');
      assert.equal(server.ref.name, 'listener');
      assert.equal(server.data.calls_started, '3');
      assert.equal(server.data.calls_succeeded, '2');
      assert.equal(server.data.calls_failed, '1');
      assert.equal(server.data.trace.events[0].description, 'listening');
      assert.equal(server.data.trace.events[0].severity, 'CT_WARNING');
      assert.equal(server.listen_socket.length, 1);
      assert.equal(server.listen_socket[0].socket_id, '1');
      assert.equal(server.listen_socket[0].name, 'listen');

      const singleServer = await unary(client, 'getServer', {server_id: 1});
      assert.equal(singleServer.server.ref.server_id, '1');
      assert.equal(singleServer.server.ref.name, 'listener');

      const singleChannel = await unary(client, 'getChannel', {channel_id: 1});
      assert.equal(singleChannel.channel.ref.channel_id, '1');
      assert.equal(singleChannel.channel.subchannel_ref[0].name, 'backend-child');

      const subchannel = await unary(client, 'getSubchannel', {subchannel_id: 1});
      assert.equal(subchannel.subchannel.ref.subchannel_id, '1');
      assert.equal(subchannel.subchannel.ref.name, 'backend-child');
      assert.equal(subchannel.subchannel.data.state.state, 'READY');
      assert.equal(subchannel.subchannel.data.target, 'dns:///backend.example');
      assert.equal(subchannel.subchannel.data.calls_started, '1');
      assert.equal(subchannel.subchannel.data.calls_succeeded, '1');
      assert.equal(subchannel.subchannel.data.trace.events[0].description, 'created');

      const sockets = await unary(client, 'getServerSockets', {
        server_id: 1, start_socket_id: 0, max_results: 0,
      });
      assert.equal(sockets.socket_ref.length, 1);
      assert.equal(sockets.socket_ref[0].socket_id, '1');
      assert.equal(sockets.socket_ref[0].name, 'listen');
      assert.equal(sockets.end, true);

      const socket = await unary(client, 'getSocket', {socket_id: 1, summary: false});
      assert.equal(socket.socket.ref.socket_id, '1');
      assert.equal(socket.socket.ref.name, 'listen');
      assert.equal(socket.socket.data.streams_started, '1');
      assert.equal(socket.socket.data.streams_succeeded, '1');
      assert.equal(socket.socket.data.messages_sent, '2');
      assert.equal(socket.socket.data.messages_received, '3');
      assert.deepEqual([...socket.socket.local.tcpip_address.ip_address], [127, 0, 0, 1]);
      assert.equal(Number(socket.socket.local.tcpip_address.port), port);

      async function expectNotFound(method, request) {
        try {
          await unary(client, method, request);
          assert.fail(`${method} should return NOT_FOUND`);
        } catch (error) {
          assert.equal(error.code, grpc.status.NOT_FOUND);
        }
      }
      await expectNotFound('getChannel', {channel_id: 999});
      await expectNotFound('getSubchannel', {subchannel_id: 999});
      await expectNotFound('getSocket', {socket_id: 999});

      process.stdout.write(JSON.stringify({
        status: 'passed',
        port,
        channelz_schema: 'grpc/grpc-js/proto/channelz.proto',
        grpc_js: require(path.join(modules, '@grpc/grpc-js/package.json')).version,
        proto_loader: require(path.join(modules, '@grpc/proto-loader/package.json')).version,
        protobufjs: require(path.join(modules, 'protobufjs/package.json')).version,
      }) + '\n');
    } finally {
      client.close();
    }
  } finally {
    child.kill();
  }
}

main().catch(error => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exit(1);
});
