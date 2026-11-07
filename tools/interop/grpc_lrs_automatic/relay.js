'use strict';
const net = require('node:net');

// Stop new connections while preserving the established ADS TCP stream. A
// source-pinned automatic LRS owner must then see ConnectionRefused independently.
class Relay {
  constructor(upstreamPort, fail) {
    this.sockets = new Set();
    this.connections = 0;
    this.stopped = false;
    this.server = net.createServer(client => {
      this.connections++;
      const upstream = net.connect(upstreamPort, '127.0.0.1');
      for (const socket of [client, upstream]) {
        this.sockets.add(socket);
        socket.on('close', () => this.sockets.delete(socket));
        socket.on('error', error => {if (!socket.destroyed) fail(error); client.destroy(); upstream.destroy();});
      }
      client.pipe(upstream);
      upstream.pipe(client);
    });
    this.closed = new Promise(resolve => this.server.once('close', resolve));
    this.server.on('error', fail);
  }
  async listen() {
    await new Promise(resolve => this.server.listen(0, '127.0.0.1', resolve));
    return this.server.address().port;
  }
  stopListening() {
    if (this.stopped) return;
    this.stopped = true;
    this.server.close();
  }
  async close() {
    this.stopListening();
    for (const socket of this.sockets) socket.destroy();
    await this.closed;
  }
}
module.exports = {Relay};
