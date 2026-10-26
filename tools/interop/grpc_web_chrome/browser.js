const grpc = require('grpc-web');
class Message { constructor(bytes) { this.bytes = bytes; } }
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const metadata = {authorization: 'Bearer grpc-web-test'};
function descriptor(method, streaming = false) {
  return new grpc.MethodDescriptor(`/demo.Echo/${method}`,
    streaming ? grpc.MethodType.SERVER_STREAMING : grpc.MethodType.UNARY,
    Message, Message, message => message.bytes, bytes => new Message(bytes));
}
function unary(client, endpoint, method, text) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`unary timeout: ${method}`)), 10000);
    const call = client.rpcCall(`${endpoint}/demo.Echo/${method}`,
      new Message(encoder.encode(text)), metadata, descriptor(method), (error, response) => {
        clearTimeout(timer);
        if (error) reject(error); else resolve(decoder.decode(response.bytes));
      });
    if (method !== 'Denied') call.on('metadata', fields => {
      if (fields['x-initial'] !== 'visible') reject(new Error('custom CORS metadata not visible'));
    });
  });
}
window.runGrpcWebProbe = async endpoint => {
  const binary = new grpc.GrpcWebClientBase({format: 'binary', withCredentials: true});
  const text = new grpc.GrpcWebClientBase({format: 'text', withCredentials: true});
  if (await unary(binary, endpoint, 'Unary', 'binary') !== 'binary') throw new Error('binary mismatch');
  if (await unary(text, endpoint, 'Unary', 'text') !== 'text') throw new Error('text mismatch');
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('stream timeout')), 10000);
    let count = 0, statusSeen = false;
    const stream = text.serverStreaming(`${endpoint}/demo.Echo/Stream`,
      new Message(encoder.encode('stream')), metadata, descriptor('Stream', true));
    stream.on('data', message => {
      count += 1;
      if (count === 1) {
        if (message.bytes.length !== 32768 || message.bytes.some(byte => byte !== 97)) return reject(new Error('first stream message mismatch'));
        // The server waits for this separate RPC before sending message two
        // or terminal status, proving official SDK delivery before END_STREAM.
        unary(binary, endpoint, 'Ack', 'ack').catch(reject);
      } else if (count === 2) {
        if (decoder.decode(message.bytes) !== 'second') reject(new Error('second stream message mismatch'));
      } else reject(new Error('extra stream message'));
    });
    stream.on('error', reject);
    stream.on('status', status => { if (status.code !== 0) reject(new Error(`stream status ${status.code}`)); statusSeen = true; });
    stream.on('end', () => { clearTimeout(timer); if (count !== 2 || !statusSeen) reject(new Error('incomplete stream')); else resolve(); });
  });
  try { await unary(binary, endpoint, 'Denied', 'denied'); throw new Error('missing RPC error'); }
  catch (error) { if (error.code !== grpc.StatusCode.UNAUTHENTICATED || error.message !== 'bad token') throw error; }
  if (await unary(binary, endpoint, 'Finish', 'finish') !== 'finish') throw new Error('finish mismatch');
  return {client: 'grpc-web-2.1.1', unary: ['binary', 'text'], stream: 'incremental-text', error: 'UNAUTHENTICATED'};
};
