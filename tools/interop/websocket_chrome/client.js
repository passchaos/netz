'use strict';

const puppeteer = require('puppeteer-core');

const [portText, scheme = 'ws'] = process.argv.slice(2);
const port = Number(portText);
if (!Number.isInteger(port) || port < 1 || port > 65535 ||
    !['ws', 'wss'].includes(scheme)) {
  throw new Error('usage: client.js PORT [ws|wss]');
}

async function expectOriginRejection({port, scheme}) {
  const socket = new WebSocket(
    `${scheme}://localhost:${port}/browser?case=rejected-origin`,
    ['netz.chrome.v1'],
  );
  return await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('rejected-origin probe timed out')),
      10_000,
    );
    socket.addEventListener('open', () => {
      clearTimeout(timer);
      socket.close();
      reject(new Error('disallowed Origin unexpectedly upgraded'));
    }, {once: true});
    socket.addEventListener('error', () => {}, {once: true});
    socket.addEventListener('close', event => {
      clearTimeout(timer);
      if (event.code !== 1006) {
        reject(new Error(`unexpected rejected-origin close code: ${event.code}`));
        return;
      }
      resolve('rejected-origin');
    }, {once: true});
  });
}

async function runBrowserProbe({port, scheme}) {
  const timeoutMs = 10_000;
  const expectedBinary = new TextEncoder().encode('netz binary');
  const compressedRequest = 'chrome compressed '.repeat(128);
  const compressedResponse = 'netz compressed '.repeat(128);
  function withTimeout(promise, label) {
    let timer;
    return Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(label + ' timed out')), timeoutMs);
      }),
    ]).finally(() => clearTimeout(timer));
  }
  function nextEvent(target, type, label) {
    return withTimeout(new Promise((resolve, reject) => {
      target.addEventListener(type, resolve, {once: true});
      target.addEventListener('error', () => reject(new Error(label + ' failed')), {once: true});
    }), label);
  }

  const socket = new WebSocket(
    `${scheme}://localhost:${port}/browser?case=interop`,
    ['netz.chrome.v1', 'unused.v1'],
  );
  socket.binaryType = 'arraybuffer';
  await nextEvent(socket, 'open', 'WebSocket open');
  if (socket.protocol !== 'netz.chrome.v1') {
    throw new Error(`unexpected subprotocol: ${JSON.stringify(socket.protocol)}`);
  }
  if (!socket.extensions.includes('permessage-deflate')) {
    throw new Error(`missing permessage-deflate: ${JSON.stringify(socket.extensions)}`);
  }

  const textEvent = nextEvent(socket, 'message', 'text response');
  socket.send('chrome text');
  const text = await textEvent;
  if (text.data !== 'netz text') {
    throw new Error(`unexpected text response: ${JSON.stringify(text.data)}`);
  }

  const binaryEvent = nextEvent(socket, 'message', 'binary response');
  socket.send(new TextEncoder().encode('chrome binary'));
  const binary = new Uint8Array((await binaryEvent).data);
  if (binary.length !== expectedBinary.length ||
      !binary.every((byte, index) => byte === expectedBinary[index])) {
    throw new Error('unexpected binary response');
  }

  const compressedEvent = nextEvent(socket, 'message', 'compressed response');
  socket.send(compressedRequest);
  const compressed = await compressedEvent;
  if (compressed.data !== compressedResponse) {
    throw new Error('unexpected compressed response');
  }

  const closeEvent = nextEvent(socket, 'close', 'WebSocket close');
  const close = await closeEvent;
  if (close.code !== 1001 || close.reason !== 'netz browser done' || !close.wasClean) {
    throw new Error(
      `unexpected close: code=${close.code} reason=${JSON.stringify(close.reason)} ` +
      `clean=${close.wasClean}`,
    );
  }
  return `Chrome WebSocket interop passed: scheme=${scheme} rejected-origin accepted-origin subprotocol compressed-text binary automatic-pong close=1001/netz-browser-done`;
}

(async () => {
  const chromeArgs = [
    '--no-sandbox',
    '--disable-background-networking',
    '--disable-component-update',
    '--disable-default-apps',
    '--disable-sync',
    '--metrics-recording-only',
    '--no-first-run',
  ];
  if (process.env.CERTIFICATE_SPKI_SHA256) {
    chromeArgs.push(
      '--ignore-certificate-errors-spki-list=' +
      process.env.CERTIFICATE_SPKI_SHA256,
    );
  }
  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME || '/usr/bin/google-chrome',
    headless: true,
    args: chromeArgs,
  });
  try {
    const page = await browser.newPage();
    await page.goto('http://127.0.0.1:' + process.env.ORIGIN_PORT + '/', {
      waitUntil: 'load',
    });
    await page.evaluate(expectOriginRejection, {port, scheme});
    await page.goto('http://localhost:' + process.env.ORIGIN_PORT + '/', {
      waitUntil: 'load',
    });
    console.log(await page.evaluate(runBrowserProbe, {port, scheme}));
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(error);
  process.exit(1);
});
