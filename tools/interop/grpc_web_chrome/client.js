'use strict';
const puppeteer = require('puppeteer-core');
const esbuild = require('esbuild');
const path = require('node:path');
const http2 = require('node:http2');
const fs = require('node:fs');
const [endpoint, origin, work] = process.argv.slice(2);

function acknowledgeStream() {
  // Use a dedicated control session so the fixture keeps a single frame
  // reader on the streaming connection while waiting for browser delivery.
  return new Promise((resolve, reject) => {
    const session = http2.connect(endpoint, {ca: fs.readFileSync(process.env.GRPC_WEB_TEST_CERTIFICATE)});
    const request = session.request({':method': 'POST', ':path': '/demo.Echo/Ack',
      'content-type': 'application/grpc-web', authorization: 'Bearer grpc-web-test'});
    let body = Buffer.alloc(0), status;
    session.on('error', reject);
    request.on('response', headers => { status = headers[':status']; });
    request.on('data', bytes => { body = Buffer.concat([body, bytes]); });
    request.on('error', error => { session.destroy(); reject(error); });
    request.on('end', () => {
      session.close();
      if (status !== 200 || !body.subarray(5, 8).equals(Buffer.from('ack'))) reject(new Error('HTTP/2 delivery acknowledgement failed'));
      else resolve();
    });
    request.setTimeout(10000, () => { request.destroy(new Error('ack timeout')); session.destroy(); });
    request.end(Buffer.from([0, 0, 0, 0, 3, 97, 99, 107]));
  });
}
(async () => {
  const bundle = path.join(work, 'browser.js');
  await esbuild.build({entryPoints: [path.join(__dirname, 'browser.js')], bundle: true, platform: 'browser', outfile: bundle});
  const args = ['--no-sandbox', '--no-proxy-server', '--disable-dev-shm-usage'];
  if (process.env.CERTIFICATE_SPKI_SHA256) args.push(`--ignore-certificate-errors-spki-list=${process.env.CERTIFICATE_SPKI_SHA256}`);
  const browser = await puppeteer.launch({executablePath: process.env.CHROME || '/usr/bin/chromium', headless: true, args});
  try {
    const page = await browser.newPage();
    const protocols = new Set();
    const network = await page.createCDPSession();
    await network.send('Network.enable');
    network.on('Network.responseReceived', event => {
      if (event.response.url.startsWith(endpoint + '/')) protocols.add(event.response.protocol);
    });
    if (process.env.EXPECTED_HTTP_PROTOCOL === 'h2') await page.exposeFunction('acknowledgeStream', acknowledgeStream);
    page.on('console', message => { if (message.type() === 'error') process.stderr.write(`browser: ${message.text()}\n`); });
    await page.goto(origin.replace('localhost', '127.0.0.1'));
    const rejected = await page.evaluate(async target => {
      try { await fetch(`${target}/demo.Echo/Unary`, {method: 'POST', headers: {'content-type': 'application/grpc-web'}, body: new Uint8Array([0,0,0,0,0])}); return false; }
      catch { return true; }
    }, endpoint);
    if (!rejected) throw new Error('disallowed Origin unexpectedly readable');
    await page.goto(origin);
    await page.addScriptTag({path: bundle});
    const result = await page.evaluate(target => window.runGrpcWebProbe(target), endpoint);
    const expected = process.env.EXPECTED_HTTP_PROTOCOL || 'http/1.1';
    if (protocols.size !== 1 || !protocols.has(expected)) throw new Error(`unexpected HTTP protocols: ${[...protocols]}`);
    process.stdout.write(`${JSON.stringify({...result, browser: await browser.version(), rejectedOrigin: true, protocols: [...protocols]})}\n`);
  } finally { await browser.close(); }
})().catch(error => { process.stderr.write(`${error.stack || error}\n`); process.exitCode = 1; });
