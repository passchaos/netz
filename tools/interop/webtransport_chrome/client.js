'use strict';

const puppeteer = require('puppeteer-core');
const crypto = require('node:crypto');
const fs = require('node:fs');

const [portText, certificateHash] = process.argv.slice(2);
const port = Number(portText);
const browserName = process.env.BROWSER_NAME || 'Chrome';
const browserProduct = process.env.BROWSER_PRODUCT || 'chrome';
const browserExecutable = process.env.BROWSER_EXECUTABLE ||
    process.env.CHROME || '/usr/bin/google-chrome';
if (!Number.isInteger(port) || port < 1 || port > 65535 ||
    !/^[0-9a-f]{64}$/i.test(certificateHash || '')) {
  throw new Error('usage: client.js PORT CERTIFICATE_SHA256_HEX');
}

async function sha256File(path) {
  const hash = crypto.createHash('sha256');
  await new Promise((resolve, reject) => {
    const input = fs.createReadStream(path);
    input.on('data', chunk => hash.update(chunk));
    input.on('error', reject);
    input.on('end', resolve);
  });
  return hash.digest('hex');
}

async function runBrowserProbe({
  port, certificateHash, browserName, testStreamCancellation, originOnly,
  rejectOnly, browserVersion, browserLauncherSha256, browserProcessSha256,
}) {
  const timeoutMs = 10_000;
  const browserUa = navigator.userAgent;
  const browserIdentity =
      `browser_version=${browserVersion} ` +
      `browser_launcher_sha256=${browserLauncherSha256} ` +
      `browser_process_sha256=${browserProcessSha256} ` +
      `browser_ua=${browserUa}`;
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();
  async function withTimeout(promise, label) {
    let timer;
    try {
      return await Promise.race([
        promise,
        new Promise((_, reject) => {
          timer = setTimeout(
            () => reject(new Error(label + ' timed out')),
            timeoutMs,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }
  async function readExact(reader, expected, label) {
    let actual = '';
    while (actual.length < expected.length) {
      const chunk = await withTimeout(reader.read(), label);
      if (chunk.done) break;
      actual += textDecoder.decode(chunk.value, {stream: true});
    }
    if (actual !== expected) {
      throw new Error(`unexpected ${label}: ${JSON.stringify(actual)}`);
    }
  }
  async function readDatagram(reader, expected, label) {
    const datagram = await withTimeout(reader.read(), label);
    if (datagram.done || textDecoder.decode(datagram.value) !== expected) {
      throw new Error(`unexpected ${label}`);
    }
  }

  const hash = Uint8Array.from(
    certificateHash.match(/../g),
    byte => Number.parseInt(byte, 16),
  );
  const transport = new WebTransport(`https://127.0.0.1:${port}/interop`, {
    serverCertificateHashes: [{algorithm: 'sha-256', value: hash.buffer}],
  });
  if (rejectOnly) {
    let rejected = false;
    try {
      await withTimeout(transport.ready, 'rejected WebTransport ready');
    } catch (_) {
      rejected = true;
    }
    if (!rejected) {
      transport.close();
      throw new Error('disallowed Origin unexpectedly accepted');
    }
    return `${browserName} WebTransport Origin policy passed: rejected=true ${browserIdentity}`;
  }
  await withTimeout(transport.ready, 'WebTransport ready');
  if (originOnly) {
    transport.close({closeCode: 0, reason: 'origin verified'});
    return `${browserName} WebTransport Origin policy passed: exact-origin=true ${browserIdentity}`;
  }
  const maxDatagramSize = transport.datagrams.maxDatagramSize;
  if (!Number.isInteger(maxDatagramSize) || maxDatagramSize <= 0) {
    throw new Error(`invalid maxDatagramSize: ${maxDatagramSize}`);
  }

  const datagramWriter = transport.datagrams.writable.getWriter();
  const datagramReader = transport.datagrams.readable.getReader();
  await withTimeout(
    datagramWriter.write(textEncoder.encode('wtransport datagram')),
    'DATAGRAM send',
  );
  await readDatagram(datagramReader, 'netz datagram', 'DATAGRAM response');

  const bidi = await withTimeout(
    transport.createBidirectionalStream(),
    'bidirectional stream open',
  );
  const bidiWriter = bidi.writable.getWriter();
  await bidiWriter.write(textEncoder.encode('wtransport bidi'));
  await bidiWriter.close();
  await readExact(bidi.readable.getReader(), 'netz bidi', 'bidirectional response');

  const uni = await withTimeout(
    transport.createUnidirectionalStream(),
    'unidirectional stream open',
  );
  const uniWriter = uni.getWriter();
  await uniWriter.write(textEncoder.encode('wtransport uni'));
  await uniWriter.close();
  const incomingUniReader = transport.incomingUnidirectionalStreams.getReader();
  const incomingUni = (await withTimeout(
    incomingUniReader.read(),
    'server unidirectional stream',
  )).value;
  await readExact(incomingUni.getReader(), 'netz uni', 'unidirectional response');

  if (!testStreamCancellation) {
    const reuse = await withTimeout(
      transport.createBidirectionalStream(),
      'reuse stream open',
    );
    const reuseWriter = reuse.writable.getWriter();
    await reuseWriter.write(textEncoder.encode('after cancel'));
    await reuseWriter.close();
    await readExact(reuse.readable.getReader(), 'session reused', 'reuse response');
    await datagramWriter.write(textEncoder.encode('close ready'));
    const closeInfo = await withTimeout(transport.closed, 'session close');
    if (closeInfo.closeCode !== 77 || closeInfo.reason !== 'netz done') {
      throw new Error(
        `unexpected session close: code=${closeInfo.closeCode} ` +
        `reason=${JSON.stringify(closeInfo.reason)}`,
      );
    }
    return `${browserName} WebTransport interop passed: CONNECT DATAGRAM max_datagram_size=${maxDatagramSize} bidi uni reuse=true drain-before-close=true close=77/netz-done ${browserIdentity}`;
  }

  const reset = await withTimeout(
    transport.createUnidirectionalStream(),
    'reset stream open',
  );
  const resetWriter = reset.getWriter();
  await resetWriter.write(textEncoder.encode('wtransport reset'));
  await readDatagram(datagramReader, 'reset ready', 'reset-ready DATAGRAM');
  await resetWriter.abort(new WebTransportError({streamErrorCode: 71}));

  const stopStream = (await withTimeout(
    incomingUniReader.read(),
    'STOP_SENDING stream',
  )).value;
  const stopReader = stopStream.getReader();
  await readExact(stopReader, 'netz stop', 'STOP_SENDING payload');
  const reuse = await withTimeout(
    transport.createBidirectionalStream(),
    'reuse stream open',
  );
  const reuseWriter = reuse.writable.getWriter();
  await reuseWriter.write(textEncoder.encode('after cancel'));
  await reuseWriter.close();
  await stopReader.cancel(new WebTransportError({streamErrorCode: 72}));
  await readDatagram(datagramReader, 'cancel done', 'cancel-done DATAGRAM');
  await readExact(reuse.readable.getReader(), 'session reused', 'reuse response');

  await datagramWriter.write(textEncoder.encode('close ready'));
  // The netz fixture sends WT_DRAIN_SESSION immediately before CLOSE. The
  // browser has no drain event, so the exact following close metadata proves
  // The browser consumed the advisory capsule without losing stream framing.
  const closeInfo = await withTimeout(transport.closed, 'session close');
  if (closeInfo.closeCode !== 77 || closeInfo.reason !== 'netz done') {
    throw new Error(
      `unexpected session close: code=${closeInfo.closeCode} ` +
      `reason=${JSON.stringify(closeInfo.reason)}`,
    );
  }
  return `${browserName} WebTransport interop passed: CONNECT DATAGRAM max_datagram_size=${maxDatagramSize} bidi uni reset=71 stop=72 concurrent_sibling=true reuse=true drain-before-close=true close=77/netz-done ${browserIdentity}`;
}

(async () => {
  const firefox = browserProduct === 'firefox';
  const browser = await puppeteer.launch({
    browser: browserProduct,
    executablePath: browserExecutable,
    headless: true,
    args: firefox ? ['--no-remote'] : [
      '--no-sandbox',
      '--disable-background-networking',
      '--disable-component-update',
      '--disable-default-apps',
      '--disable-sync',
      '--metrics-recording-only',
      '--no-first-run',
    ],
    extraPrefsFirefox: firefox ? {
      'network.http.http3.enable': true,
      'network.http.http3.webtransport.enabled': true,
    } : undefined,
  });
  try {
    const browserProcess = browser.process();
    if (browserProcess === null) {
      throw new Error('Puppeteer did not expose the launched browser process');
    }
    const requestedExecutable = fs.realpathSync(browserExecutable);
    const launchedExecutable = fs.realpathSync(browserProcess.spawnfile);
    if (launchedExecutable !== requestedExecutable) {
      throw new Error(
        `unexpected launched browser executable: ${JSON.stringify(launchedExecutable)}`,
      );
    }
    const browserLauncherSha256 = await sha256File(launchedExecutable);
    const processImage = fs.realpathSync(`/proc/${browserProcess.pid}/exe`);
    const browserProcessSha256 = await sha256File(processImage);
    const browserVersion = await browser.version();
    const expectedVersionPrefix = firefox ? 'firefox/' : 'Chrome/';
    if (!browserVersion.startsWith(expectedVersionPrefix)) {
      throw new Error(
        `unexpected browser version identity: ${JSON.stringify(browserVersion)}`,
      );
    }
    const page = await browser.newPage();
    await page.goto('http://localhost:' + process.env.ORIGIN_PORT + '/', {
      waitUntil: 'load',
    });
    console.log(await page.evaluate(runBrowserProbe, {
      port,
      certificateHash,
      browserName,
      browserVersion,
      browserLauncherSha256,
      browserProcessSha256,
      testStreamCancellation: !firefox,
      originOnly: process.env.WEBTRANSPORT_ORIGIN_ONLY === '1',
      rejectOnly: process.env.WEBTRANSPORT_REJECT_ONLY === '1',
    }));
  } finally {
    await browser.close();
  }
})().catch(error => {
  console.error(error);
  process.exit(1);
});
