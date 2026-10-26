'use strict';
const puppeteer = require('puppeteer-core');
const esbuild = require('esbuild');
const path = require('node:path');
const [endpoint, origin, work] = process.argv.slice(2);
(async () => {
  const bundle = path.join(work, 'browser.js');
  await esbuild.build({entryPoints: [path.join(__dirname, 'browser.js')], bundle: true, platform: 'browser', outfile: bundle});
  const args = ['--no-sandbox', '--no-proxy-server', '--disable-dev-shm-usage'];
  if (process.env.CERTIFICATE_SPKI_SHA256) args.push(`--ignore-certificate-errors-spki-list=${process.env.CERTIFICATE_SPKI_SHA256}`);
  const browser = await puppeteer.launch({executablePath: process.env.CHROME || '/usr/bin/chromium', headless: true, args});
  try {
    const page = await browser.newPage();
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
    process.stdout.write(`${JSON.stringify({...result, browser: await browser.version(), rejectedOrigin: true})}\n`);
  } finally { await browser.close(); }
})().catch(error => { process.stderr.write(`${error.stack || error}\n`); process.exitCode = 1; });
