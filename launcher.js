#!/usr/bin/env node
/**
 * Electron Interceptor Launcher for Burp Suite (CLI only).
 * Spawns Electron with --inspect-brk, injects prepend-electron.js via CDP
 * so Chromium uses proxy + Burp CA.
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const OVERRIDES_DIR = path.join(__dirname, 'overrides');
const PREPEND_ELECTRON_PATH = path.join(OVERRIDES_DIR, 'js', 'prepend-electron.js');

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    proxyHost: '127.0.0.1',
    proxyPort: '8080',
    certPath: '',
    extraCerts: [],
    fetchFallback: true,
  };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--app' && args[i + 1]) {
      opts.appPath = args[++i].replace(/\/+$/, '');
    } else if (args[i] === '--proxy' && args[i + 1]) {
      const v = args[++i];
      const [h, p] = v.split(':');
      if (h) opts.proxyHost = h;
      if (p) opts.proxyPort = p;
    } else if (args[i] === '--cert' && args[i + 1]) {
      opts.certPath = args[++i];
    } else if (args[i] === '--extra-cert' && args[i + 1]) {
      opts.extraCerts.push(args[++i]);
    } else if (args[i] === '--no-bypass') {
      opts.noBypass = true;
    } else if (args[i] === '--no-fetch-fallback') {
      opts.fetchFallback = false;
    }
  }
  return opts;
}

function canAccess(p) {
  try {
    fs.accessSync(p);
    return true;
  } catch {
    return false;
  }
}

function isAppBundle(appPath) {
  return process.platform === 'darwin' && appPath.endsWith('.app');
}

async function shouldBeAppBundle(appPath) {
  if (process.platform !== 'darwin') return false;
  if (canAccess(appPath)) return false;
  return canAccess(appPath + '.app');
}

function findExecutableInApp(appPath) {
  const plistPath = path.join(appPath, 'Contents', 'Info.plist');
  const macOsDir = path.join(appPath, 'Contents', 'MacOS');
  if (!canAccess(macOsDir)) throw new Error(`Not a valid .app bundle: ${appPath}`);
  if (canAccess(plistPath)) {
    const content = fs.readFileSync(plistPath, 'utf8');
    const match = content.match(/<key>CFBundleExecutable<\/key>\s*<string>([^<]+)<\/string>/);
    if (match) {
      const exe = path.join(macOsDir, match[1].trim());
      if (canAccess(exe)) return exe;
    }
  }
  const appName = path.basename(appPath, '.app');
  const exe = path.join(macOsDir, appName);
  if (canAccess(exe)) return exe;
  const files = fs.readdirSync(macOsDir);
  const first = files.find((f) => {
    try {
      return fs.statSync(path.join(macOsDir, f)).isFile();
    } catch {
      return false;
    }
  });
  if (first) return path.join(macOsDir, first);
  throw new Error(`Could not find executable in app bundle: ${appPath}`);
}

async function resolveCommand(appPath) {
  if (isAppBundle(appPath)) return findExecutableInApp(appPath);
  if (await shouldBeAppBundle(appPath)) return findExecutableInApp(appPath + '.app');
  return appPath;
}

function getPort(port) {
  try {
    const portfinder = require('portfinder');
    portfinder.basePort = port;
    return portfinder.getPortPromise();
  } catch {
    return Promise.resolve(port);
  }
}

function extractPemCerts(fileContent) {
  const certs = [];
  const re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let m;
  while ((m = re.exec(fileContent)) !== null) certs.push(m[0]);
  return certs;
}

function computeSpki(certPem) {
  try {
    if (typeof crypto.X509Certificate === 'function') {
      const x509 = new crypto.X509Certificate(certPem);
      const spkiDer = x509.publicKey.export({ type: 'spki', format: 'der' });
      return crypto.createHash('sha256').update(spkiDer).digest('base64');
    } else {
      const key = crypto.createPublicKey({ key: certPem, format: 'pem' });
      const spkiDer = key.export({ type: 'spki', format: 'der' });
      return crypto.createHash('sha256').update(spkiDer).digest('base64');
    }
  } catch (e) {
    console.warn('Could not compute SPKI fingerprint:', e.message);
    return '';
  }
}

function loadCertParams(certPath, extraCertPaths) {
  const allPems = [];

  if (certPath && canAccess(certPath)) {
    const content = fs.readFileSync(path.resolve(certPath), 'utf8');
    allPems.push(...extractPemCerts(content));
  }
  for (const p of (extraCertPaths || [])) {
    if (canAccess(p)) {
      const content = fs.readFileSync(path.resolve(p), 'utf8');
      allPems.push(...extractPemCerts(content));
    }
  }

  if (allPems.length === 0) {
    return { certDataList: [], spkiFingerprint: '', combinedCertPath: '' };
  }

  const certDataList = allPems.map((pem) => pem.replace(/\r\n|\r|\n/g, '\\n'));
  const spkiList = allPems.map(computeSpki).filter(Boolean);
  const spkiFingerprint = spkiList.join(',');

  let combinedCertPath = certPath ? path.resolve(certPath) : '';
  if (extraCertPaths && extraCertPaths.length > 0) {
    combinedCertPath = path.join(__dirname, '.combined-ca.pem');
    fs.writeFileSync(combinedCertPath, allPems.join('\n') + '\n');
    console.log('Combined CA file:', combinedCertPath, `(${allPems.length} certs)`);
  }

  return { certDataList, spkiFingerprint, combinedCertPath };
}

async function runWithCDP(options) {
  const { cmd, proxyUrl, certPath, extraCerts, debugPort, noBypass, fetchFallback } = options;
  const certParams = loadCertParams(certPath, extraCerts);
  const proxyBypassList = noBypass ? '' : '<-loopback>';

  const env = {
    ...process.env,
    HTTP_PROXY: proxyUrl,
    HTTPS_PROXY: proxyUrl,
    http_proxy: proxyUrl,
    https_proxy: proxyUrl,
    GLOBAL_AGENT_HTTP_PROXY: proxyUrl,
    GLOBAL_AGENT_HTTPS_PROXY: proxyUrl,
    BURP_INTERCEPT_ACTIVE: 'true',
    HTTP_TOOLKIT_ACTIVE: 'true',
    NODE_OPTIONS: '',
  };
  if (certParams.combinedCertPath) {
    env.NODE_EXTRA_CA_CERTS = certParams.combinedCertPath;
  } else if (certPath && canAccess(certPath)) {
    env.NODE_EXTRA_CA_CERTS = path.resolve(certPath);
  }

  spawn(cmd, [`--inspect-brk=127.0.0.1:${debugPort}`], { stdio: 'inherit', env });

  let CDP;
  try {
    CDP = require('chrome-remote-interface');
  } catch (e) {
    throw new Error('Install dependencies: npm install chrome-remote-interface portfinder');
  }

  let debugClient;
  let retries = 15;
  const delay = (ms) => new Promise((r) => setTimeout(r, ms));

  while (retries >= 0) {
    try {
      debugClient = await CDP({ host: '127.0.0.1', port: debugPort });
      break;
    } catch (err) {
      if (err.code !== 'ECONNREFUSED' && err.code !== 'ECONNRESET') throw err;
      retries--;
      if (retries < 0) throw new Error('Could not connect to Electron debugger');
      await delay(400);
    }
  }

  await debugClient.Runtime.enable();
  await debugClient.Debugger.enable();

  const callFramePromise = new Promise((resolve) => {
    debugClient.Debugger.paused((stack) => {
      resolve(stack.callFrames[0].callFrameId);
    });
  });

  await debugClient.Runtime.runIfWaitingForDebugger();
  const callFrameId = await callFramePromise;

  const expression = `(() => {
    const __interceptRequire = (function getCompatRequire() {
      if (typeof globalThis.require === 'function') return globalThis.require;
      try {
        const mod = process.getBuiltinModule && process.getBuiltinModule('module');
        if (mod && typeof mod.createRequire === 'function') {
          return mod.createRequire(process.cwd() + '/__electron_interceptor__.cjs');
        }
      } catch (e) {
        process.stderr.write('[ELECTRON-INTERCEPT] createRequire bootstrap failed: ' + e.message + '\\n');
      }
      return null;
    })();
    if (!__interceptRequire) {
      throw new Error('No compatible require() available in this ESM frame');
    }
    return __interceptRequire(${JSON.stringify(PREPEND_ELECTRON_PATH)})({
      certDataList: ${JSON.stringify(certParams.certDataList)},
      spkiFingerprint: ${JSON.stringify(certParams.spkiFingerprint)},
      proxyBypassList: ${JSON.stringify(proxyBypassList)},
      enableFetchFallback: ${JSON.stringify(fetchFallback !== false)}
    });
  })()`;

  const result = await debugClient.Debugger.evaluateOnCallFrame({ callFrameId, expression });
  if (result.exceptionDetails) {
    throw new Error('Injection failed: ' + JSON.stringify(result.exceptionDetails));
  }

  console.log('Injection OK, resuming app...');
  await debugClient.Debugger.resume();
  debugClient.close();
}

async function main() {
  const opts = parseArgs();
  if (!opts.appPath) {
    console.error('Usage: node launcher.js --app /path/to/Electron.app [--proxy 127.0.0.1:8080] [--cert /path/to/cacert.pem] [--extra-cert /path/to/another-ca.pem] [--no-bypass] [--no-fetch-fallback]');
    process.exit(1);
  }

  if (!canAccess(PREPEND_ELECTRON_PATH)) {
    console.error('Missing overrides: expected', PREPEND_ELECTRON_PATH);
    process.exit(1);
  }

  const proxyUrl = `http://${opts.proxyHost}:${opts.proxyPort}`;
  const debugPort = await getPort(9229);
  const cmd = await resolveCommand(opts.appPath);

  console.log('Launching Electron through Burp proxy:', proxyUrl);
  console.log('Command:', cmd);
  console.log('Debug port:', debugPort);

  try {
    await runWithCDP({
      cmd,
      proxyUrl,
      certPath: opts.certPath,
      extraCerts: opts.extraCerts,
      debugPort,
      noBypass: opts.noBypass || false,
      fetchFallback: opts.fetchFallback,
    });
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
}

main();