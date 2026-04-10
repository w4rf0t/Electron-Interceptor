#!/usr/bin/env node
'use strict';
/**
 * Generic Electron Interceptor — Launcher
 *
 * Usage:
 *   node launcher.js --app /path/to/App.app [options]
 *
 * Options:
 *   --app <path>          Path to Electron app (required)
 *   --cert <path>         Path to Burp CA PEM (default: ./cacert.pem)
 *   --proxy <host:port>   Burp proxy (default: 127.0.0.1:8080)
 *   --log-file <path>     Enable logging to file
 *   --channel-filter <list> IPC channel prefixes to log (comma-separated)
 *   --no-bypass           Route localhost through proxy too
 *   --debug-port <port>   Force specific debug port
 */

const { spawn }      = require('child_process');
const net            = require('net');
const path           = require('path');
const fs             = require('fs');
const crypto         = require('crypto');
const { injectViaCDP } = require('./core/cdp-injector');
const cfg            = require('./config');

// ─── Argument parsing ────────────────────────────────────────────────────────

function parseArgs() {
  const argv = process.argv.slice(2);
  const opts = {
    appPath:    '',
    certPath:   cfg.defaultCertPath,
    burpHost:   cfg.burpHost,
    burpPort:   cfg.burpPort,
    logFile:    '',
    channelFilter: cfg.channelFilter,
    noBypass:   false,
    debugPort:  0,
  };

  for (let i = 0; i < argv.length; i++) {
    switch (argv[i]) {
      case '--app':        opts.appPath   = argv[++i]; break;
      case '--cert':       opts.certPath  = argv[++i]; break;
      case '--log-file':   opts.logFile   = argv[++i]; break;
      case '--channel-filter': opts.channelFilter = argv[++i]; break;
      case '--no-bypass':  opts.noBypass  = true; break;
      case '--debug-port': opts.debugPort = parseInt(argv[++i], 10); break;
      case '--proxy':
        if (argv[i + 1]) {
          const v = argv[++i];
          const colon = v.lastIndexOf(':');
          if (colon > 0) {
            opts.burpHost = v.slice(0, colon);
            opts.burpPort = parseInt(v.slice(colon + 1), 10) || opts.burpPort;
          } else {
            opts.burpHost = v;
          }
        }
        break;
    }
  }

  if (!opts.appPath) opts.appPath = cfg.defaultAppPath;
  return opts;
}

// ─── File helpers ────────────────────────────────────────────────────────────

function canAccess(p) {
  try { fs.accessSync(p); return true; } catch { return false; }
}

function findExecutable(appPath) {
  appPath = appPath.replace(/\/+$/, '');

  // macOS .app bundle
  if (process.platform === 'darwin') {
    if (!appPath.endsWith('.app') && canAccess(appPath + '.app')) {
      appPath = appPath + '.app';
    }

    if (appPath.endsWith('.app')) {
      const macOsDir  = path.join(appPath, 'Contents', 'MacOS');
      const plistPath = path.join(appPath, 'Contents', 'Info.plist');

      if (!canAccess(macOsDir)) throw new Error(`Not a valid .app bundle: ${appPath}`);

      if (canAccess(plistPath)) {
        const plist = fs.readFileSync(plistPath, 'utf8');
        const m = plist.match(/<key>CFBundleExecutable<\/key>\s*<string>([^<]+)<\/string>/);
        if (m) {
          const exe = path.join(macOsDir, m[1].trim());
          if (canAccess(exe)) return exe;
        }
      }

      const appName = path.basename(appPath, '.app');
      const guess   = path.join(macOsDir, appName);
      if (canAccess(guess)) return guess;

      const files = fs.readdirSync(macOsDir);
      const first = files.find((f) => {
        try { return fs.statSync(path.join(macOsDir, f)).isFile(); } catch { return false; }
      });
      if (first) return path.join(macOsDir, first);

      throw new Error(`Could not locate executable inside ${appPath}`);
    }
  }

  // Direct binary path
  if (!canAccess(appPath)) throw new Error(`Executable not found: ${appPath}`);
  return appPath;
}

// ─── Certificate helpers ─────────────────────────────────────────────────────

function extractPemCerts(fileContent) {
  const re   = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  const certs = [];
  let m;
  while ((m = re.exec(fileContent)) !== null) certs.push(m[0]);
  return certs;
}

function computeSpkiFingerprint(certPem) {
  try {
    if (typeof crypto.X509Certificate === 'function') {
      const x509 = new crypto.X509Certificate(certPem);
      const der  = x509.publicKey.export({ type: 'spki', format: 'der' });
      return crypto.createHash('sha256').update(der).digest('base64');
    }
    const key = crypto.createPublicKey({ key: certPem, format: 'pem' });
    const der = key.export({ type: 'spki', format: 'der' });
    return crypto.createHash('sha256').update(der).digest('base64');
  } catch (e) {
    console.warn('[warn] Could not compute SPKI fingerprint:', e.message);
    return '';
  }
}

function loadBurpCert(certPath) {
  if (!certPath || !canAccess(certPath)) {
    console.warn('[warn] Burp cert not found at:', certPath);
    console.warn('[warn] TLS cert verification may fail');
    return { certDataList: [], spkiFingerprint: '', certPath: '' };
  }

  const content       = fs.readFileSync(certPath, 'utf8');
  const certs         = extractPemCerts(content);
  const certDataList  = certs.map((pem) => pem.replace(/\r\n|\r|\n/g, '\\n'));
  const spkis         = certs.map(computeSpkiFingerprint).filter(Boolean);

  console.log(`[cert] Loaded ${certs.length} cert(s) from ${certPath}`);
  return {
    certDataList,
    spkiFingerprint: spkis.join(','),
    certPath: path.resolve(certPath),
  };
}

// ─── Free port ───────────────────────────────────────────────────────────────

async function getFreePort(base) {
  try {
    const portfinder   = require('portfinder');
    portfinder.basePort = base;
    return await portfinder.getPortPromise();
  } catch {
    return base;
  }
}

// ─── Spawn Electron ──────────────────────────────────────────────────────────

function spawnElectron(exePath, debugPort, proxyServer, certInfo, noBypass) {
  const env = {
    ...process.env,
    HTTP_PROXY:              '',
    HTTPS_PROXY:             '',
    http_proxy:              '',
    https_proxy:             '',
    GLOBAL_AGENT_HTTP_PROXY: '',
    GLOBAL_AGENT_HTTPS_PROXY: '',
    BURP_INTERCEPT_ACTIVE:   'true',
    HTTP_TOOLKIT_ACTIVE:     'true',
    ...(certInfo.certPath ? { NODE_EXTRA_CA_CERTS: certInfo.certPath } : {}),
    NODE_OPTIONS: '',
  };

  const flags = [
    `--inspect-brk=127.0.0.1:${debugPort}`,
    ...(certInfo.spkiFingerprint
      ? [`--ignore-certificate-errors-spki-list=${certInfo.spkiFingerprint}`]
      : []),
    `--proxy-server=${proxyServer}`,
    ...(noBypass ? [] : [`--proxy-bypass-list=<-loopback>`]),
  ];

  console.log('[launch] Executable:', exePath);
  console.log('[launch] Debug port:', debugPort);
  console.log('[launch] Proxy:', proxyServer);
  console.log('[launch] Flags:', flags.join(' '));

  const child = spawn(exePath, flags, { stdio: 'inherit', env });
  child.on('error', (err) => {
    console.error('[launch] Failed to start app:', err.message);
    process.exit(1);
  });
  child.on('exit', (code) => {
    console.log(`[launch] App exited with code ${code}`);
    process.exit(code || 0);
  });

  return child;
}

// ─── Build CDP injection expression ──────────────────────────────────────────

function buildInjectionExpression(opts) {
  const INJECT_DIR = path.join(__dirname, 'injections');
  const mainInjectPath   = path.join(INJECT_DIR, 'main-inject.js');
  const preloadExtraPath = path.join(INJECT_DIR, 'preload-extra.js');

  const parts = [];

  // Build compatibility require
  parts.push(`
    const __interceptRequire = (function getCompatRequire() {
      if (typeof globalThis.require === 'function') return globalThis.require;
      try {
        const mod = process.getBuiltinModule && process.getBuiltinModule('module');
        if (mod && typeof mod.createRequire === 'function') {
          return mod.createRequire(process.cwd() + '/__electron_interceptor__.cjs');
        }
      } catch (e) {
        process.stderr.write('[inject] createRequire bootstrap failed: ' + e.message + '\\\\n');
      }
      return null;
    })();
    if (!__interceptRequire) {
      throw new Error('No compatible require() available in this ESM frame');
    }
  `);

  // Setup Electron proxy + cert trust (inline, no prepend-electron.js)
  parts.push(`
    (function setupElectronProxy() {
      const { app, session } = __interceptRequire('electron');
      const certDataList = ${JSON.stringify(opts.certInfo.certDataList)};
      const proxyServer = ${JSON.stringify(opts.proxyServer)};
      const bypassList = ${JSON.stringify(opts.noBypass ? '' : '<-loopback>')};
      const spki = ${JSON.stringify(opts.certInfo.spkiFingerprint)};

      if (app.commandLine) {
        app.commandLine.appendSwitch('proxy-server', proxyServer);
        if (bypassList) app.commandLine.appendSwitch('proxy-bypass-list', bypassList);
        if (spki) app.commandLine.appendSwitch('ignore-certificate-errors-spki-list', spki);
      }

      app.on('ready', function () {
        function normalizePem(s) {
          return String(s || '').replace(/\\\\r\\\\n|\\\\r|\\\\n/g, '\\\\n');
        }
        function isTrustedIssuer(cert) {
          if (!cert) return false;
          const issuerData = cert.issuerCert && cert.issuerCert.data ? normalizePem(cert.issuerCert.data) : '';
          const certData = cert.data ? normalizePem(cert.data) : '';
          return certDataList.some(function(d) {
            return normalizePem(d) === issuerData || normalizePem(d) === certData;
          });
        }
        function shouldForceTrust(req) {
          const host = String(req && req.hostname || '');
          return host !== '127.0.0.1' && host !== 'localhost' && host !== '::1';
        }

        if (certDataList.length > 0) {
          session.defaultSession.setCertificateVerifyProc(function (req, cb) {
            const issuerTrusted = isTrustedIssuer(req.certificate);
            const forceTrusted = shouldForceTrust(req);
            const decision = (issuerTrusted || forceTrusted) ? 0 : -3;
            cb(decision);
          });
        }
      });

      app.on('certificate-error', function (ev, _wc, _url, _err, cert, cb) {
        function normalizePem(s) {
          return String(s || '').replace(/\\\\r\\\\n|\\\\r|\\\\n/g, '\\\\n');
        }
        function isTrustedIssuer(c) {
          if (!c) return false;
          const issuerData = c.issuerCert && c.issuerCert.data ? normalizePem(c.issuerCert.data) : '';
          const certData = c.data ? normalizePem(c.data) : '';
          return certDataList.some(function(d) {
            return normalizePem(d) === issuerData || normalizePem(d) === certData;
          });
        }
        const trusted = certDataList.length > 0 && isTrustedIssuer(cert);
        if (trusted) {
          ev.preventDefault();
          cb(true);
        } else {
          cb(false);
        }
      });

      app.on('quit', function () {
        try { __interceptRequire('inspector').close(); } catch {}
        setTimeout(function () { process.exit(0); }, 1000);
      });

      process.stdout.write('[ELECTRON-INTERCEPT] Electron proxy setup complete\\\\n');
    })();
  `);

  // Load main-inject.js for IPC + TLS hooks
  parts.push(`
    try {
      __interceptRequire(${JSON.stringify(mainInjectPath)})({
        logFile: ${JSON.stringify(opts.logFile || '')},
        channelFilter: ${JSON.stringify(opts.channelFilter || '')},
        preloadExtraPath: ${JSON.stringify(preloadExtraPath)},
        burpHost: ${JSON.stringify(opts.burpHost)},
        burpPort: ${JSON.stringify(opts.burpPort)}
      });
    } catch(e) {
      process.stderr.write('[inject] main-inject failed: ' + e.message + '\\\\n');
    }
  `);

  return parts.join('\n;\n');
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const opts = parseArgs();

  console.log('');
  console.log('╔══════════════════════════════════════════════════╗');
  console.log('║      Generic Electron Interceptor v2.0          ║');
  console.log('╚══════════════════════════════════════════════════╝');
  console.log('');

  if (!opts.appPath) {
    console.error('[error] Missing --app parameter');
    console.error('Usage: node launcher.js --app /path/to/App.app [options]');
    process.exit(1);
  }

  // Find executable
  let exePath;
  try {
    exePath = findExecutable(opts.appPath);
  } catch (e) {
    console.error('[error]', e.message);
    process.exit(1);
  }

  // Load Burp cert
  const certInfo = loadBurpCert(opts.certPath);
  const proxyServer = `${opts.burpHost}:${opts.burpPort}`;

  // Prepare log file
  if (opts.logFile) {
    const logDir = path.dirname(opts.logFile);
    fs.mkdirSync(logDir, { recursive: true });
    console.log('[log] Logging to:', opts.logFile);
  }

  // Get debug port
  const debugPort = opts.debugPort > 0 ? opts.debugPort : await getFreePort(cfg.debugPortBase);

  // Build injection expression
  const expression = buildInjectionExpression({
    certInfo,
    proxyServer,
    noBypass: opts.noBypass,
    logFile: opts.logFile,
    channelFilter: opts.channelFilter,
    burpHost: opts.burpHost,
    burpPort: opts.burpPort,
  });

  // Spawn Electron
  spawnElectron(exePath, debugPort, proxyServer, certInfo, opts.noBypass);

  // Inject via CDP
  console.log('[cdp] Connecting to Electron debugger...');

  let injectionOk = false;
  try {
    await injectViaCDP({ port: debugPort, expression });
    injectionOk = true;
  } catch (e) {
    console.error('[cdp] Injection error:', e.message);
    console.error('[cdp] App is running but may not be intercepted');
  }

  console.log('');
  if (injectionOk) {
    console.log('✓  App is running with full interception active');
    console.log('✓  Network traffic → Burp Suite at', `http://${opts.burpHost}:${opts.burpPort}`);
    console.log('✓  IPC channels hooked');
    console.log('✓  Fetch hooks installed');
    console.log('✓  TLS tunnel active');
    if (opts.logFile) console.log('✓  Logging to:', opts.logFile);
  } else {
    console.log('⚠  App is running but injection FAILED');
  }
  console.log('');
  console.log('Press Ctrl+C to stop');
}

main().catch((e) => {
  console.error('[fatal]', e.message);
  process.exit(1);
});
