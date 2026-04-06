/**
 * Injected into Electron via CDP before any user code runs (from HTTP Toolkit).
 * Configures Chromium proxy and certificate trust so all traffic goes through Burp.
 */

require('./prepend-node');

module.exports = function reconfigureElectron(params) {
  let electronWrapped = false;
  const wrapModule = require('./wrap-require');
  const enableFetchFallback = params.enableFetchFallback !== false;

  const trustedCerts = params.certDataList || (params.newlineEncodedCertData ? [params.newlineEncodedCertData] : []);

  function isTrustedIssuer(certificate) {
    if (!certificate || !certificate.issuerCert) return false;
    return trustedCerts.some((certData) => certificate.issuerCert.data === certData);
  }

  function parseProxy(rawProxy) {
    const raw = String(rawProxy || '').trim();
    if (!raw) return { proxyServer: '', host: '', port: 0 };
    try {
      const url = new URL(raw.includes('://') ? raw : `http://${raw}`);
      const port = Number(url.port || 8080);
      return {
        proxyServer: `${url.hostname}:${port}`,
        host: url.hostname,
        port,
      };
    } catch {
      return { proxyServer: raw.replace(/^https?:\/\//i, ''), host: '', port: 0 };
    }
  }

  function getFetchUrl(resource) {
    if (!resource) return '';
    if (typeof resource === 'string') return resource;
    if (resource instanceof URL) return resource.toString();
    if (resource && typeof resource.url === 'string') return resource.url;
    return '';
  }

  function shouldFallbackUrl(rawUrl, proxyHost, proxyPort) {
    try {
      const u = new URL(String(rawUrl || ''));
      const host = String(u.hostname || '').toLowerCase();
      const port = Number(u.port || (u.protocol === 'https:' ? 443 : 80));
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
      if (host === '127.0.0.1' || host === 'localhost' || host === '::1') return false;
      if (proxyHost && host === String(proxyHost).toLowerCase() && proxyPort && port === Number(proxyPort)) return false;
      return true;
    } catch {
      return false;
    }
  }

  function applyElectronHooks(loadedModule) {
    if (electronWrapped || !loadedModule.app || !loadedModule.app.commandLine) return;
    electronWrapped = true;

    const app = loadedModule.app;
    const proxyCfg = parseProxy(process.env.HTTP_PROXY);
    if (proxyCfg.proxyServer) {
      app.commandLine.appendSwitch('proxy-server', proxyCfg.proxyServer);
    }
    const bypassList = (params.proxyBypassList !== undefined && params.proxyBypassList !== null)
      ? params.proxyBypassList
      : '<-loopback>';
    app.commandLine.appendSwitch('proxy-bypass-list', bypassList);

    if (params.spkiFingerprint) {
      app.commandLine.appendSwitch('ignore-certificate-errors-spki-list', params.spkiFingerprint);
    }

    app.on('quit', () => {
      try {
        require('inspector').close();
      } catch (e) {
        setTimeout(() => process.exit(0), 1000);
      }
    });

    app.on('ready', async () => {
      if (trustedCerts.length > 0) {
        loadedModule.session.defaultSession.setCertificateVerifyProc((req, callback) => {
          if (isTrustedIssuer(req.certificate)) {
            callback(0);
          } else {
            callback(-3);
          }
        });
      }

      // Runtime safety-net: enforce proxy at session level even if command-line
      // args were ignored or overwritten by the target app.
      if (proxyCfg.proxyServer && loadedModule.session && loadedModule.session.defaultSession) {
        try {
          const session = loadedModule.session.defaultSession;
          await session.setProxy({
            mode: 'fixed_servers',
            proxyRules: proxyCfg.proxyServer,
            proxyBypassRules: bypassList,
          });
          const resolved = await session.resolveProxy('https://example.com');
          process.stdout.write(`[ELECTRON-INTERCEPT] session proxy applied -> ${resolved}\n`);
        } catch (e) {
          process.stdout.write(`[ELECTRON-INTERCEPT] session proxy apply failed: ${e.message}\n`);
        }
      }

      // Fallback path for apps that bypass Node proxy envs but still expose
      // fetch in main process. We route those fetch calls through electron.net.
      if (enableFetchFallback &&
          typeof globalThis.fetch === 'function' &&
          loadedModule.net &&
          typeof loadedModule.net.fetch === 'function' &&
          !globalThis.__electronInterceptFetchFallbackInstalled) {
        const origFetch = globalThis.fetch.bind(globalThis);
        const netFetch = loadedModule.net.fetch.bind(loadedModule.net);
        globalThis.fetch = function interceptedFetch(resource, init) {
          const url = getFetchUrl(resource);
          if (shouldFallbackUrl(url, proxyCfg.host, proxyCfg.port)) {
            return netFetch(resource, init);
          }
          return origFetch(resource, init);
        };
        globalThis.__electronInterceptFetchFallbackInstalled = true;
        process.stdout.write('[ELECTRON-INTERCEPT] fetch fallback installed\n');
      }
    });

    app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
      if (trustedCerts.length > 0 && isTrustedIssuer(certificate)) {
        event.preventDefault();
        callback(true);
      } else {
        callback(false);
      }
    });
  }

  // Patch already-loaded electron module immediately (ESM entrypoints often import
  // electron before our wrapper is installed).
  try {
    applyElectronHooks(require('electron'));
  } catch (e) {
    process.stdout.write(`[ELECTRON-INTERCEPT] immediate electron patch failed: ${e.message}\n`);
  }

  // Also patch future loads via require() to keep compatibility with other apps.
  wrapModule('electron', function wrapElectron(loadedModule) {
    applyElectronHooks(loadedModule);
  }, true);

  // Skip process.binding('crypto') patch: deprecated in Node 18+ (DEP0111).
  // NODE_EXTRA_CA_CERTS (set by launcher) is enough for Node TLS to trust Burp CA.
};