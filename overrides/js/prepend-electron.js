/**
 * Injected into Electron via CDP before any user code runs (from HTTP Toolkit).
 * Configures Chromium proxy and certificate trust so all traffic goes through Burp.
 */

require('./prepend-node');

module.exports = function reconfigureElectron(params) {
  let electronWrapped = false;
  const wrapModule = require('./wrap-require');

  wrapModule('electron', function wrapElectron(loadedModule) {
    if (electronWrapped || !loadedModule.app || !loadedModule.app.commandLine) return;
    electronWrapped = true;

    const app = loadedModule.app;
    app.commandLine.appendSwitch('proxy-server', process.env.HTTP_PROXY);
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

    app.on('ready', () => {
      if (params.newlineEncodedCertData) {
        loadedModule.session.defaultSession.setCertificateVerifyProc((req, callback) => {
          if (
            req.certificate &&
            req.certificate.issuerCert &&
            req.certificate.issuerCert.data === params.newlineEncodedCertData
          ) {
            callback(0);
          } else {
            callback(-3);
          }
        });
      }
    });

    app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
      if (
        params.newlineEncodedCertData &&
        certificate.issuerCert &&
        certificate.issuerCert.data === params.newlineEncodedCertData
      ) {
        event.preventDefault();
        callback(true);
      } else {
        callback(false);
      }
    });
  }, true);

  // Skip process.binding('crypto') patch: deprecated in Node 18+ (DEP0111).
  // NODE_EXTRA_CA_CERTS (set by launcher) is enough for Node TLS to trust Burp CA.
};
