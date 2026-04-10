'use strict';
/**
 * main-inject.js - Generic Electron HTTP/HTTPS + IPC interceptor
 *
 * Simplified version based on kchat-interceptor but without XMPP-specific code.
 * Hooks:
 *   1. globalThis.fetch / undici.fetch → reroute to electron.net.fetch
 *   2. tls.connect → HTTPS MITM via CONNECT tunnel to Burp
 *   3. ipcMain.handle / ipcMain.on / webContents.send → IPC logging
 */

module.exports = function installHooks(config) {
  const fs   = require('fs');
  const path = require('path');
  const http = require('http');
  const tls  = require('tls');
  const net  = require('net');

  const LOG_FILE        = config.logFile         || '';
  const CHANNEL_FILTER  = config.channelFilter   || '';
  const PRELOAD_EXTRA   = config.preloadExtraPath || '';
  const BURP_HOST       = config.burpHost        || '127.0.0.1';
  const BURP_PORT       = config.burpPort        || 8080;
  const CONNECT_TIMEOUT_MS = Math.max(5000, Number(process.env.ELECTRON_CONNECT_TIMEOUT_MS || 45000));
  const INTERNAL_PREFIX = '_intercept:';

  // ─── Logging ────────────────────────────────────────────────────────────────

  const LOG_DIR = LOG_FILE ? path.dirname(LOG_FILE) : '';
  if (LOG_DIR) {
    try { fs.mkdirSync(LOG_DIR, { recursive: true }); } catch {}
  }

  function safeStringify(value) {
    const seen = new WeakSet();
    try {
      return JSON.stringify(value, (key, v) => {
        if (typeof v === 'bigint') return v.toString();
        if (typeof v === 'function') return `[Function:${v.name || 'anonymous'}]`;
        if (Buffer.isBuffer(v)) return { type: 'Buffer', length: v.length };
        if (v && typeof v === 'object') {
          if (seen.has(v)) return '[Circular]';
          seen.add(v);
        }
        return v;
      });
    } catch {
      return JSON.stringify({ error: 'log-serialize-failed' });
    }
  }

  function writeLog(entry) {
    try {
      const line = safeStringify({ ts: Date.now(), ...entry }) + '\n';
      process.stdout.write('\x1b[36m[ELECTRON-INTERCEPT]\x1b[0m ' + line);
      if (LOG_FILE) {
        try { fs.appendFileSync(LOG_FILE, line); } catch {}
      }
    } catch {}
  }

  // ─── Fetch Hooks ────────────────────────────────────────────────────────────

  function extractFetchMeta(resource, init) {
    let url = '';
    if (typeof resource === 'string') url = resource;
    else if (resource && typeof resource.url === 'string') url = resource.url;
    else if (resource instanceof URL) url = resource.toString();

    const method = (init && init.method) || 'GET';
    let body = null;
    if (init && init.body) {
      if (typeof init.body === 'string') body = Buffer.from(init.body);
      else if (Buffer.isBuffer(init.body)) body = init.body;
      else if (init.body instanceof ArrayBuffer) body = Buffer.from(init.body);
    }
    return { url, method, body };
  }

  function getUrlHost(url) {
    try {
      return new URL(String(url || '')).hostname.toLowerCase();
    } catch {
      return '';
    }
  }

  function shouldInterceptHost(host) {
    // Intercept all HTTPS traffic (you can customize this)
    const h = String(host || '').toLowerCase();
    // Skip localhost and proxy itself
    if (h === '127.0.0.1' || h === 'localhost' || h === '::1') return false;
    if (h === BURP_HOST.toLowerCase()) return false;
    return true;
  }

  function stripInitForChromiumFetch(init) {
    if (!init) return init;
    const cleaned = { ...init };
    delete cleaned.agent;
    delete cleaned.dispatcher;
    delete cleaned.duplex;
    delete cleaned.priority;
    return cleaned;
  }

  function hookFetch() {
    try {
      const electron = require('electron');

      // Hook globalThis.fetch
      if (typeof globalThis.fetch === 'function' && !globalThis.__electronInterceptFetchPatched) {
        const origFetch = globalThis.fetch.bind(globalThis);
        globalThis.fetch = function interceptedFetch(resource, init) {
          try {
            const meta = extractFetchMeta(resource, init);
            const host = getUrlHost(meta.url);
            if (meta.url && shouldInterceptHost(host) &&
                electron.net && typeof electron.net.fetch === 'function') {
              writeLog({
                layer: 'fetch',
                event: 'rerouted',
                host,
                method: meta.method,
                url: meta.url,
                via: 'electron.net.fetch'
              });
              return electron.net.fetch(resource, stripInitForChromiumFetch(init));
            }
          } catch (e) {
            writeLog({ layer: 'fetch', event: 'wrap-error', error: e.message });
          }
          return origFetch(resource, init);
        };
        globalThis.__electronInterceptFetchPatched = true;
        writeLog({ layer: 'fetch', event: 'globalThis.fetch-patched' });
      }

      // Hook undici builtin
      if (typeof process.getBuiltinModule === 'function') {
        try {
          const builtinUndici = process.getBuiltinModule('undici');
          if (builtinUndici && typeof builtinUndici.fetch === 'function' &&
              !builtinUndici.__electronInterceptFetchPatched) {
            const origBuiltinFetch = builtinUndici.fetch.bind(builtinUndici);
            builtinUndici.fetch = function interceptedUndiciFetch(input, init) {
              try {
                const meta = extractFetchMeta(input, init);
                const host = getUrlHost(meta.url);
                if (meta.url && shouldInterceptHost(host) &&
                    electron.net && typeof electron.net.fetch === 'function') {
                  writeLog({
                    layer: 'fetch',
                    event: 'undici-rerouted',
                    host,
                    method: meta.method,
                    url: meta.url,
                    via: 'electron.net.fetch'
                  });
                  return electron.net.fetch(input, stripInitForChromiumFetch(init));
                }
              } catch (e) {
                writeLog({ layer: 'fetch', event: 'undici-wrap-error', error: e.message });
              }
              return origBuiltinFetch(input, init);
            };
            builtinUndici.__electronInterceptFetchPatched = true;
            writeLog({ layer: 'fetch', event: 'undici-builtin-patched' });
          }
        } catch (e) {
          writeLog({ layer: 'fetch', event: 'undici-patch-skip', error: e.message });
        }
      }

      writeLog({ layer: 'fetch', event: 'hooks-installed' });
    } catch (err) {
      writeLog({ layer: 'fetch', event: 'hook-failed', error: err.message });
    }
  }

  // ─── TLS MITM via CONNECT Tunnel ────────────────────────────────────────────

  function shouldTunnelTls(host, port) {
    const h = String(host || '').toLowerCase();
    const p = Number(port || 0);
    if (!p) return false;
    if (h === '127.0.0.1' || h === 'localhost' || h === '::1') return false;
    if (h === String(BURP_HOST).toLowerCase() && p === Number(BURP_PORT)) return false;
    return p === 443 || p === 8443;
  }

  function createConnectTunnelSocket(host, port) {
    let pendingConnect = true;
    let headerBuffer = Buffer.alloc(0);
    let connectTimer = null;
    const socket = new net.Socket();
    let tcpConnected = false;

    function detach() {
      socket.removeListener('data', onData);
      socket.removeListener('error', onError);
    }

    function fail(errLike) {
      if (!pendingConnect) return;
      pendingConnect = false;
      if (connectTimer) clearTimeout(connectTimer);
      detach();
      socket.removeListener('close', onClose);
      const err = errLike instanceof Error ? errLike : new Error(String(errLike || 'Burp CONNECT failed'));
      process.nextTick(() => {
        socket.emit('error', err);
        socket.destroy();
      });
    }

    function complete(remainder) {
      if (!pendingConnect) return;
      pendingConnect = false;
      if (connectTimer) clearTimeout(connectTimer);
      detach();
      socket.removeListener('close', onClose);
      if (remainder && remainder.length > 0) {
        socket.unshift(remainder);
      }
      // Emit custom 'tunnel-ready' event instead of 'connect'
      process.nextTick(() => socket.emit('tunnel-ready'));
    }

    function onData(chunk) {
      if (!pendingConnect) return;
      headerBuffer = Buffer.concat([headerBuffer, chunk]);
      const marker = headerBuffer.indexOf('\r\n\r\n');
      if (marker === -1) return;
      const header = headerBuffer.slice(0, marker).toString('utf8');
      const remainder = headerBuffer.slice(marker + 4);
      const statusLine = (header.split('\r\n')[0] || '').trim();
      const statusCodeMatch = statusLine.match(/^HTTP\/\d+\.\d+\s+(\d{3})/i);
      const statusCode = statusCodeMatch ? Number(statusCodeMatch[1]) : 0;
      if (statusCode !== 200) {
        fail(new Error(`Proxy CONNECT rejected: ${statusLine || 'invalid response'}`));
        return;
      }
      complete(remainder);
    }

    function onError(err) {
      fail(new Error(`Proxy socket error: ${err.message}`));
    }
    function onClose() {
      if (pendingConnect) {
        fail(new Error('Proxy socket closed before CONNECT completed'));
      }
    }

    function onTcpConnect() {
      tcpConnected = true;
      if (!pendingConnect) return;
      const req =
        `CONNECT ${host}:${port} HTTP/1.1\r\n` +
        `Host: ${host}:${port}\r\n` +
        'Proxy-Connection: keep-alive\r\n' +
        'Connection: keep-alive\r\n' +
        '\r\n';
      socket.write(req);
    }

    socket.on('data', onData);
    socket.on('error', onError);
    socket.on('close', onClose);
    socket.once('connect', onTcpConnect);

    connectTimer = setTimeout(() => {
      fail(new Error('Proxy CONNECT timeout'));
    }, CONNECT_TIMEOUT_MS);

    socket.connect(BURP_PORT, BURP_HOST);
    return socket;
  }

  function createDeferredTlsFace() {
    const { EventEmitter } = require('events');
    const face = new EventEmitter();
    face.setMaxListeners(0);
    face._real = null;
    let keepAliveArgs = null;
    let noDelayVal;
    let timeoutMs;
    const emitterMethods = new Set([
      'on', 'once', 'addListener', 'prependListener', 'prependOnceListener',
      'removeListener', 'off', 'removeAllListeners', 'listeners', 'rawListeners', 'emit',
    ]);

    let proxy;
    face.setKeepAlive = function (enable, initialDelay) {
      if (face._real) face._real.setKeepAlive(enable, initialDelay);
      else keepAliveArgs = [enable, initialDelay];
      return proxy;
    };
    face.setNoDelay = function (noDelay) {
      const v = noDelay !== false;
      if (face._real) face._real.setNoDelay(v);
      else noDelayVal = v;
      return proxy;
    };
    face.setTimeout = function (ms, listener) {
      if (face._real) face._real.setTimeout(ms, listener);
      else {
        timeoutMs = Number(ms) || 0;
        if (typeof listener === 'function') face.once('timeout', listener);
      }
      return proxy;
    };

    proxy = new Proxy(face, {
      get(target, prop, receiver) {
        if (prop === 'setKeepAlive' || prop === 'setNoDelay' || prop === 'setTimeout') {
          return Reflect.get(target, prop, receiver);
        }
        if (emitterMethods.has(String(prop))) return Reflect.get(target, prop, receiver);
        const real = target._real;
        if (real && prop in real) {
          const v = real[prop];
          return typeof v === 'function' ? v.bind(real) : v;
        }
        return Reflect.get(target, prop, receiver);
      },
    });

    return {
      proxy,
      attach(real) {
        face._real = real;
        if (keepAliveArgs) real.setKeepAlive(keepAliveArgs[0], keepAliveArgs[1]);
        if (noDelayVal !== undefined) real.setNoDelay(noDelayVal);
        if (timeoutMs !== undefined) real.setTimeout(timeoutMs);
        ['session', 'secureConnect', 'error', 'close', 'end', 'timeout'].forEach((ev) => {
          real.on(ev, (...args) => face.emit(ev, ...args));
        });
      },
      emitError(err) {
        process.nextTick(() => face.emit('error', err));
      },
    };
  }

  function hookTls() {
    if (global.__electronInterceptTlsHookInstalled) return;
    global.__electronInterceptTlsHookInstalled = true;

    const origTlsConnect = tls.connect.bind(tls);

    tls.connect = function interceptedTlsConnect(options, cb) {
      let opts = options;
      let callback = cb;

      if (typeof opts === 'number') {
        const port = opts;
        let host = 'localhost';
        let rest;
        if (typeof cb === 'string') {
          host = cb;
          rest = arguments[2];
          callback = arguments[3];
        } else {
          rest = arguments[1];
        }
        opts = { port, host };
        if (rest && typeof rest === 'object' && !Array.isArray(rest)) Object.assign(opts, rest);
      }
      opts = opts || {};

      if (opts.socket) {
        return origTlsConnect.apply(tls, arguments);
      }

      const host = opts.host || opts.servername || 'localhost';
      const port = Number(opts.port || 443);

      if (!shouldTunnelTls(host, port)) {
        return origTlsConnect.apply(tls, arguments);
      }

      writeLog({
        layer: 'tls',
        event: 'tunnel-start',
        host,
        port,
      });

      const tlsFace = createDeferredTlsFace();
      const tunnelSocket = createConnectTunnelSocket(host, port);

      tunnelSocket.once('tunnel-ready', () => {
        writeLog({
          layer: 'tls',
          event: 'tunnel-established',
          host,
          port,
        });

        const tlsOpts = { ...opts, socket: tunnelSocket };
        if (!tlsOpts.servername) tlsOpts.servername = host;
        tlsOpts.rejectUnauthorized = false;

        try {
          const real = typeof callback === 'function'
            ? origTlsConnect.call(tls, tlsOpts, callback)
            : origTlsConnect.call(tls, tlsOpts);
          tlsFace.attach(real);

          real.once('secureConnect', () => {
            writeLog({
              layer: 'tls',
              event: 'handshake-complete',
              host,
              port,
              protocol: real.getProtocol(),
              cipher: real.getCipher()?.name,
            });
          });
        } catch (e) {
          writeLog({
            layer: 'tls',
            event: 'tunnel-failed',
            host,
            port,
            error: e.message,
          });
          tlsFace.emitError(e instanceof Error ? e : new Error(String(e)));
          try { tunnelSocket.destroy(); } catch (_) {}
        }
      });

      tunnelSocket.once('error', (err) => {
        writeLog({
          layer: 'tls',
          event: 'tunnel-error',
          host,
          port,
          error: err.message,
        });
      });

      return tlsFace.proxy;
    };

    writeLog({ layer: 'tls', event: 'hooks-installed' });
  }

  // ─── IPC Hooks ──────────────────────────────────────────────────────────────

  function shouldLogChannel(channel) {
    if (!channel || typeof channel !== 'string') return false;
    if (channel.startsWith(INTERNAL_PREFIX)) return false;
    if (!CHANNEL_FILTER) return true;
    const filters = CHANNEL_FILTER.split(',').map((s) => s.trim()).filter(Boolean);
    return filters.some((prefix) => channel.startsWith(prefix));
  }

  function hookIpc() {
    try {
      const { ipcMain, session, app } = require('electron');

      // Hook ipcMain.handle
      const origHandle = ipcMain.handle.bind(ipcMain);
      ipcMain.handle = function (channel, listener) {
        if (shouldLogChannel(channel)) {
          const wrapped = async function (event, ...args) {
            writeLog({
              layer: 'ipc',
              type: 'handle',
              direction: 'renderer→main',
              channel,
              args: safeStringify(args),
            });
            const result = await listener(event, ...args);
            writeLog({
              layer: 'ipc',
              type: 'handle',
              direction: 'main→renderer',
              channel,
              result: safeStringify(result),
            });
            return result;
          };
          return origHandle(channel, wrapped);
        }
        return origHandle(channel, listener);
      };

      // Hook ipcMain.on
      const origOn = ipcMain.on.bind(ipcMain);
      ipcMain.on = function (channel, listener) {
        if (shouldLogChannel(channel)) {
          const wrapped = function (event, ...args) {
            writeLog({
              layer: 'ipc',
              type: 'on',
              direction: 'renderer→main',
              channel,
              args: safeStringify(args),
            });
            return listener(event, ...args);
          };
          return origOn(channel, wrapped);
        }
        return origOn(channel, listener);
      };

      // Hook webContents.send
      app.on('web-contents-created', (_, webContents) => {
        const origSend = webContents.send.bind(webContents);
        webContents.send = function (channel, ...args) {
          if (shouldLogChannel(channel)) {
            writeLog({
              layer: 'ipc',
              type: 'send',
              direction: 'main→renderer',
              channel,
              args: safeStringify(args),
            });
          }
          return origSend(channel, ...args);
        };
      });

      // Inject preload script
      if (PRELOAD_EXTRA && fs.existsSync(PRELOAD_EXTRA)) {
        app.on('session-created', (sess) => {
          const preloads = sess.getPreloads();
          if (!preloads.includes(PRELOAD_EXTRA)) {
            sess.setPreloads([...preloads, PRELOAD_EXTRA]);
          }
        });
        app.whenReady().then(() => {
          const preloads = session.defaultSession.getPreloads();
          if (!preloads.includes(PRELOAD_EXTRA)) {
            session.defaultSession.setPreloads([...preloads, PRELOAD_EXTRA]);
          }
        });
      }

      // Listen for renderer logs
      ipcMain.on('_intercept:renderer-log', (_, entry) => {
        writeLog(entry);
      });

      writeLog({ layer: 'ipc', event: 'hooks-installed' });
    } catch (err) {
      writeLog({ layer: 'ipc', event: 'hook-failed', error: err.message });
    }
  }

  // ─── Initialize ─────────────────────────────────────────────────────────────

  writeLog({ layer: 'main-inject', event: 'initializing', config: {
    logFile: LOG_FILE || '(none)',
    channelFilter: CHANNEL_FILTER || '(all)',
    preloadExtra: PRELOAD_EXTRA || '(none)',
    burpHost: BURP_HOST,
    burpPort: BURP_PORT,
  }});

  hookFetch();
  hookIpc();
  hookTls();

  writeLog({ layer: 'main-inject', event: 'ready' });
};
