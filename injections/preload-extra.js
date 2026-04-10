'use strict';
/**
 * preload-extra.js
 * Additional preload script injected into every renderer window via session.setPreloads().
 * Runs in the renderer's preload context (has access to Node.js + Electron APIs,
 * but NOT to the web page's window yet).
 *
 * Hooks ipcRenderer.invoke and ipcRenderer.on so every renderer↔main call
 * is relayed back to main-inject.js via the '_intercept:renderer-log' channel
 * for file logging.
 */

(function () {
  const { ipcRenderer } = require('electron');

  const INTERNAL = '_intercept:';
  const LOG_CH   = '_intercept:renderer-log';

  function sendLog(entry) {
    try {
      ipcRenderer.send(LOG_CH, entry);
    } catch {}
  }

  // ── Hook invoke (renderer → main, expects response) ──────────────────────

  const origInvoke = ipcRenderer.invoke.bind(ipcRenderer);

  ipcRenderer.invoke = async function (channel, ...args) {
    const logArgs = safeSerialize(args);

    sendLog({
      layer: 'renderer',
      type: 'invoke',
      direction: 'renderer→main',
      channel,
      args: logArgs,
    });

    const result = await origInvoke(channel, ...args);

    sendLog({
      layer: 'renderer',
      type: 'invoke',
      direction: 'main→renderer',
      channel,
      result: safeSerialize(result),
    });

    return result;
  };

  // ── Hook send (one-way renderer → main) ──────────────────────────────────

  const origSend = ipcRenderer.send.bind(ipcRenderer);

  ipcRenderer.send = function (channel, ...args) {
    if (!channel.startsWith(INTERNAL)) {
      sendLog({
        layer: 'renderer',
        type: 'send',
        direction: 'renderer→main',
        channel,
        args: safeSerialize(args),
      });
    }
    return origSend(channel, ...args);
  };

  // ── Hook on (main → renderer push events) ────────────────────────────────

  const origOn = ipcRenderer.on.bind(ipcRenderer);

  ipcRenderer.on = function (channel, listener) {
    if (channel.startsWith(INTERNAL)) {
      return origOn(channel, listener);
    }
    const wrapped = function (event, ...args) {
      sendLog({
        layer: 'renderer',
        type: 'push',
        direction: 'main→renderer',
        channel,
        args: safeSerialize(args),
      });
      return listener(event, ...args);
    };
    return origOn(channel, wrapped);
  };

  // ── Serialization helper ──────────────────────────────────────────────────
  // IPC payloads can contain non-serialisable objects (Buffers, errors, etc.)

  function safeSerialize(value) {
    try {
      JSON.stringify(value); // test
      return value;
    } catch {
      try {
        return JSON.parse(
          JSON.stringify(value, (_k, v) => {
            if (v instanceof Error) return { __error: true, message: v.message, stack: v.stack };
            if (typeof v === 'bigint') return v.toString();
            if (Buffer.isBuffer(v)) return { __buffer: true, hex: v.toString('hex').slice(0, 256) };
            if (v instanceof Uint8Array) return { __bytes: true, hex: Buffer.from(v).toString('hex').slice(0, 256) };
            return v;
          })
        );
      } catch {
        return '[unserializable]';
      }
    }
  }

  console.log('[kchat-interceptor] preload-extra.js loaded — ipcRenderer hooked');
})();
