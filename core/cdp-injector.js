'use strict';
/**
 * CDP Injector - connects to Electron's debug port and evaluates injection code
 * on the very first call frame (before any app code runs).
 */

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * @param {object} opts
 * @param {number} opts.port      - debug port Electron was started with
 * @param {string} opts.expression - JS expression to evaluate on call frame
 * @param {number} [opts.retries=20]
 * @param {number} [opts.retryDelay=400]
 * @returns {Promise<void>}
 */
async function injectViaCDP({ port, expression, retries = 20, retryDelay = 400 }) {
  let CDP;
  try {
    CDP = require('chrome-remote-interface');
  } catch {
    throw new Error('Missing dependency: run "npm install" inside intercept-extension/');
  }

  let client;
  let attempts = retries;

  while (attempts >= 0) {
    try {
      client = await CDP({ host: '127.0.0.1', port });
      break;
    } catch (err) {
      if (err.code !== 'ECONNREFUSED' && err.code !== 'ECONNRESET') throw err;
      attempts--;
      if (attempts < 0) throw new Error(`Could not connect to Electron debugger on port ${port} after ${retries} retries`);
      await delay(retryDelay);
    }
  }

  try {
    await client.Runtime.enable();
    await client.Debugger.enable();

    const pausePromise = new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Timed out waiting for Debugger.paused')), 15000);
      client.Debugger.paused((stack) => {
        clearTimeout(timeout);
        resolve(stack.callFrames[0].callFrameId);
      });
    });

    // Tell the paused-on-start debugger to proceed to the first breakpoint
    await client.Runtime.runIfWaitingForDebugger();
    const callFrameId = await pausePromise;

    const result = await client.Debugger.evaluateOnCallFrame({
      callFrameId,
      expression,
      returnByValue: false,
    });

    if (result.exceptionDetails) {
      const ex = result.exceptionDetails;
      const msg = ex.exception?.description || JSON.stringify(ex);
      throw new Error(`Injection failed in CDP frame: ${msg}`);
    }

    console.log('[cdp] Injection succeeded, resuming app...');
    await client.Debugger.resume();
  } finally {
    client.close();
  }
}

module.exports = { injectViaCDP };
