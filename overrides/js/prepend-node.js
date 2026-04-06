/**
 * Sets up global agent for http/https and patches libs to use proxy (from HTTP Toolkit).
 * Used when injected into Electron main process.
 */

const wrapModule = require('./wrap-require');

if (process.env.http_proxy && !process.env.HTTP_PROXY) {
  process.env.HTTP_PROXY = process.env.http_proxy;
}

wrapModule('axios', function wrapAxios(loadedModule) {
  if (global.GLOBAL_AGENT) return;
  loadedModule.defaults.proxy = false;
});

wrapModule('request', function wrapRequest(loadedModule) {
  if (global.GLOBAL_AGENT) return;
  if (!loadedModule.defaults) return;
  if (loadedModule.INTERCEPTED_BY_HTTPTOOLKIT) return;
  const fixedModule = loadedModule.defaults({ proxy: false });
  fixedModule.INTERCEPTED_BY_HTTPTOOLKIT = true;
  return fixedModule;
});

wrapModule('superagent', function wrapSuperagent(loadedModule) {
  if (global.GLOBAL_AGENT) return;
  if (loadedModule.INTERCEPTED_BY_HTTPTOOLKIT) return;
  loadedModule.INTERCEPTED_BY_HTTPTOOLKIT = true;
  const originalRequestMethod = loadedModule.Request.prototype.request;
  loadedModule.Request.prototype.request = function () {
    if (this.url.indexOf('https:') === 0) {
      this._agent = require('https').globalAgent;
    } else {
      this._agent = require('http').globalAgent;
    }
    return originalRequestMethod.apply(this, arguments);
  };
});

wrapModule('undici', function wrapUndici(loadedModule) {
  const ProxyAgent = loadedModule.ProxyAgent;
  const setGlobalDispatcher = loadedModule.setGlobalDispatcher;
  if (!ProxyAgent || !setGlobalDispatcher) return;
  setGlobalDispatcher(new ProxyAgent(process.env.HTTP_PROXY));
});

wrapModule('stripe', function wrapStripe(loadedModule) {
  if (loadedModule.INTERCEPTED_BY_HTTPTOOLKIT) return;
  return Object.assign(
    function () {
      const agentConfigSupported = !loadedModule.DEFAULT_HOST;
      const agent = require('https').globalAgent;
      if (agentConfigSupported) {
        const [apiKey, configOption] = arguments;
        const config = { ...configOption, httpAgent: agent };
        return loadedModule.call(this, apiKey, config);
      } else {
        const result = loadedModule.apply(this, arguments);
        result.setHttpAgent(agent);
        return result;
      }
    },
    loadedModule,
    { INTERCEPTED_BY_HTTPTOOLKIT: true }
  );
});

const MAJOR_NODEJS_VERSION = parseInt(process.version.slice(1).split('.')[0], 10);
if (MAJOR_NODEJS_VERSION >= 10) {
  try {
    const globalAgent = require('global-agent');
    globalAgent.bootstrap();
  } catch (e) {
    // global-agent optional
  }
} else {
  try {
    const globalTunnel = require('global-tunnel-ng');
    globalTunnel.initialize();
  } catch (e) {
    // optional
  }
}

if (MAJOR_NODEJS_VERSION >= 18 || typeof global.fetch === 'function') {
  try {
    require('undici');
  } catch (e) {}
}