/**
 * Intercept require() to monkey-patch modules (from HTTP Toolkit).
 * Enabled when process.env.HTTP_TOOLKIT_ACTIVE or BURP_INTERCEPT_ACTIVE is set.
 */

const mod = require('module');
const realLoad = mod._load;

const wrappers = {};
let wrappingBlocked = false;

function fixModule(requestedName, filename, loadedModule) {
  const wrapper = wrappers[requestedName];
  if (wrapper) {
    wrappingBlocked = wrapper.shouldBlockWrapping ? [] : false;
    const fixedModule = wrapper.wrap(loadedModule) || loadedModule;
    if (fixedModule !== loadedModule && mod._cache[filename] && mod._cache[filename].exports) {
      mod._cache[filename].exports = fixedModule;
    }
    if (wrappingBlocked) {
      wrappingBlocked.forEach(function (modDetails) {
        fixModule(modDetails.requestedName, modDetails.filename, modDetails.loadedModule);
      });
      wrappingBlocked = false;
    }
    return fixedModule;
  }
  return loadedModule;
}

mod._load = function (requestedName, parent, isMain) {
  const filename = mod._resolveFilename(requestedName, parent, isMain);
  let loadedModule = realLoad.apply(this, arguments);

  const active = process.env.HTTP_TOOLKIT_ACTIVE === 'true' || process.env.BURP_INTERCEPT_ACTIVE === 'true';
  if (!active) return loadedModule;

  if (wrappingBlocked !== false) {
    wrappingBlocked.push({ requestedName: requestedName, filename: filename, loadedModule: loadedModule });
  } else {
    loadedModule = fixModule(requestedName, filename, loadedModule);
  }
  return loadedModule;
};

module.exports = function wrapModule(requestedName, wrapperFunction, shouldBlockWrapping) {
  wrappers[requestedName] = {
    wrap: wrapperFunction,
    shouldBlockWrapping: shouldBlockWrapping || false
  };
};