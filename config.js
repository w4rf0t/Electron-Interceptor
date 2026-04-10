'use strict';
/**
 * config.js - Default configuration for intercept-extension
 */

module.exports = {
  // Default Electron app path (override with --app)
  defaultAppPath: '/Applications/App.app',

  // Burp proxy settings
  burpHost: '127.0.0.1',
  burpPort: 8080,

  // Default certificate path (override with --cert)
  defaultCertPath: './cacert.pem',

  // Debug port base (will find free port starting from this)
  debugPortBase: 9229,

  // Log file for IPC/network traffic (override with --log-file)
  logFile: './logs/traffic.ndjson',

  // IPC channel filter (comma-separated prefixes, override with --channel-filter)
  channelFilter: '', // empty = log all channels
};
