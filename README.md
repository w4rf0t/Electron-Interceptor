

# Electron Interceptor for Burp Suite (macOS)

> Burp Suite extension to intercept traffic from any Electron app on macOS via Burp proxy. Inspired by [HTTP Toolkit Electron Interceptor](https://github.com/httptoolkit/httptoolkit-server/blob/main/src/interceptors/electron.ts).

## Features
- Injects proxy and CA certificate into both Chromium (renderer) and Node (main process) of Electron apps.
- Enables security testing and HTTPS traffic analysis.

## Requirements
- macOS
- Burp Suite + Jython (for Python extension)
- Node.js (for launcher)

## Installation
1. Install dependencies for the launcher:
   ```bash
   cd intercept-extension && npm install
   cd overrides/js && npm install
   ```
2. Configure Jython in Burp:
   - Burp → Extensions → Options → Python environment → Location of Jython standalone JAR ([download Jython](https://www.jython.org/download))
3. Load the extension:
   - Extensions → Add → Extension type: Python
   - Extension file: electron_interceptor.py
4. Export Burp CA certificate:
   - Burp → Proxy → Options → Import/export CA certificate → Export → Certificate in DER format (cacert.der)
   - Convert to PEM if needed:
     ```bash
     openssl x509 -inform DER -in cacert.der -out cacert.pem
     ```
5. Make sure Burp Proxy is listening (e.g., 127.0.0.1:8080)

## Usage
1. Open the Electron Interceptor tab in Burp.
2. Select the Electron app path (e.g., /Applications/MyApp.app).
3. Select the launcher script (launcher.js).
4. Select Node executable (default: node, or provide full path if needed).
5. Enter Burp proxy host/port (match Proxy Listener).
6. Enter Burp CA cert path (PEM).
7. Click "Launch Electron through Burp" → traffic will appear in Burp Proxy.

### Run launcher from terminal (CLI)
```bash
cd intercept-extension
node launcher.js --app "/Applications/YourElectronApp.app" --proxy 127.0.0.1:8080 --cert /path/to/cacert.pem
```

## Troubleshooting
- Requests not showing in Burp: check scope, filter, TLS Pass Through, proxy-bypass-list.
- Requests to localhost/127.0.0.1: bypassed by default, use `--no-bypass` to intercept.
- Health check failed: not a proxy error, just API returns non-2xx.
- "No such file or directory" error when launching: provide full path to Node.

## Notes
- For security testing of your own apps or with permission only.
- Always use Burp CA cert (PEM) to intercept HTTPS.

## Folder Structure

```
intercept-extension/
├── README.md
├── package.json
├── launcher.js               # Launcher CLI: spawn --inspect-brk + CDP inject
├── cacert.der                # Burp CA cert (exported from Burp, optional)
└── overrides/
    └── js/
        ├── package.json
        ├── prepend-electron.js   # Inject: proxy + cert for Chromium
        ├── prepend-node.js       # Global agent for Node http(s)
        └── wrap-require.js       # Hook require() to patch modules
```
