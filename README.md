
# Electron Interceptor for Burp Suite (macOS)

> Extension Burp Suite giúp intercept traffic của **mọi ứng dụng Electron** trên macOS bằng proxy Burp Suite. Dựa trên ý tưởng [HTTP Toolkit Electron Interceptor](https://github.com/httptoolkit/httptoolkit-server/blob/main/src/interceptors/electron.ts).

## Tính năng
- Inject proxy và CA cert vào cả Chromium (renderer) và Node (main process) của Electron app.
- Cho phép kiểm thử bảo mật, phân tích traffic HTTPS.

## Yêu cầu
- macOS
- Burp Suite + Jython (cho extension Python)
- Node.js (cho launcher)

## Cài đặt
1. Cài dependency cho launcher:
   ```bash
   cd intercept-extension && npm install
   cd overrides/js && npm install
   ```
2. Cấu hình Jython trong Burp:
   - Burp → Extensions → Options → Python environment → Location of Jython standalone JAR ([tải Jython](https://www.jython.org/download))
3. Load extension:
   - Extensions → Add → Extension type: Python
   - Extension file: electron_interceptor.py
4. Export CA cert của Burp:
   - Burp → Proxy → Options → Import/export CA certificate → Export → Certificate in DER format (cacert.der)
   - Chuyển sang PEM nếu cần:
     ```bash
     openssl x509 -inform DER -in cacert.der -out cacert.pem
     ```
5. Đảm bảo Burp Proxy đang listen (ví dụ: 127.0.0.1:8080)

## Sử dụng
1. Mở tab Electron Interceptor trong Burp.
2. Chọn đường dẫn Electron app (ví dụ: /Applications/MyApp.app).
3. Chọn launcher script (launcher.js).
4. Chọn Node executable (mặc định: node, có thể điền đường dẫn đầy đủ nếu lỗi).
5. Nhập Burp proxy host/port (khớp với Proxy Listener).
6. Nhập đường dẫn Burp CA cert (PEM).
7. Bấm Launch Electron through Burp → traffic sẽ hiển thị trong Burp Proxy.

### Chạy launcher từ terminal (CLI)
```bash
cd intercept-extension
node launcher.js --app "/Applications/YourElectronApp.app" --proxy 127.0.0.1:8080 --cert /path/to/cacert.pem
```

## Troubleshooting
- Request không xuất hiện trong Burp: kiểm tra scope, filter, TLS Pass Through, proxy-bypass-list.
- Request tới localhost/127.0.0.1: mặc định bypass, muốn intercept thêm `--no-bypass` khi chạy launcher.
- Health check failed: không phải lỗi proxy, chỉ là API trả về non-2xx.
- Lỗi "No such file or directory" khi Launch: điền đường dẫn đầy đủ tới Node.

## Lưu ý
- Chỉ dùng cho kiểm thử bảo mật app của bạn hoặc khi được phép.
- Luôn dùng Burp CA cert (PEM) để intercept HTTPS.

## Cấu trúc thư mục

```
intercept-extension/
├── README.md
├── package.json
├── launcher.js               # Launcher CLI: spawn --inspect-brk + CDP inject
├── cacert.der                # Burp CA cert (export từ Burp, tuỳ chọn)
└── overrides/
    └── js/
        ├── package.json
        ├── prepend-electron.js   # Inject: proxy + cert cho Chromium
        ├── prepend-node.js       # Global agent cho Node http(s)
        └── wrap-require.js       # Hook require() để patch modules
```

```
intercept-extension/
├── README.md
├── package.json
├── electron_interceptor.py   # Burp extension (Python) – tab trong Burp
├── launcher.js               # Launcher CLI: spawn --inspect-brk + CDP inject
└── overrides/
    └── js/
        ├── package.json
        ├── prepend-electron.js   # Inject: proxy + cert cho Chromium
        ├── prepend-node.js       # Global agent cho Node http(s)
        └── wrap-require.js       # Hook require() để patch modules
```
