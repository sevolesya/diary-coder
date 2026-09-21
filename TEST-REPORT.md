# Diary Coder — local verification

Автоматически выполнено при сборке:

- JavaScript syntax check: `app.js` — PASS
- JavaScript syntax check: `service-worker.js` — PASS
- `manifest.webmanifest` JSON validation — PASS
- Crypto round-trip: русский — PASS
- Crypto round-trip: English — PASS
- Crypto round-trip: сербский / Unicode — PASS
- Crypto round-trip: emoji — PASS
- Crypto round-trip: multiline / blank lines — PASS
- Crypto round-trip: 10,000 characters — PASS
- Wrong password rejected — PASS
- One-character ciphertext modification rejected by AES-GCM — PASS
- Notion-style fenced text normalization — PASS
- Newlines / whitespace normalization — PASS
- zero-width characters normalization — PASS
- Unicode dash normalization — PASS
- Output alphabet check: `DC1.` + base64url-safe ASCII — PASS
- Forbidden client persistence API scan — PASS
- PWA icon dimensions — PASS
- Static app assets return HTTP 200 from local server — PASS

## Требует проверки на реальном iPad/Safari

Среда сборки не эмулирует iPadOS Safari, поэтому вручную на устройстве следует подтвердить:

- Add to Home Screen / standalone launch;
- работу Clipboard API и fallback в конкретной версии Safari;
- повторный запуск без сети после первой успешной загрузки;
- поведение экранной клавиатуры в portrait/landscape.
