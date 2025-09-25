# WISP Proxy Package

Contents:
- `proxy.html` — single-file client UI that connects directly to `wss://wisp.mercurywork.shop/`. Choose payload templates or send raw messages.
- `server.js` — a minimal Node/Express HTTP → WebSocket bridge. POST `/fetch` with JSON `{ "url": "...", "template": "fetch_action" }`.
- `package.json` — dependencies and start script.

## How to use the client (proxy.html)
1. Open `proxy.html` in a browser (or host on GitHub Pages).
2. Click **Connect** to establish a WebSocket with `wss://wisp.mercurywork.shop/`.
3. Choose a template or `Raw` and send a message. If the server returns HTML or base64-encoded HTML in `body`/`body_b64`, the UI will offer to open it.

## How to use the bridge (server.js)
1. Install Node 18+ (recommended).
2. In the package directory:
   ```bash
   npm install
   node server.js
   ```
3. Send a POST request:
   ```bash
   curl -X POST http://localhost:3000/fetch -H "Content-Type: application/json" \
     -d '{"url":"https://example.com","template":"fetch_action"}'
   ```
4. The server will open a WebSocket to `WISP_URL` (env var) and forward the chosen payload. Response is returned to the HTTP client.

## Security & Legal
- This is a template. Don't use it to access content you are not authorized to access or to violate terms of service.
- Add input validation, rate limiting, and authentication before deploying publicly.
- Consider CORS and HTTPS for production.

## Customization
- Change `WISP_URL` by setting the `WISP_URL` environment variable when running `server.js`.
- Adjust payload formats in `server.js` → `buildPayload()` to match your upstream's protocol.

