/**
 * Updated bridge:
 * - POST /fetch  { url, template }  -> returns upstream HTML or JSON
 * - GET  /resource?url=...           -> returns resource bytes (image/css/js) proxied from upstream
 *
 * Note: This is a minimal example. Improve error handling, pooling, timeouts, and security before production.
 */

const express = require('express');
const WebSocket = require('ws');
const bodyParser = require('body-parser');

const WISP_URL = process.env.WISP_URL || 'wss://wisp.mercurywork.shop/';
const PORT = process.env.PORT || 3000;
const WS_TIMEOUT_MS = 20000;

const app = express();
app.use(bodyParser.json({ limit: '2mb' }));

// Simple CORS for dev (tighten for prod)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

function buildPayload(template, url) {
  if (template === 'fetch_action') return JSON.stringify({ action: 'fetch', url });
  if (template === 'httpreq') return JSON.stringify({ type: 'http-request', method: 'GET', url });
  if (template === 'fetch_v2') return JSON.stringify({ cmd: 'fetch', target: url, opts: {} });
  // fallback
  return JSON.stringify({ action: 'fetch', url });
}

// Generic helper to open a WS, send payload, await a single message (or timeout)
function sendWsAndWait(payload) {
  return new Promise((resolve, reject) => {
    let ws;
    try { ws = new WebSocket(WISP_URL); }
    catch (err) { return reject(err); }

    const timeout = setTimeout(() => {
      try { ws.terminate(); } catch (e) {}
      reject(new Error('Upstream timeout'));
    }, WS_TIMEOUT_MS);

    ws.on('open', () => {
      try { ws.send(payload); } catch (e) { clearTimeout(timeout); ws.close(); reject(e); }
    });

    ws.on('message', (data) => {
      clearTimeout(timeout);
      // data may be Buffer, string, or JSON string
      // try to parse as JSON
      let parsed = null;
      try {
        const s = (typeof data === 'string') ? data : data.toString('utf8');
        parsed = JSON.parse(s);
      } catch (e) {
        parsed = null;
      }
      // Resolve with an object describing what we got
      resolve({ raw: data, parsed: parsed });
      try { ws.close(); } catch (e) {}
    });

    ws.on('error', (err) => {
      clearTimeout(timeout);
      try { ws.close(); } catch (e) {}
      reject(err);
    });

    ws.on('close', () => {
      // If closed without message, let the timeout handle it; do nothing.
    });
  });
}

// POST /fetch -> used for HTML pages. Wrapper around buildPayload
app.post('/fetch', async (req, res) => {
  const { url, template } = req.body || {};
  if (!url) return res.status(400).json({ error: 'Missing url' });
  const payload = buildPayload(template || 'fetch_action', url);

  try {
    const result = await sendWsAndWait(payload);
    // If parsed JSON includes body/body_b64, return JSON for client parsing
    if (result.parsed) {
      return res.json({ raw: result.raw.toString(), parsed: result.parsed });
    }
    // else assume raw text/html
    const text = (Buffer.isBuffer(result.raw)) ? result.raw.toString('utf8') : String(result.raw);
    // attempt to guess content-type (simple heuristic: starts with '<!doctype' or '<html' -> text/html)
    const t = text.trim().toLowerCase();
    if (t.startsWith('<') || t.includes('<html')) {
      res.setHeader('content-type', 'text/html; charset=utf-8');
      return res.send(text);
    } else {
      // fallback JSON
      return res.json({ raw: text });
    }
  } catch (e) {
    console.error('Fetch error', e);
    return res.status(502).json({ error: String(e) });
  }
});

// GET /resource?url=... -> used for images, css, js, etc. Responds with binary body and content-type if possible.
app.get('/resource', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send('Missing url query');

  // For resource requests we use the same fetch payload; upstream may return raw bytes or JSON with base64
  const payload = buildPayload('fetch_action', url);

  try {
    const result = await sendWsAndWait(payload);
    // If upstream sent JSON-encoded resource info
    if (result.parsed && (result.parsed.body_b64 || result.parsed.body)) {
      const b64 = result.parsed.body_b64 || Buffer.from(result.parsed.body, 'utf8').toString('base64');
      const buf = Buffer.from(b64, 'base64');
      const ct = result.parsed.content_type || 'application/octet-stream';
      res.setHeader('Content-Type', ct);
      res.setHeader('Content-Length', buf.length);
      return res.send(buf);
    }

    // If raw is a Buffer, send it directly
    if (Buffer.isBuffer(result.raw)) {
      // best-effort: no content-type known; send as octet-stream
      res.setHeader('Content-Type', 'application/octet-stream');
      return res.send(result.raw);
    }

    // If raw is string, return as text
    const text = String(result.raw);
    // Try to detect if it's HTML/CSS/JS or image-data (not likely)
    if (text.trim().startsWith('<') || text.includes('{') || text.includes('function')) {
      // send as text (utf-8)
      res.setHeader('Content-Type', 'text/plain; charset=utf-8');
      return res.send(text);
    }

    // last fallback
    res.setHeader('Content-Type', 'application/octet-stream');
    return res.send(Buffer.from(text, 'utf8'));
  } catch (e) {
    console.error('Resource error', e);
    return res.status(502).send('Upstream error: ' + String(e));
  }
});

app.get('/', (req, res) => {
  res.send('WISP bridge: POST /fetch and GET /resource?url=...');
});

app.listen(PORT, () => {
  console.log(`Bridge listening on http://localhost:${PORT} -> upstream ${WISP_URL}`);
});
