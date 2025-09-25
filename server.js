/**
 * Minimal HTTP -> WebSocket bridge for wss://wisp.mercurywork.shop/
 * Usage:
 * 1. npm install
 * 2. node server.js
 *
 * POST /fetch
 * Body JSON: { "url": "https://example.com", "template": "fetch_action" }
 *
 * The bridge opens a WebSocket to the WISP upstream, sends a payload (adaptable),
 * waits for a response (or times out), and returns that response.
 *
 * IMPORTANT: This example is educational. You are responsible for legal use,
 * CORS, input validation, and securing credentials in production.
 */
const express = require('express');
const WebSocket = require('ws');
const bodyParser = require('body-parser');

const WISP_URL = process.env.WISP_URL || 'wss://wisp.mercurywork.shop/';
const PORT = process.env.PORT || 3000;
const WS_TIMEOUT_MS = 20000;

const app = express();
app.use(bodyParser.json({limit: '1mb'}));

// Simple CORS for development; tighten in production.
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
  // fallback: send raw URL string
  return url;
}

app.post('/fetch', async (req, res) => {
  const { url, template } = req.body || {};
  if (!url) return res.status(400).json({ error: 'Missing url in request body' });

  const payload = buildPayload(template || 'fetch_action', url);

  let ws;
  try {
    ws = new WebSocket(WISP_URL);
  } catch (err) {
    return res.status(502).json({ error: 'Failed to create WebSocket: ' + String(err) });
  }

  const timeout = setTimeout(() => {
    try { ws.terminate(); } catch(e){}
    return res.status(504).json({ error: 'Timeout waiting for upstream response' });
  }, WS_TIMEOUT_MS);

  ws.on('open', () => {
    try {
      ws.send(payload);
    } catch (e) {
      clearTimeout(timeout);
      ws.close();
      return res.status(500).json({ error: 'Failed to send payload: ' + String(e) });
    }
  });

  ws.on('message', (data) => {
    clearTimeout(timeout);
    // Try to parse as JSON
    let parsed = null;
    try {
      parsed = JSON.parse(data.toString());
    } catch (e) {
      // not JSON
    }
    // Close ws gracefully
    try { ws.close(); } catch(e){}
    // Return raw data if not JSON; otherwise JSON
    if (parsed) return res.json({ raw: data.toString(), parsed });
    return res.type('text').send(data.toString());
  });

  ws.on('error', (err) => {
    clearTimeout(timeout);
    try { ws.close(); } catch(e){}
    return res.status(502).json({ error: 'WebSocket error: ' + String(err) });
  });

  ws.on('close', (code, reason) => {
    // If closed before we sent/received, ensure we reply
    // Note: close handler might run after message; safe-guarded by checks above
    // Do nothing here.
  });
});

app.get('/', (req, res) => {
  res.send('WISP HTTP->WS bridge. POST /fetch with JSON {url, template}.');
});

app.listen(PORT, () => {
  console.log(`Bridge listening on http://localhost:${PORT}  -> upstream ${WISP_URL}`);
});
