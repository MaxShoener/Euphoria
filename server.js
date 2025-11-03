// server.js
// Euphoria proxy - streams proxied responses using scramjet
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const { DataStream } = require('scramjet');
const { fetch } = require('undici');

const app = express();
const PORT = process.env.PORT || 3000;

// Basic middleware
app.use(helmet());
app.use(morgan('tiny'));
app.use(cors()); // allow frontend to call. In production restrict origins!
app.use(express.static('public')); // serves euphoria.html

// NOTE: We don't use body-parsing middleware for /stream-proxy because we want to
// stream raw request bodies when present. For JSON/FORM calls the frontend will send JSON.
// But we will support both query-based and JSON-body requests.

// Helper to parse small JSON config bodies
app.use('/proxy', express.json({ limit: '2mb' }));

/**
 * POST /proxy
 * Accepts JSON body:
 * {
 *   "url": "https://example.com/path",
 *   "method": "GET",
 *   "headers": { "Accept": "text/html" }
 * }
 *
 * Or you can call with query parameters (GET) but POST recommended for body forwarding.
 *
 * This implementation streams the upstream response back to the client using scramjet.
 */
app.post('/proxy', async (req, res) => {
  try {
    // Obtain config either from JSON body or query params
    const conf = req.body && Object.keys(req.body).length ? req.body : req.query || {};
    const targetUrl = conf.url;
    if (!targetUrl) {
      return res.status(400).json({ error: 'Missing url parameter in body or query' });
    }

    const method = (conf.method || 'GET').toUpperCase();
    const headers = conf.headers || {};

    // If method typically includes body and the user included `forwardBody: true`,
    // forward the incoming request body stream; otherwise, use any supplied body in conf.body
    let upstreamBody = null;
    if (conf.forwardBody) {
      // forward the raw incoming request stream (express req is a readable stream)
      upstreamBody = req;
    } else if (conf.body) {
      // if a JSON/string body present in the config, use it
      if (typeof conf.body === 'object') {
        upstreamBody = JSON.stringify(conf.body);
        headers['content-type'] = headers['content-type'] || 'application/json';
      } else {
        upstreamBody = String(conf.body);
      }
    }

    // Start the fetch to the target
    const fetchOptions = {
      method,
      headers,
      body: upstreamBody
    };

    const upstreamResp = await fetch(targetUrl, fetchOptions);

    // Copy status and headers (remove hop-by-hop headers)
    res.statusMessage = upstreamResp.statusText || '';
    res.status(upstreamResp.status);

    // copy headers but avoid 'transfer-encoding' and other hop-by-hop headers
    const hopByHop = new Set([
      'connection',
      'keep-alive',
      'proxy-authenticate',
      'proxy-authorization',
      'te',
      'trailers',
      'transfer-encoding',
      'upgrade'
    ]);
    for (const [k, v] of upstreamResp.headers) {
      if (!hopByHop.has(k.toLowerCase())) {
        res.setHeader(k, v);
      }
    }

    // Upstream's body is a Node-readable stream via undici => stream.pipe works.
    // Use scramjet to create a stream pipeline (we use DataStream.fromReadable)
    // and pipe into the express response. This demonstrates scramjet usage and lets
    // us process bytes if needed (e.g., logging, transformation).
    if (upstreamResp.body) {
      const upstreamNodeStream = upstreamResp.body; // undici returns a Node stream
      // Wrap it with Scramjet
      const ds = DataStream.fromReadable(upstreamNodeStream);
      // You can .map or .consume to transform; here we directly pipe chunks unmodified
      ds.pipe(res);
      // When the scramjet stream finishes, the res will also finish.
      ds.on('error', (err) => {
        console.error('Scramjet stream error:', err);
        try { res.end(); } catch (e) {}
      });
    } else {
      // No body — just end
      res.end();
    }

  } catch (err) {
    console.error('Proxy error:', err);
    if (!res.headersSent) {
      res.status(502).json({ error: 'Upstream fetch failed', details: String(err) });
    } else {
      try { res.end(); } catch (e) {}
    }
  }
});

// Small health endpoint
app.get('/health', (req, res) => res.json({ ok: true, name: 'euphoria' }));

app.listen(PORT, () => {
  console.log(`Euphoria proxy listening on http://localhost:${PORT}`);
  console.log(`Frontend (downloadable) available at http://localhost:${PORT}/euphoria.html`);
});