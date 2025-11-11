import express from 'express';
import fetch from 'node-fetch';
import cors from 'cors';
import compression from 'compression';
import path from 'path';
import { fileURLToPath } from 'url';
import NodeCache from 'node-cache';
import { WebSocketServer } from 'ws';
import { minify as minifyHtml } from 'html-minifier-terser';
import CleanCSS from 'clean-css';
import Terser from 'terser';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

// --- Middleware ---
app.use(cors());
app.use(compression());
app.use(express.json());

// --- Cache ---
const cache = new NodeCache({ stdTTL: 300, checkperiod: 60 });

// --- JS rewriting snippet ---
const jsRewriteSnippet = `
<script>
(function(){
    const proxy = '/proxy?url=';
    function rewriteUrl(url, base) {
        try {
            if (!url) return url;
            const u = new URL(url, base);
            return '/proxy?url=' + encodeURIComponent(u.href);
        } catch(e) { return url; }
    }
    const originalFetch = window.fetch;
    window.fetch = function(input, init){
        if (typeof input === 'string') input = rewriteUrl(input, location.href);
        else input.url = rewriteUrl(input.url, location.href);
        return originalFetch(input, init);
    };
    const originalXhrOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, async, user, pass){
        url = rewriteUrl(url, location.href);
        return originalXhrOpen.call(this, method, url, async, user, pass);
    };
    const OriginalWS = window.WebSocket;
    window.WebSocket = function(url, protocols){
        url = rewriteUrl(url, location.href);
        return new OriginalWS(url, protocols);
    };
})();
</script>
`;

// --- Helper: rewrite HTML/CSS assets ---
function rewriteAssets(body, baseUrl) {
    // Rewrite HTML links and resources
    body = body.replace(/(href|src)=["'](?!http)([^"']+)["']/g, (m, attr, link) => {
        const fullUrl = new URL(link, baseUrl).href;
        return `${attr}="/proxy?url=${encodeURIComponent(fullUrl)}"`;
    });

    // Rewrite CSS url() references
    body = body.replace(/url\(["']?(?!http)([^"')]+)["']?\)/g, (m, link) => {
        const fullUrl = new URL(link, baseUrl).href;
        return `url("/proxy?url=${encodeURIComponent(fullUrl)}")`;
    });

    return body;
}

// --- Minify HTML, JS, CSS ---
async function minifyContent(body, contentType) {
    try {
        if (contentType.includes('text/html')) {
            return await minifyHtml(body, {
                collapseWhitespace: true,
                removeComments: true,
                minifyJS: true,
                minifyCSS: true
            });
        } else if (contentType.includes('text/css')) {
            return new CleanCSS().minify(body).styles;
        } else if (contentType.includes('javascript') || contentType.includes('application/x-javascript')) {
            const result = await Terser.minify(body);
            return result.code || body;
        }
        return body;
    } catch (err) {
        console.error('Minification error:', err);
        return body; // fallback
    }
}

// --- Proxy Route with smart caching and minification ---
app.get('/proxy', async (req, res) => {
    const url = req.query.url;
    if (!url) return res.status(400).send('Missing URL parameter');

    const cached = cache.get(url);
    const headers = cached?.etag ? { 'If-None-Match': cached.etag } : {};
    try {
        const response = await fetch(url, { headers: { ...headers, 'X-Euphoria': 'true' } });

        // 304 Not Modified: serve cache
        if (response.status === 304 && cached) {
            res.set('Content-Type', cached.contentType);
            return res.send(cached.body);
        }

        let body = await response.text();
        const contentType = response.headers.get('content-type') || '';
        const etag = response.headers.get('etag') || null;

        // Rewrite assets and inject JS snippet
        if (contentType.includes('text/html')) {
            body = rewriteAssets(body, url);
            body = body.replace('</body>', `${jsRewriteSnippet}</body>`);
        } else if (contentType.includes('text/css')) {
            body = rewriteAssets(body, url);
        }

        // Minify
        body = await minifyContent(body, contentType);

        // Cache with ETag
        cache.set(url, { body, contentType, etag });

        res.set('Content-Type', contentType);
        res.send(body);

    } catch (err) {
        res.status(500).send(`Proxy error: ${err.message}`);
    }
});

// --- SPA / static fallback ---
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// --- WebSocket Server ---
const server = app.listen(PORT, () => console.log(`Euphoria running on port ${PORT}`));
const wss = new WebSocketServer({ server });
wss.on('connection', ws => ws.send(JSON.stringify({ message: 'Welcome to Euphoria WebSocket!' })));