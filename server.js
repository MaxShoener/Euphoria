import express from 'express';
import fetch from 'node-fetch';
import pkg from 'scramjet';
const { StringStream } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

// Serve frontend
app.use('/', express.static('public')); // assuming index.html is in ./public

// Proxy endpoint
app.get('/proxy', async (req, res) => {
    const targetURL = req.query.url;
    if(!targetURL) return res.status(400).send("Missing 'url' query parameter");

    try {
        const response = await fetch(targetURL, { redirect: 'manual' });

        // Handle HTTP redirects
        if(response.status >= 300 && response.status < 400 && response.headers.get('location')) {
            const redirectURL = new URL(response.headers.get('location'), targetURL).href;
            return res.redirect(`/proxy?url=${encodeURIComponent(redirectURL)}`);
        }

        const contentType = response.headers.get('content-type') || '';
        res.set('content-type', contentType);

        // Only stream text/html through Scramjet
        if(contentType.includes('text/html')) {
            const text = await response.text();
            // Rewrite all href/src attributes to pass through proxy
            const rewritten = text.replace(
                /(href|src)=["'](.*?)["']/gi,
                (match, attr, url) => {
                    if(url.startsWith('javascript:')) return match;
                    try {
                        const absolute = new URL(url, targetURL).href;
                        return `${attr}="/proxy?url=${encodeURIComponent(absolute)}"`;
                    } catch {
                        return match;
                    }
                }
            );
            // Stream rewritten HTML
            StringStream.from(rewritten).pipe(res);
        } else {
            // Stream non-HTML (images, scripts, etc.) directly
            const arrayBuffer = await response.arrayBuffer();
            res.send(Buffer.from(arrayBuffer));
        }

    } catch(err) {
        console.error('Proxy error:', err);
        res.status(500).send('Proxy error: ' + err.message);
    }
});

app.listen(PORT, () => console.log(`Euphoria proxy running on port ${PORT}`));
