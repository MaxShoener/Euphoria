import express from 'express';
import fetch from 'node-fetch';
import pkg from 'scramjet';
const { StringStream } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

// Serve frontend
app.use('/', express.static('public')); // index.html in ./public

app.get('/proxy', async (req, res) => {
    const targetURL = req.query.url;
    if(!targetURL) return res.status(400).send("Missing 'url' query parameter");

    try {
        const response = await fetch(targetURL, {
            redirect: 'manual',
            headers: { 
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' 
            }
        });

        // Handle HTTP redirects
        if(response.status >= 300 && response.status < 400 && response.headers.get('location')) {
            const redirectURL = new URL(response.headers.get('location'), targetURL).href;
            return res.redirect(`/proxy?url=${encodeURIComponent(redirectURL)}`);
        }

        const contentType = response.headers.get('content-type') || '';
        res.set('content-type', contentType);

        if(contentType.includes('text/html')) {
            let text = await response.text();

            // Rewrite href/src only if not already rewritten
            text = text.replace(
                /(href|src)=["'](.*?)["']/gi,
                (match, attr, url) => {
                    if(url.startsWith('javascript:') || url.startsWith('/proxy?url=')) return match;
                    try {
                        const absolute = new URL(url, targetURL).href;
                        return `${attr}="/proxy?url=${encodeURIComponent(absolute)}"`;
                    } catch {
                        return match;
                    }
                }
            );

            StringStream.from(text).pipe(res).on('end', () => res.end());
        } else {
            const buffer = await response.arrayBuffer();
            res.send(Buffer.from(buffer));
        }

    } catch(err) {
        console.error('Proxy error:', err);
        res.status(500).send('Proxy error: ' + err.message);
    }
});

app.listen(PORT, () => console.log(`Euphoria proxy running on port ${PORT}`));
