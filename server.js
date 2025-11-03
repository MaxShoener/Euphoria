import express from 'express';
import fetch from 'node-fetch';
const app = express();

app.get('/proxy', async (req, res) => {
    const targetURL = req.query.url;
    if(!targetURL) return res.status(400).send("Missing url");

    try {
        const response = await fetch(targetURL, { redirect: 'manual' });
        if(response.status >= 300 && response.status < 400 && response.headers.get('location')) {
            // Follow redirect through proxy
            return res.redirect(`/proxy?url=${encodeURIComponent(new URL(response.headers.get('location'), targetURL).href)}`);
        }
        const body = await response.text();
        res.send(body);
    } catch(err) {
        res.status(500).send("Proxy error: " + err.message);
    }
});

app.listen(3000, () => console.log("Proxy running on port 3000"));
