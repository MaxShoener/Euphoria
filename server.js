import express from 'express';
import fetch from 'node-fetch';
import path from 'path';
import NodeCache from 'node-cache';
import { fileURLToPath } from 'url';
import { minify as minifyHtml } from 'html-minifier-terser';
import CleanCSS from 'clean-css';
import * as Terser from 'terser';
import { WebSocketServer } from 'ws';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = process.env.PORT || 8080;

// --- Middleware ---
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const cache = new NodeCache({ stdTTL: 300, checkperiod: 60 });

// JS snippet to rewrite remote URLs
const jsRewriteSnippet = `
<script>
(function(){
    const proxy = '/proxy?url=';
    const originalFetch = window.fetch;
    window.fetch = function(input, init){
        if(typeof input==='string') input=proxy+encodeURIComponent(input);
        else input.url=proxy+encodeURIComponent(input.url);
        return originalFetch(input, init);
    };
    const origXhr = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open=function(method,url,...args){ url=proxy+encodeURIComponent(url); return origXhr.call(this,method,url,...args); };
    const OrigWS=window.WebSocket;
    window.WebSocket=function(url,protocols){ url=proxy+encodeURIComponent(url); return new OrigWS(url,protocols); };
})();
</script>
`;

// Minify content
async function minifyContent(body, contentType){
    try{
        if(contentType.includes('text/html')) return await minifyHtml(body,{collapseWhitespace:true,removeComments:true,minifyJS:true,minifyCSS:true});
        if(contentType.includes('text/css')) return new CleanCSS().minify(body).styles;
        if(contentType.includes('javascript')||contentType.includes('application/x-javascript')){
            const result = await Terser.minify(body);
            return result.code||body;
        }
        return body;
    }catch(err){ console.error(err); return body; }
}

// Rewrite relative URLs
function rewriteAssets(body, baseUrl){
    return body
        .replace(/(href|src)=["'](?!\/)([^"']+)["']/g,(m,attr,link)=>{
            const fullUrl=new URL(link,baseUrl).href;
            return `${attr}="/proxy?url=${encodeURIComponent(fullUrl)}"`;
        })
        .replace(/url\(["']?(?!\/)([^"')]+)["']?\)/g,(m,link)=>{
            const fullUrl=new URL(link,baseUrl).href;
            return `url("/proxy?url=${encodeURIComponent(fullUrl)}")`;
        });
}

// --- Proxy route ---
app.get('/proxy', async (req,res)=>{
    const url = req.query.url;
    if(!url) return res.status(400).send('Missing URL');

    try{
        const cached = cache.get(url);
        const headers = cached?.etag ? { 'If-None-Match': cached.etag } : {};
        const response = await fetch(url, { headers:{...headers, 'X-Euphoria':'true'} });

        if(response.status===304 && cached){
            res.set('Content-Type', cached.contentType);
            return res.send(cached.body);
        }

        const contentType = response.headers.get('content-type') || '';
        const etag = response.headers.get('etag') || null;

        if(contentType.includes('text') || contentType.includes('javascript') || contentType.includes('css')){
            let body = await response.text();
            if(contentType.includes('text/html')){
                body = rewriteAssets(body,url);
                body = body.replace('</body>',`${jsRewriteSnippet}</body>`);
            } else if(contentType.includes('text/css')){
                body = rewriteAssets(body,url);
            }
            body = await minifyContent(body,contentType);
            cache.set(url,{body,contentType,etag});
            res.set('Content-Type',contentType);
            res.send(body);
        } else {
            const buffer = await response.arrayBuffer();
            const data = Buffer.from(buffer);
            cache.set(url,{body:data,contentType,etag});
            res.set('Content-Type',contentType);
            res.send(data);
        }

    } catch(err){
        res.status(500).send(`Proxy error: ${err.message}`);
    }
});

// --- SPA fallback ---
app.get('*', (req,res)=>{
    res.sendFile(path.resolve(__dirname,'public','index.html'));
});

// --- WebSocket ---
const server = app.listen(PORT,()=>console.log(`Euphoria running on port ${PORT}`));
const wss = new WebSocketServer({server});
wss.on('connection', ws => ws.send(JSON.stringify({message:'Welcome to Euphoria WebSocket!'})));