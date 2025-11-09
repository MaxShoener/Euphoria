// server.js ~500 lines
import express from "express";
import fetch from "node-fetch";
import pkg from "scramjet";
const { DataStream } = pkg;
import LRU from "lru-cache";
import { parse } from "node-html-parser";
import compression from "compression";
import { URL } from "url";
import path from "path";

const app = express();
const PORT = process.env.PORT || 3000;

// ----- CACHE SETUP -----
const cache = new LRU({
    max: 100, // max number of cached items
    ttl: 1000 * 60 * 10, // 10 min cache
});

// ----- MIDDLEWARE -----
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(compression());

// ----- SESSION HISTORY -----
const sessions = new Map(); // Map<sessionId, {history: [], index: number}>

// ----- UTILITIES -----
function cleanHtml(html) {
    // remove Google analytics, GTM, Doubleclick, etc
    html = html.replace(/<script[^>]+(analytics|gtag|googletagmanager|doubleclick|googlesyndication)[^>]*>[\s\S]*?<\/script>/gi, "");
    // remove meta refresh
    html = html.replace(/<meta[^>]+http-equiv=["']refresh["'][^>]*>/gi, "");
    return html;
}

function rewriteLinks(html, baseUrl) {
    const root = parse(html);
    root.querySelectorAll("a,link,script,img").forEach((el) => {
        let attr = "href";
        if (el.tagName === "SCRIPT" || el.tagName === "IMG") attr = "src";
        const val = el.getAttribute(attr);
        if (!val) return;
        try {
            const newUrl = new URL(val, baseUrl).toString();
            el.setAttribute(attr, `/proxy?url=${encodeURIComponent(newUrl)}`);
        } catch (e) {}
    });
    return root.toString();
}

function getSession(req) {
    let id = req.headers["x-session-id"];
    if (!id) {
        id = Math.random().toString(36).substring(2);
    }
    if (!sessions.has(id)) {
        sessions.set(id, { history: [], index: -1 });
    }
    return { id, ...sessions.get(id) };
}

// ----- ROUTES -----
app.get("/", (req, res) => {
    res.sendFile(path.join(process.cwd(), "index.html"));
});

// proxy GET requests
app.get("/proxy", async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).send("Missing url");
    const cacheKey = url;
    if (cache.has(cacheKey)) {
        console.log(`CACHE HIT: ${url}`);
        return res.send(cache.get(cacheKey));
    }
    try {
        const response = await fetch(url);
        const contentType = response.headers.get("content-type");
        let body = await response.text();
        if (contentType && contentType.includes("text/html")) {
            body = cleanHtml(body);
            body = rewriteLinks(body, url);
        }
        cache.set(cacheKey, body);
        res.send(body);
    } catch (err) {
        console.error(err);
        res.status(500).send("Failed to load page");
    }
});

// Autocomplete route
app.get("/autocomplete", async (req, res) => {
    const { q } = req.query;
    if (!q) return res.json([]);
    // simple Google suggest API
    try {
        const r = await fetch(`https://suggestqueries.google.com/complete/search?client=firefox&q=${encodeURIComponent(q)}`);
        const data = await r.json();
        res.json(data[1].slice(0, 10));
    } catch (e) {
        console.error(e);
        res.json([]);
    }
});

// navigation buttons
app.post("/nav", (req, res) => {
    const { sessionId, action, currentUrl } = req.body;
    if (!sessionId || !action) return res.status(400).send("Missing params");
    const session = sessions.get(sessionId);
    if (!session) return res.status(400).send("Invalid session");
    if (action === "push") {
        session.history = session.history.slice(0, session.index + 1);
        session.history.push(currentUrl);
        session.index++;
    } else if (action === "back") {
        if (session.index > 0) session.index--;
    } else if (action === "forward") {
        if (session.index < session.history.length - 1) session.index++;
    } else if (action === "home") {
        session.history = [currentUrl];
        session.index = 0;
    }
    sessions.set(sessionId, session);
    res.json({ current: session.history[session.index] });
});

// ----- STATIC RESOURCES -----
app.use("/static", express.static(path.join(process.cwd(), "static")));

// ----- CHUNKED STREAMING -----
async function streamProxy(url, res) {
    const r = await fetch(url);
    res.setHeader("content-type", r.headers.get("content-type") || "text/html");
    const ds = new DataStream(r.body);
    ds.map(chunk => chunk.toString())
      .map(chunk => cleanHtml(chunk))
      .forEach(chunk => res.write(chunk))
      .finally(() => res.end());
}

// ----- ERROR HANDLING -----
app.use((req, res) => {
    res.status(404).send("Not Found");
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send("Internal Server Error");
});

// ----- START SERVER -----
app.listen(PORT, () => {
    console.log(`Proxy server running on port ${PORT}`);
});

// ----- KEEP-ALIVE PING -----
setInterval(() => {
    console.log("Server alive check");
}, 5 * 60 * 1000);

// ----- OPTIONAL: LOG METRICS -----
setInterval(() => {
    console.log(`Cache size: ${cache.size}, Sessions: ${sessions.size}`);
}, 60 * 1000);

// ----- ADVANCED SCRAMJET STREAMING EXAMPLE -----
app.get("/stream", async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).send("Missing url");
    try {
        await streamProxy(url, res);
    } catch (e) {
        console.error(e);
        res.status(500).send("Stream failed");
    }
});

// ----- HISTORY CLEANUP -----
setInterval(() => {
    for (const [id, session] of sessions.entries()) {
        if (session.history.length > 100) {
            session.history = session.history.slice(-50);
            session.index = Math.min(session.index, session.history.length - 1);
        }
    }
}, 10 * 60 * 1000);

// ----- SIMPLE AUTOFILL CACHE -----
const autofillCache = new Map();
app.get("/autofill", (req, res) => {
    const { q } = req.query;
    if (!q) return res.json([]);
    if (autofillCache.has(q)) return res.json(autofillCache.get(q));
    const suggestions = Array.from({length:5}, (_,i) => `${q} suggestion ${i+1}`);
    autofillCache.set(q, suggestions);
    res.json(suggestions);
});
