import express from "express";
import fetch from "node-fetch";
import { JSDOM } from "jsdom";
import url from "url";

const app = express();

const PORT = process.env.PORT || 3000;

/* -------------------------------------------------------------------------- */
/*                                GLOBAL CONFIG                               */
/* -------------------------------------------------------------------------- */

// Full Chromium Windows desktop UA (best for Xbox, YouTube, Google)
const DESKTOP_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36";

// resources we **stream**, not DOM-rewrite
const STREAM_TYPES = [
  "image/",
  "audio/",
  "video/",
  "font/",
  "application/octet-stream",
  "application/font-woff",
  "application/font-woff2",
  "application/pdf",
];

// domains that block fetch unless we remove headers
const REMOVE_HEADERS = [
  "content-security-policy",
  "x-frame-options",
  "frame-options",
  "permissions-policy",
];

/* -------------------------------------------------------------------------- */
/*                              MAIN PROXY ROUTE                              */
/* -------------------------------------------------------------------------- */

app.get("/proxy", async (req, res) => {
  let target = req.query.url;

  if (!target) return res.status(400).send("Missing URL: use ?url=https://");

  if (!target.startsWith("http")) target = "https://" + target;
  const parsed = new URL(target);

  try {
    const proxied = await fetch(target, {
      method: "GET",
      headers: {
        "User-Agent": DESKTOP_UA,
        Accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9," +
          "image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        referer: parsed.origin,
      },
      redirect: "follow",
    });

    /* ---------------------------------- HEADERS ---------------------------------- */
    const contentType = proxied.headers.get("content-type") || "";

    // Copy response headers except dangerous ones
    proxied.headers.forEach((v, h) => {
      if (!REMOVE_HEADERS.includes(h.toLowerCase())) {
        res.setHeader(h, v);
      }
    });

    /* ------------------------ STREAM NON-HTML CONTENT ------------------------ */
    if (STREAM_TYPES.some((t) => contentType.startsWith(t))) {
      return proxied.body.pipe(res);
    }

    /* ----------------------------- FETCH HTML TEXT ---------------------------- */
    let html = await proxied.text();

    /* -------------------------------------------------------------------------- */
    /*                        HTML REWRITE (Fix black UI)                         */
    /* -------------------------------------------------------------------------- */

    const dom = new JSDOM(html);
    const doc = dom.window.document;

    // Remove dark-mode forcing
    doc.querySelectorAll('meta[name="color-scheme"]').forEach((m) => m.remove());
    doc.querySelectorAll('*').forEach((el) => {
      if (el.style && el.style.colorScheme) el.style.colorScheme = "";
    });

    // Remove CSP tags
    doc.querySelectorAll("meta[http-equiv='Content-Security-Policy']").forEach((m) => m.remove());

    // Remove Xbox CSP blocks
    doc.querySelectorAll("script").forEach((s) => {
      if (s.textContent && s.textContent.includes("content-security-policy")) {
        s.remove();
      }
    });

    /* -------------------------------- URL REWRITE ------------------------------- */
    const rewriteAttr = (el, attr) => {
      if (!el.hasAttribute(attr)) return;
      const value = el.getAttribute(attr);
      if (!value) return;

      // Ignore javascript:, mailto:
      if (value.startsWith("javascript:") || value.startsWith("mailto:")) return;

      // protocol-relative URLs (//)
      if (value.startsWith("//")) {
        el.setAttribute(attr, `/proxy?url=https:${value}`);
        return;
      }

      // absolute URLs
      if (value.startsWith("http://") || value.startsWith("https://")) {
        el.setAttribute(attr, `/proxy?url=${value}`);
        return;
      }

      // relative URLs
      const newURL = url.resolve(parsed.href, value);
      el.setAttribute(attr, `/proxy?url=${newURL}`);
    };

    // rewrite <a>, <img>, <script>, <link>, <video>, <audio>, etc.
    const ATTRS = ["href", "src", "srcset", "data-src", "data-href", "poster"];

    ATTRS.forEach((attr) => {
      doc.querySelectorAll(`[${attr}]`).forEach((el) => rewriteAttr(el, attr));
    });

    /* ------------------------------- FIX FETCH/XHR ------------------------------ */

    const injectJS = doc.createElement("script");
    injectJS.textContent = `
      (function() {
        const ORIGIN = "${parsed.origin}";
        const PROXY = "${req.protocol}://${req.get("host")}/proxy?url=";

        // Patch fetch
        const oldFetch = window.fetch;
        window.fetch = function(input, opt) {
          let u = input;
          if (typeof input === "string") {
            if (!input.startsWith("http")) {
              u = new URL(input, ORIGIN).href;
            }
            u = PROXY + encodeURIComponent(u);
          }
          return oldFetch(u, opt);
        };

        // Patch XHR
        const XHR = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url) {
          if (!url.startsWith("http")) {
            url = new URL(url, ORIGIN).href;
          }
          url = PROXY + encodeURIComponent(url);
          return XHR.call(this, method, url);
        };
      })();
    `;
    doc.body.appendChild(injectJS);

    /* ----------------------- Return rewritten HTML ---------------------- */
    res.setHeader("content-type", "text/html; charset=utf-8");
    res.send(dom.serialize());
  } catch (e) {
    console.error("Proxy error:", e);
    res.status(500).send("Proxy failed: " + e.message);
  }
});

/* -------------------------------------------------------------------------- */
/*                                HOME REDIRECT                               */
/* -------------------------------------------------------------------------- */

app.get("/", (req, res) => {
  res.redirect("/proxy?url=https://www.google.com");
});

/* -------------------------------------------------------------------------- */
/*                                 START SERVER                               */
/* -------------------------------------------------------------------------- */

app.listen(PORT, () => {
  console.log("Proxy running on port " + PORT);
});