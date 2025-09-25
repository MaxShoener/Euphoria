# WISP Ultimate Transparent Proxy

This repository hosts a **fully client-side, transparent proxy** using WISP (`wss://wisp.mercurywork.shop/`) for GitHub Pages. It can proxy almost any website, including:  

- GET/POST forms  
- AJAX/fetch/XHR requests  
- WebSockets (even dynamically created)  
- Inline and external CSS (`url(...)` and `@import`)  
- All static resources (images, scripts, videos, audio, iframes)  
- Inline and dynamically generated JavaScript URLs  

---

## Getting Started

Follow these steps to deploy the proxy on GitHub Pages:

1. **Clone or download this repository**:

```bash
git clone https://github.com/<your-username>/<repository-name>.git
```

2. **Remove any unnecessary files**:  
   - Delete `package.json` or `server.js` if present — GitHub Pages only serves static files.  

3. **Push the repository to GitHub** (if you cloned locally):

```bash
cd <repository-name>
git add .
git commit -m "Initial WISP proxy setup"
git push origin main
```

4. **Enable GitHub Pages**:  
   - Go to your repository on GitHub → **Settings → Pages**.  
   - Under **Source**, select your branch (`main` or `master`) and folder `/root`.  
   - Click **Save**.  

5. **Open the proxy**:  
   - After a few moments, GitHub Pages will provide a URL like:

```
https://<your-username>.github.io/<repository-name>/
```

   - Open it in your browser. Enter the URL of the site you want to access and click **Go**.  

---

## Repository Structure

```
my-wisp-proxy/
│
├─ index.html       ← The complete WISP proxy HTML (client-side only)
├─ README.md        ← This file
└─ (optional assets)
```

> Only `index.html` is required. All functionality is client-side; no Node.js backend is needed.

---

## Notes

- All network requests are routed through the WISP WebSocket server (`wss://wisp.mercurywork.shop/`).  
- Works with dynamic pages, SPAs, WebSockets, and CSS/JS resources.  
- Some extremely dynamic or protected sites may require minor tweaks.  

---

## License

This repository is open for personal or educational use. Redistribution and modification are allowed under MIT license terms.
