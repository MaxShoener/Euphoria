import express from "express";
import fetch from "node-fetch";
import pkg from "scramjet";
const { StringStream } = pkg;

const app = express();
const PORT = process.env.PORT || 3000;

// Serve minimal sleek UI
app.get("/", (req, res) => {
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Euphoria Proxy</title>
<style>
  body {
    margin: 0;
    background: #0f0f0f;
    color: white;
    font-family: "Inter", sans-serif;
    display: flex;
    flex-direction: column;
    height: 100vh;
  }
  #topbar {
    display: flex;
    align-items: center;
    gap: 6px;
    background: #181818;
    padding: 10px;
    border-bottom: 1px solid #2a2a2a;
  }
  button {
    background: #222;
    color: white;
    border: none;
    padding: 8px 12px;
    border-radius: 8px;
    cursor: pointer;
    transition: background 0.2s;
  }
  button:hover { background: #333; }
  #url {
    flex: 1;
    padding: 8px 12px;
    border-radius: 8px;
    border: none;
    outline: none;
    background: #101010;
    color: white;
  }
  iframe {
    flex: 1;
    border: none;
    width: 100%;
  }
  #spinner {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    border: 5px solid #333;
    border-top: 5px solid #fff;
    border-radius: 50%;
    width: 40px;
    height: 40px;
    animation: spin 0.9s linear infinite;
    display: none;
  }
  @keyframes spin {
    0% { transform: translate(-50%, -50%) rotate(0deg); }
    100% { transform: translate(-50%, -50%) rotate(360deg); }
  }
</style>
</head>
<body>
  <div id="topbar">
    <button id="back">←</button>
    <button id="forward">→</button>
    <button id="refresh">⟳</button>
    <input id="url" type="text" placeholder="Enter a URL or search" />
    <button id="go">Go</button>
    <button id="home">🏠</button>
    <button id="fullscreen">⛶</button>
  </div>
  <div id="spinner"></div>
  <iframe id="view" src=""></iframe>
  <script>
    const iframe = document.getElementById("view");
    const urlInput = document.getElementById("url");
    const spinner = document.getElementById("spinner");
    let historyStack = [], currentIndex = -1;

    function showSpinner(show) {
      spinner.style.display = show ? "block" : "none";
    }

    function navigate(raw) {
      if (!raw) return;
      let url = raw.trim();
      if (!url.includes(".")) url = "https://www.google.com/search?q=" + encodeURIComponent(url);
      else if (!url.startsWith("http")) url = "https://" + url;
      const proxy = "/proxy?url=" + encodeURIComponent(url);
      iframe.src = proxy;
      showSpinner(true);
      historyStack = historyStack.slice(0, currentIndex + 1);
      historyStack.push(url);
      currentIndex++;
    }

    iframe.addEventListener("load", () => showSpinner(false));

    document.getElementById("go").onclick = () => navigate(urlInput.value);
    urlInput.addEventListener("keydown", e => {
      if (e.key === "Enter") navigate(urlInput.value);
    });

    document.getElementById("home").onclick = () => {
      urlInput.value = "google.com";
      navigate("google.com");
    };
    document.getElementById("refresh").onclick = () => iframe.contentWindow.location.reload();
    document.getElementById("back").onclick = () => {
      if (currentIndex > 0) {
        currentIndex--;
        navigate(historyStack[currentIndex]);
      }
    };
    document.getElementById("forward").onclick = () => {
      if (currentIndex < historyStack.length - 1) {
        currentIndex++;
        navigate(historyStack[currentIndex]);
      }
    };

    const fsBtn = document.getElementById("fullscreen");
    fsBtn.onclick = () => {
      if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen();
        fsBtn.textContent = "❎";
      } else {
        document.exitFullscreen();
        fsBtn.textContent = "⛶";
      }
    };

    navigate("google.com");
  </script>
</body>
</html>
  `);
});

// Proxy stream handler
app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send("Missing 'url'");

  try {
    const response = await fetch(target, {
      headers: { "User-Agent": "Mozilla/5.0 (Euphoria Browser)" },
      redirect: "manual"
    });

    if (response.status >= 300 && response.status < 400 && response.headers.get("location")) {
      const redirectURL = new URL(response.headers.get("location"), target).href;
      return res.redirect(`/proxy?url=${encodeURIComponent(redirectURL)}`);
    }

    const contentType = response.headers.get("content-type") || "";
    res.set("content-type", contentType);

    if (contentType.includes("text/html")) {
      let html = await response.text();

      // Rewrite URLs
      html = html.replace(
        /(href|src)=["'](.*?)["']/gi,
        (match, attr, link) => {
          if (link.startsWith("javascript:")) return match;
          try {
            const abs = new URL(link, target).href;
            return `${attr}="/proxy?url=${encodeURIComponent(abs)}"`;
          } catch {
            return match;
          }
        }
      );

      StringStream.from(html).pipe(res);
    } else {
      response.body.pipe(res);
    }
  } catch (err) {
    console.error("Proxy error:", err);
    res.status(500).send("Error loading page.");
  }
});

app.listen(PORT, () => console.log(`✨ Euphoria running on port ${PORT}`));
