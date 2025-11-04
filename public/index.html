<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Euphoria Proxy</title>
  <style>
    body { margin: 0; font-family: Arial, sans-serif; background: #f0f0f0; }
    #top-bar {
      display: flex;
      align-items: center;
      padding: 8px 12px;
      background: #222;
      color: white;
      border-radius: 12px;
      margin: 10px;
    }
    #top-bar input {
      flex: 1;
      margin: 0 8px;
      padding: 6px 10px;
      border-radius: 8px;
      border: none;
      background: #333;
      color: white;
    }
    #top-bar button {
      padding: 6px 12px;
      border-radius: 8px;
      border: none;
      background: #555;
      color: white;
      cursor: pointer;
      margin-left: 4px;
    }
    #spinner {
      display: none;
      position: absolute;
      top: 50%; left: 50%;
      transform: translate(-50%, -50%);
      border: 8px solid #f3f3f3;
      border-top: 8px solid #555;
      border-radius: 50%;
      width: 60px;
      height: 60px;
      animation: spin 1s linear infinite;
      z-index: 999;
    }
    @keyframes spin { 100% { transform: rotate(360deg); } }
    #content {
      margin: 0;
      padding: 0;
      width: 100%;
      height: calc(100vh - 60px);
      overflow: hidden;
    }
    iframe {
      width: 100%;
      height: 100%;
      border: none;
    }
  </style>
</head>
<body>
  <div id="top-bar">
    <button id="home">Home</button>
    <input type="text" id="url-input" placeholder="Enter URL..." />
    <button id="go">Go</button>
    <button id="fullscreen">Fullscreen</button>
  </div>

  <div id="spinner"></div>
  <div id="content"></div>

  <script>
    const spinner = document.getElementById("spinner");
    const content = document.getElementById("content");
    const input = document.getElementById("url-input");

    const showSpinner = () => spinner.style.display = "block";
    const hideSpinner = () => spinner.style.display = "none";

    async function loadURL(url) {
      showSpinner();
      try {
        const res = await fetch(`/fetch?url=${encodeURIComponent(url)}`);
        const html = await res.text();
        content.innerHTML = html;
      } catch (e) {
        content.innerHTML = "<h1 style='text-align:center;margin-top:50px;'>Error loading page</h1>";
      }
      hideSpinner();
    }

    document.getElementById("go").addEventListener("click", () => {
      loadURL(input.value);
    });

    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") loadURL(input.value);
    });

    document.getElementById("home").addEventListener("click", () => {
      input.value = "https://www.google.com";
      loadURL(input.value);
    });

    document.getElementById("fullscreen").addEventListener("click", () => {
      if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen();
      } else {
        document.exitFullscreen();
      }
    });

    // Load Google by default
    loadURL("https://www.google.com");
  </script>
</body>
</html>
