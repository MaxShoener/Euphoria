import express from "express";
import fetch from "node-fetch";
import cookieParser from "cookie-parser";
import { DataStream } from "scramjet";
import LRU from "lru-cache";

const app = express();
const port = process.env.PORT || 3000;

app.use(cookieParser());
app.use(express.static("public"));

const cache = new LRU({ max: 50, ttl: 1000 * 60 * 5 }); // cache 5 mins

app.get("/proxy", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send("Missing url parameter");

  if (cache.has(url)) {
    return res.send(cache.get(url));
  }

  try {
    const response = await fetch(url);
    const html = await response.text();

    // Stream and rewrite links to pass through proxy
    const processed = await new DataStream(html)
      .map(line =>
        line
          .replace(/href="\/?/g, 'href="/proxy?url=' + encodeURIComponent(url) + '/')
          .replace(/src="\/?/g, 'src="/proxy?url=' + encodeURIComponent(url) + '/')
      )
      .reduce("", (acc, val) => acc + val);

    cache.set(url, processed);
    res.send(processed);
  } catch (err) {
    console.error(err);
    res.status(500).send("Failed to fetch site");
  }
});

app.listen(port, () => {
  console.log(`Proxy running at http://localhost:${port}`);
});
