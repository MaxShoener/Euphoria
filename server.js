const path = require('path');
const express = require('express');
const fetch = require('node-fetch');
const puppeteer = require('puppeteer');

const app = express();
const PORT = process.env.PORT || 10000;

// Serve static frontend files
app.use(express.static(path.join(__dirname)));

// Proxy endpoint using Puppeteer
app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send('No URL provided');

  try {
    const browser = await puppeteer.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(url, { waitUntil: 'networkidle2' });
    const content = await page.content();
    await browser.close();
    res.send(content);
  } catch (err) {
    res.status(500).send(err.toString());
  }
});

app.listen(PORT, () => {
  console.log(`Euphoria proxy running on port ${PORT}`);
});
