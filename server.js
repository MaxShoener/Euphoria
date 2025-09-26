const express = require('express');
const { chromium } = require('playwright');
const fetch = require('node-fetch'); // optional, in case you need it
const app = express();

const PORT = process.env.PORT || 10000;

// Parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));

// Proxy route
app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  if (!target) return res.status(400).send('Missing URL parameter');

  let browser;
  try {
    // Launch Chromium headless
    browser = await chromium.launch({
      args: ['--no-sandbox', '--disable-setuid-sandbox']
    });

    const context = await browser.newContext();
    const page = await context.newPage();

    await page.goto(target, { waitUntil: 'networkidle' });

    const content = await page.content();
    res.send(content);
  } catch (err) {
    console.error(err);
    res.status(500).send(`Error loading ${target}: ${err.message}`);
  } finally {
    if (browser) await browser.close();
  }
});

app.listen(PORT, () => console.log(`Euphoria proxy running on port ${PORT}`));