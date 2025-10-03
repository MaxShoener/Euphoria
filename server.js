import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { HttpClient } from '@ultraviolet/http';
import { DataStream } from 'scramjet';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Serve frontend files
app.use(express.static(__dirname));

// API endpoint using Ultraviolet + Scramjet
app.get('/api', async (req, res) => {
  const targetUrl = req.query.url;
  if (!targetUrl) return res.status(400).json({ error: 'Missing URL parameter' });

  try {
    // Ultraviolet fetch
    const client = new HttpClient();
    const response = await client.get(targetUrl);

    // Scramjet stream for processing response body line by line
    const textStream = new DataStream.StringStream(await response.text());
    const processed = await textStream
      .lines()
      .map(line => line.trim())
      .filter(line => line.length > 0)
      .toArray();

    res.json({ url: targetUrl, data: processed });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fallback route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));