const express = require('express');
const path = require('path');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// Serve frontend files
app.use(express.static(__dirname));

// Proxy route to backend
app.get('/api', async (req, res) => {
  try {
    // Replace with your backend website URL
    const backendUrl = 'https://example.com/api';
    const response = await fetch(backendUrl);
    const data = await response.json();

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fallback route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));