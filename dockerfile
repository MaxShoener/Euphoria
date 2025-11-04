FROM node:20-bullseye

# Install Chromium and dependencies
RUN apt-get update && apt-get install -y \
    chromium \
    ca-certificates \
    fonts-liberation \
    libx11-6 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxrender1 \
    libxss1 \
    libxtst6 \
    libnss3 \
    libglib2.0-0 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    libasound2 \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package.json & package-lock.json
COPY package*.json ./

# Use puppeteer-core latest supported version
RUN npm install puppeteer-core@25 express

# Copy rest of the files
COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
