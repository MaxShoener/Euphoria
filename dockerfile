FROM node:20-slim

# Install git
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package.json first
COPY package.json package-lock.json* ./

# Upgrade npm
RUN npm install -g npm@11.6.1

# Install dependencies
RUN npm install --legacy-peer-deps

# Copy rest of app
COPY . .

CMD ["npm", "start"]