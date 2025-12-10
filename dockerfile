# Use Node 20 slim as base
FROM node:20-slim

# Set working directory
WORKDIR /app

# Upgrade npm to latest stable
RUN npm install -g npm@11.7.0

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies (omit dev)
RUN npm install --omit=dev

# Copy application code
COPY . .

# Expose default port
EXPOSE 3000

# Start server
CMD ["node", "server.js"]