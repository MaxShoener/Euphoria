# Use Node 20 slim as base
FROM node:20-slim

# Install git (needed for HTTPS git installs)
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm install --legacy-peer-deps

# Copy the rest of the app
COPY . .

# Expose port (adjust if your server uses a different port)
EXPOSE 3000

# Start the app
CMD ["npm", "start"]