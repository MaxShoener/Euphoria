# Use official Node.js 20 slim image
FROM node:20-slim

# Install git (needed for GitHub dependencies)
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package files first (for caching)
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm install --legacy-peer-deps

# Copy the rest of your app
COPY . .

# Expose port (adjust if different)
EXPOSE 3000

# Start the server
CMD ["npm", "start"]