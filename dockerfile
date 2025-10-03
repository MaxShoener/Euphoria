# Use Node.js 20 slim image
FROM node:20-slim

# Install git + dependencies for npm install from GitHub
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Install dependencies first
COPY package.json package-lock.json* ./
RUN npm install --legacy-peer-deps

# Copy rest of the app
COPY . .

# Expose port (Koyeb will route traffic here)
EXPOSE 3000

# Start app
CMD ["npm", "start"]