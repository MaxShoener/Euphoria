# Use official Node.js LTS image
FROM node:20-bullseye-slim

# Set working directory
WORKDIR /app

# Copy package files first (for caching)
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm install --production

# Copy rest of the app
COPY . .

# Expose port
EXPOSE 3000

# Run the server
CMD ["node", "server.js"]