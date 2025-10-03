# Use Node.js 20
FROM node:20-slim

# Create app directory
WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install base dependencies
RUN npm install

# Install git and clone Ultraviolet into node_modules
RUN apt-get update && apt-get install -y git \
    && git clone https://github.com/titaniumnetwork-dev/Ultraviolet.git /app/node_modules/ultraviolet \
    && cd /app/node_modules/ultraviolet && npm install --omit=dev

# Copy source
COPY . .

# Expose port
EXPOSE 3000

# Start server
CMD ["node", "server.js"]