# Euphoria v2 Dockerfile
FROM node:20-slim

# Set working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# Copy full application code
COPY server.js ./
COPY public ./public

# Expose port
EXPOSE 3000

# Start the server
CMD ["node", "server.js"]