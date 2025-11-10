# Use an official Node.js runtime
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy dependency files
COPY package*.json ./

# Install dependencies (not ci — safe for dynamic builds)
RUN npm install --omit=dev

# Copy source code
COPY . .

# Expose port
EXPOSE 8080

# Start server
CMD ["node", "server.js"]
