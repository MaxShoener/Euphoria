# Use Node.js 20
FROM node:20-slim

# Create app directory
WORKDIR /app

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm install

# Copy all other files
COPY . .

# Expose port
EXPOSE 3000

# Run the server
CMD ["node", "server.js"]