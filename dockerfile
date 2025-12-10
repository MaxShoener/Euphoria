# Base image
FROM node:20-slim

# Set working directory
WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# Copy application code
COPY . .

# Expose the proxy port
EXPOSE 8000

# Start the application
CMD ["npm", "start"]