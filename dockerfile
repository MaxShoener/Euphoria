# Use Node.js 20 slim image
FROM node:20-slim

# Create app directory
WORKDIR /app

# Install dependencies first
COPY package.json package-lock.json* ./
RUN npm install --legacy-peer-deps

# Copy rest of the app
COPY . .

# Expose port
EXPOSE 3000

# Start app
CMD ["npm", "start"]