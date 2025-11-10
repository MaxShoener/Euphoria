# Use official Node 20 image (LTS and ESM compatible)
FROM node:20-alpine

# Create and set working directory
WORKDIR /app

# Copy only package files first (better layer caching)
COPY package*.json ./

# Install dependencies
RUN npm install --production

# Copy the rest of the app
COPY . .

# Expose your app port
EXPOSE 8080

# Set environment variables (optional defaults)
ENV NODE_ENV=production
ENV PORT=8080

# Start the app
CMD ["node", "server.js"]