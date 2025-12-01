# Use a full Debian-based Node image for compatibility with jsdom dependencies
FROM node:20-slim

WORKDIR /app

# copy package info and install dependencies first (cache layer)
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# copy application files
COPY . .

# Create a cache dir used by server (optional)
RUN mkdir -p /app/cache

EXPOSE 3000

# start the app
CMD ["node", "server.js"]