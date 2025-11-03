# --- Dockerfile (works perfectly on Koyeb) ---
FROM node:20-alpine

WORKDIR /app

# Copy package files first
COPY package*.json ./

# Use npm install instead of npm ci (Koyeb’s build env sometimes lacks package-lock.json)
RUN npm install --production

# Copy the rest of the app
COPY . .

# Expose and start
EXPOSE 3000
CMD ["node", "server.js"]