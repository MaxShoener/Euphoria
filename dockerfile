FROM node:20-slim

WORKDIR /app

# Copy only package.json first for caching
COPY package.json ./

# Use npm install instead of npm ci (because you have no package-lock.json)
RUN npm install --omit=dev

# Copy all code
COPY . .

EXPOSE 8080

CMD ["node", "server.js"]