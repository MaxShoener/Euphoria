# Use Node 20 slim - modern fetch API + small image
FROM node:20-slim

WORKDIR /app

# copy package manifest and install deps
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# copy application
COPY . .

# create cache directory
RUN mkdir -p /app/cache /app/public

EXPOSE 3000
ENV NODE_ENV=production
CMD ["node", "server.js"]
