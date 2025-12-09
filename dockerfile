# Use Node 20 slim for modern global fetch + small footprint
FROM node:20-slim

WORKDIR /app

# copy package manifest and install prod deps
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# copy app files
COPY . .

# create cache dir
RUN mkdir -p /app/cache /app/public

EXPOSE 3000
ENV NODE_ENV=production
CMD ["node", "server.js"]
