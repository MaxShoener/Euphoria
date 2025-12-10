FROM node:20-slim

WORKDIR /app

# copy package info and install dependencies first (cache layer)
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# copy application code
COPY . .

# create cache and public folder (public may already exist)
RUN mkdir -p /app/cache /app/public

EXPOSE 3000
ENV NODE_ENV=production
CMD ["node", "server.js"]