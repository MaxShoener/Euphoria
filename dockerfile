FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

RUN mkdir -p /app/cache /app/public

EXPOSE 3000
ENV NODE_ENV=production
CMD ["node", "server.js"]