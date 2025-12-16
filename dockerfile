FROM node:20-slim

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

ENV NODE_ENV=production
ENV PORT=8000
EXPOSE 8000

CMD ["node", "server.js"]