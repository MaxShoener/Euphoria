# Dockerfile — EUPHORIA v2
FROM node:20-alpine

WORKDIR /app

# copy package files first for better layer caching
COPY package.json package-lock.json* ./

# install production deps
RUN npm install --omit=dev

# copy application code
COPY . .

EXPOSE 3000

CMD ["node", "server.js"]