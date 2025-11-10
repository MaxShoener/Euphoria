FROM node:20-alpine

WORKDIR /app

# copy package files first to leverage layer caching
COPY package*.json ./

# install production deps (omit dev)
RUN npm install --omit=dev

COPY . .

EXPOSE 3000
CMD ["node", "server.js"]
