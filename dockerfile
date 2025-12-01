# Use node 20 slim (compatible with jsdom runtime)
FROM node:20-slim

WORKDIR /app

# copy package json and install deps (no package-lock required)
COPY package.json ./
RUN npm install --omit=dev

# copy rest of the app
COPY . .

# create cache dir used by server
RUN mkdir -p /app/cache

EXPOSE 3000

CMD ["node", "server.js"]