FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

# Use npm install to avoid "missing lockfile" issues on Koyeb
RUN npm install --production

COPY . .

EXPOSE 3000
CMD ["node", "server.js"]