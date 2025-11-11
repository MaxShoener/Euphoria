FROM node:20-alpine

WORKDIR /app

# Copy package files and install
COPY package*.json ./
RUN npm install --production

# Copy all files including public/
COPY . .

EXPOSE 8080
CMD ["node", "server.js"]