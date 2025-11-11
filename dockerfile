FROM node:20-alpine

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --production

# Copy all files including public/ folder
COPY . .

EXPOSE 8080
CMD ["node", "server.js"]