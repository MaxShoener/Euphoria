FROM node:20-alpine

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install --production

# Copy all other files including server.js and index.html
COPY . .

EXPOSE 8080

CMD ["node", "server.js"]