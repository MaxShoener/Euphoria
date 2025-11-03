FROM node:20-alpine

WORKDIR /app

# Copy and install dependencies
COPY package*.json ./
RUN npm install --production

# Copy all other files
COPY . .

EXPOSE 3000
CMD ["node", "server.js"]