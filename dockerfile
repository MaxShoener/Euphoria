FROM node:20-alpine

WORKDIR /app

# Copy dependencies and install
COPY package*.json ./
RUN npm install --production

# Copy the rest of the app
COPY . .

EXPOSE 3000
CMD ["node", "server.js"]