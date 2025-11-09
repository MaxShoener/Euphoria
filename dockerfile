FROM node:20

WORKDIR /app

COPY package*.json ./

# npm install without dev dependencies; doesn't require package-lock.json
RUN npm install --omit=dev

COPY . .

EXPOSE 8080
CMD ["node", "server.js"]