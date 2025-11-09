FROM node:20

WORKDIR /app

COPY package*.json ./

# Install only production deps — avoids needing package-lock.json
RUN npm install --omit=dev

COPY . .

EXPOSE 8080
CMD ["node", "server.js"]