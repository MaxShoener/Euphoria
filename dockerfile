FROM node:20-bullseye

WORKDIR /app

# Copy package.json and install
COPY package*.json ./
RUN npm install

# Copy everything else
COPY . .

EXPOSE 3000

CMD ["npm", "start"]
