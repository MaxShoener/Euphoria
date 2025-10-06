FROM node:20

WORKDIR /app

COPY package.json ./

# Install dependencies safely (no SSH, no peer issues)
RUN npm install --legacy-peer-deps --fetch-retries=5 --fetch-retry-mintimeout=20000 --fetch-retry-maxtimeout=120000

COPY . .

CMD ["npm", "start"]