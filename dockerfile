FROM node:20-slim

WORKDIR /app

# copy package and install only production deps
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# copy app
COPY . .

# ensure cache & public exist
RUN mkdir -p /app/cache /app/public

EXPOSE 3000
ENV NODE_ENV=production
CMD ["node", "server.js"]