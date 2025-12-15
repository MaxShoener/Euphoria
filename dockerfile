FROM node:20-slim

ENV NODE_ENV=production
WORKDIR /app

# install deps
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

# copy app
COPY . .

# optional: create cache dir (safe even if not used)
RUN mkdir -p /app/cache

EXPOSE 3000
ENV PORT=3000

CMD ["npm", "start"]