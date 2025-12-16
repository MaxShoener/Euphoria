FROM node:20-slim

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY . .

ENV PORT=8000
EXPOSE 8000

CMD ["npm","start"]