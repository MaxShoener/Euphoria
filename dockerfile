# Use official Node.js slim image
FROM node:20-slim

# Set working directory
WORKDIR /app

# Install dependencies needed for builds
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

# Copy package.json & package-lock.json
COPY package*.json ./

# ARG for engine selection (default: scramjet)
ARG ENGINE=scramjet
ENV ENGINE=${ENGINE}

# Install the selected engine
RUN if [ "$ENGINE" = "scramjet" ]; then \
      echo "Installing scramjet..."; \
      npm install scramjet --omit=dev; \
    else \
      echo "Installing uv from Git..."; \
      npm install github:MaxShoener/uv --omit=dev; \
    fi

# Copy rest of the application code
COPY . .

# Expose default port (if any)
EXPOSE 3000

# Default start command
CMD ["node", "index.js"]