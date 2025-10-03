# Use Node 20 slim
FROM node:20-slim

# Build arguments
ARG GITHUB_TOKEN
ARG ENGINE=scramjet

# Set working directory
WORKDIR /app

# Install git and essentials
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

# Copy package files
COPY package*.json ./

# Install the selected engine
RUN if [ "$ENGINE" = "scramjet" ]; then \
        echo "Installing scramjet..."; \
        npm install scramjet --omit=dev; \
    else \
        echo "Installing uv..."; \
        npm install uv --omit=dev; \
    fi

# Copy app source
COPY . .

# Expose default port
EXPOSE 3000

# Default command
CMD ["npm", "start"]