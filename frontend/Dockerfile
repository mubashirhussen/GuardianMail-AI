# --- Stage 1: Build React/Vite Static Bundle ---
FROM node:20-alpine AS build

WORKDIR /app

# Copy dependency files
COPY package.json package-lock.json ./

# Install packages
RUN npm ci

# Copy code and build
COPY . .
RUN npm run build

# --- Stage 2: Production Nginx Server ---
FROM nginx:1.25-alpine

# Copy built frontend assets
COPY --from=build /app/dist /usr/share/nginx/html

# Copy custom reverse-proxy server config
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
