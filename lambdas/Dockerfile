FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev
COPY handler.js server.js ./
EXPOSE 8080
CMD ["node", "server.js"]
