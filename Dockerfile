FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
COPY . .
EXPOSE 8899
CMD ["node", "bin/cli.js", "--web", "--port", "8899"]
