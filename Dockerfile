FROM node:22

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

RUN npm run build

EXPOSE 8080

CMD ["npx", "mcp-proxy", "--port", "8080", "--", "npm", "start"]
