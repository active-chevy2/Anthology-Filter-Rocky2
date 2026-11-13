FROM node:20-alpine

WORKDIR /app

COPY server.js index.html ./

EXPOSE 80

CMD ["node", "server.js"]
