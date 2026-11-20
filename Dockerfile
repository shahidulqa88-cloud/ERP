FROM node:22-alpine
WORKDIR /app
COPY server.js package.json ./
COPY public ./public
ENV PORT=3000 DB_FILE=/data/data.db
VOLUME /data
EXPOSE 3000
CMD ["node","server.js"]
