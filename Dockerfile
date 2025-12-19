# Stage 1: build
FROM node:20-alpine AS builder
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --production

COPY src ./src

# Stage 2: runtime
FROM node:20-alpine
ENV NODE_ENV=production
ENV DATA_DIR=/data
ENV CRON_DIR=/cron
ENV TZ=UTC
WORKDIR /app

RUN apk add --no-cache bash tzdata busybox-suid

# copy cron file for ROOT
COPY crontab /etc/crontabs/root
RUN chmod 600 /etc/crontabs/root

# switch user ONLY for node app
CMD sh -c "/usr/sbin/crond -f -l 8 & su node -c 'node src/server.js'"


RUN mkdir -p /data /cron \
  && chown -R node:node /data /cron \
  && chmod 700 /data /cron

EXPOSE 8080
USER node

CMD sh -c "mkdir -p $DATA_DIR $CRON_DIR && /usr/sbin/crond -f -l 8 & node src/server.js"
