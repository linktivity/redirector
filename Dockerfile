FROM alpine:3.15

RUN apk --no-cache add ca-certificates tzdata && update-ca-certificates

RUN mkdir -p /app

WORKDIR /app

ADD dist /app
