FROM kassany/alpine-ziglang:latest

USER root

RUN apk update && \
    apk add --no-cache \
    build-base \
    git

USER ziguana
CMD [ "ash" ]