ARG PHP_V=8.1.2
FROM php:${PHP_V}-apache
RUN apt-get update && apt-get install -y curl
COPY . /var/www/html
