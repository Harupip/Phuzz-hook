ARG PHP_IMAGE=php:8.2.10-cli

FROM ${PHP_IMAGE} AS base

WORKDIR /workspace

FROM base AS opcache

RUN docker-php-ext-install opcache

FROM base AS vld

RUN apt-get update \
    && apt-get install -y --no-install-recommends $PHPIZE_DEPS \
    && pecl install vld \
    && docker-php-ext-enable vld \
    && rm -rf /var/lib/apt/lists/*
