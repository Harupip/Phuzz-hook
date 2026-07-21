FROM php:8.2.10-apache AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends $PHPIZE_DEPS \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/hookphuzz_opcode_phase5
COPY extension/ ./
RUN phpize \
    && ./configure --enable-hookphuzz_opcode_phase5 \
    && make -j"$(nproc)" \
    && make install

FROM php:8.2.10-apache AS base

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /shared/opcode-events /logs \
    && chown -R www-data:www-data /shared /logs

COPY --from=build /usr/local/lib/php/extensions/ /usr/local/lib/php/extensions/
COPY apache/php-phase5.ini $PHP_INI_DIR/conf.d/99-phase5.ini
COPY apache/000-default.conf /etc/apache2/sites-available/000-default.conf

FROM base AS enabled
RUN printf 'extension=hookphuzz_opcode_phase5.so\n' > $PHP_INI_DIR/conf.d/50-hookphuzz-opcode-phase5.ini

FROM base AS disabled

FROM base AS verifier
WORKDIR /workspace
