FROM php:8.2.10-cli

WORKDIR /usr/src/hookphuzz_opcode

RUN apt-get update \
    && apt-get install -y --no-install-recommends $PHPIZE_DEPS \
    && docker-php-ext-install opcache \
    && rm -rf /var/lib/apt/lists/*

COPY extension/ /usr/src/hookphuzz_opcode/

RUN phpize \
    && ./configure --enable-hookphuzz_opcode \
    && make -j"$(nproc)" \
    && make install \
    && docker-php-ext-enable hookphuzz_opcode

WORKDIR /workspace
