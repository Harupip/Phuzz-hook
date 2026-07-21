ARG WORDPRESS_VERSION=6.5.5

FROM php:8.2.10-apache AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends $PHPIZE_DEPS \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/hookphuzz_opcode_phase7
COPY extension/ ./
RUN phpize \
    && ./configure --enable-hookphuzz_opcode_phase7 \
    && make -j"$(nproc)" \
    && make install

FROM php:8.2.10-apache AS base
ARG WORDPRESS_VERSION
ARG WP_CLI_VERSION=2.10.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl mariadb-client \
    && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install mysqli \
    && mkdir -p /usr/src/wordpress /shared/opcode-events /logs \
    && curl -fsSL "https://wordpress.org/wordpress-${WORDPRESS_VERSION}.tar.gz" -o /tmp/wordpress.tar.gz \
    && tar -xzf /tmp/wordpress.tar.gz -C /usr/src/wordpress --strip-components=1 \
    && rm /tmp/wordpress.tar.gz \
    && curl -fsSL "https://github.com/wp-cli/wp-cli/releases/download/v${WP_CLI_VERSION}/wp-cli-${WP_CLI_VERSION}.phar" -o /usr/local/bin/wp \
    && chmod +x /usr/local/bin/wp \
    && chown -R www-data:www-data /shared /logs

COPY --from=build /usr/local/lib/php/extensions/ /usr/local/lib/php/extensions/
COPY apache/php-phase7.ini $PHP_INI_DIR/conf.d/99-phase7.ini
COPY apache/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY docker/wordpress-entrypoint.sh /usr/local/bin/wordpress-entrypoint
RUN chmod +x /usr/local/bin/wordpress-entrypoint

FROM base AS enabled
RUN printf 'extension=hookphuzz_opcode_phase7.so\nhookphuzz_opcode.target_callbacks=hookphuzz_phase7_probe,HookPhuzz_Phase7_Handler::probe\n' > $PHP_INI_DIR/conf.d/50-hookphuzz-opcode-phase7.ini

FROM base AS disabled

FROM base AS verifier
WORKDIR /workspace
