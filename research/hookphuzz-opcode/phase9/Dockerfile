ARG WORDPRESS_VERSION=6.5.5

FROM php:8.2.10-apache AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends $PHPIZE_DEPS \
    && pecl channel-update pecl.php.net \
    && pecl install uopz-7.1.1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/hookphuzz_opcode_phase9
COPY extension/ ./
RUN phpize \
    && ./configure --enable-hookphuzz_opcode_phase9 \
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
COPY apache/php-phase9.ini $PHP_INI_DIR/conf.d/99-phase9.ini
COPY apache/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY docker/wordpress-entrypoint.sh /usr/local/bin/wordpress-entrypoint
COPY instrumentation/ /opt/phase9-instrumentation/
RUN chmod +x /usr/local/bin/wordpress-entrypoint

RUN printf 'extension=uopz.so\nuopz.exit=1\n' > $PHP_INI_DIR/conf.d/40-uopz.ini

FROM base AS enabled
RUN printf 'extension=hookphuzz_opcode_phase9.so\nhookphuzz_opcode.target_callbacks=\nhookphuzz_opcode.target_callbacks_file=/shared/phase9-callback-registry.json\n' > $PHP_INI_DIR/conf.d/50-hookphuzz-opcode-phase9.ini

FROM enabled AS enabled-static
RUN printf 'hookphuzz_opcode.target_callbacks=HookPhuzz_Phase9_Handler_A::probe\n' > $PHP_INI_DIR/conf.d/51-hookphuzz-opcode-phase9-static.ini

FROM base AS disabled

FROM base AS verifier
WORKDIR /workspace
