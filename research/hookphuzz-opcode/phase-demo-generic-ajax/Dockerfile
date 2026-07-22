ARG WORDPRESS_VERSION=6.5.5

FROM php:8.2.10-apache AS extension-build

RUN apt-get update \
    && apt-get install -y --no-install-recommends $PHPIZE_DEPS \
    && pecl channel-update pecl.php.net \
    && pecl install uopz-7.1.1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/hookphuzz_opcode_phase9
COPY phase9/extension/ ./
RUN phpize \
    && ./configure --enable-hookphuzz_opcode_phase9 \
    && make -j"$(nproc)" \
    && make install

FROM php:8.2.10-apache
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

COPY --from=extension-build /usr/local/lib/php/extensions/ /usr/local/lib/php/extensions/
COPY phase-demo-generic-ajax/apache/php-demo.ini $PHP_INI_DIR/conf.d/99-demo.ini
COPY phase-demo-generic-ajax/apache/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY phase-demo-generic-ajax/docker/wordpress-entrypoint.sh /usr/local/bin/wordpress-entrypoint
COPY phase-demo-generic-ajax/instrumentation/ /opt/hookphuzz-demo-instrumentation/

RUN printf 'extension=uopz.so\nuopz.exit=1\n' > $PHP_INI_DIR/conf.d/40-uopz.ini \
    && printf 'extension=hookphuzz_opcode_phase9.so\nhookphuzz_opcode.target_callbacks=\nhookphuzz_opcode.target_callbacks_file=/shared/hook-registration.json\n' > $PHP_INI_DIR/conf.d/50-hookphuzz-opcode-demo.ini \
    && chmod +x /usr/local/bin/wordpress-entrypoint

