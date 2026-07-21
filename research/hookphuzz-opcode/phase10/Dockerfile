ARG WORDPRESS_VERSION=6.5.5

FROM php:8.2.10-apache AS phase9-build
RUN apt-get update && apt-get install -y --no-install-recommends $PHPIZE_DEPS && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/hookphuzz_opcode_phase9
COPY phase9/extension/ ./
RUN phpize && ./configure --enable-hookphuzz_opcode_phase9 && make -j"$(nproc)" && make install

FROM php:8.2.10-apache
RUN apt-get update && apt-get install -y --no-install-recommends curl mariadb-client unzip $PHPIZE_DEPS && pecl install uopz-7.1.1 \
    && rm -rf /var/lib/apt/lists/* && docker-php-ext-install mysqli \
    && mkdir -p /shared/opcode-events && chown -R www-data:www-data /shared
COPY --from=phase9-build /usr/local/lib/php/extensions/ /usr/local/lib/php/extensions/
COPY phase10/docker/php-phase10.ini $PHP_INI_DIR/conf.d/99-phase10.ini
COPY phase10/docker/wordpress-entrypoint.sh /usr/local/bin/phase10-entrypoint
COPY phase10/targets/controlled-plugin /opt/phase10-controlled
COPY phase10/targets/noise-plugin /opt/phase10-noise
COPY phase10/targets/phase10-discovery.php /opt/phase10-discovery.php
RUN chmod +x /usr/local/bin/phase10-entrypoint
RUN printf 'extension=uopz.so\nuopz.exit=1\n' > $PHP_INI_DIR/conf.d/40-uopz.ini
