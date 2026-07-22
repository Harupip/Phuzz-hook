# syntax=docker/dockerfile:1.7
ARG WORDPRESS_VERSION=6.5.5
FROM php:8.2.10-apache AS extension-build
RUN apt-get update && apt-get install -y --no-install-recommends $PHPIZE_DEPS && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY extension/ ./
RUN phpize && ./configure --enable-hookphuzz_opcode_phase9 && make -j"$(nproc)" && make install
FROM php:8.2.10-apache AS runtime
ARG WORDPRESS_VERSION
RUN --mount=type=secret,id=environment_ca,required=false \
    apt-get update && apt-get install -y --no-install-recommends ca-certificates curl mariadb-client python3 unzip \
    && docker-php-ext-install mysqli && update-ca-certificates \
    && if [ -s /run/secrets/environment_ca ]; then install -m 0644 /run/secrets/environment_ca /usr/local/share/ca-certificates/hookphuzz-environment-ca.crt && update-ca-certificates; fi \
    && curl --fail --show-error --silent --location --http1.1 --retry 3 --retry-all-errors --retry-delay 2 --connect-timeout 20 --max-time 120 --output /tmp/wordpress.tar.gz "https://wordpress.org/wordpress-${WORDPRESS_VERSION}.tar.gz" \
    && test -s /tmp/wordpress.tar.gz && tar -tzf /tmp/wordpress.tar.gz >/dev/null && tar -xzf /tmp/wordpress.tar.gz -C /usr/src && mv /usr/src/wordpress /usr/src/wordpress-base \
    && curl --fail --show-error --silent --location --http1.1 --retry 3 --retry-all-errors --retry-delay 2 --connect-timeout 20 --max-time 120 --output /usr/local/bin/wp "https://github.com/wp-cli/wp-cli/releases/download/v2.10.0/wp-cli-2.10.0.phar" \
    && test -s /usr/local/bin/wp && chmod +x /usr/local/bin/wp && pecl install uopz-7.1.1 \
    && mkdir -p /results/runtime /shared/opcode-events && rm -rf /var/lib/apt/lists/* /tmp/wordpress.tar.gz
COPY --from=extension-build /usr/local/lib/php/extensions/no-debug-non-zts-20220829/hookphuzz_opcode_phase9.so /opt/hookphuzz_opcode_phase9.so
COPY targets/contact-form-7.5.7.7.zip /opt/contact-form-7.zip
COPY wordpress/entrypoint.sh /usr/local/bin/phase10-cf7-rest-entrypoint
COPY wordpress/lab-observer.php /opt/lab-observer.php
COPY docker/php.ini $PHP_INI_DIR/conf.d/99-phase10-cf7-rest.ini
RUN install -m 0755 /opt/hookphuzz_opcode_phase9.so "$(php -n -r 'echo ini_get("extension_dir");')/hookphuzz_opcode_phase9.so" && chmod +x /usr/local/bin/phase10-cf7-rest-entrypoint && printf 'extension=uopz.so\nuopz.exit=1\n' > $PHP_INI_DIR/conf.d/40-uopz.ini
CMD ["/usr/local/bin/phase10-cf7-rest-entrypoint"]
