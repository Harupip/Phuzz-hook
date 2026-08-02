FROM php:8.2.10-apache

RUN apt-get update && apt-get install -y --no-install-recommends $PHPIZE_DEPS curl mariadb-client python3 python3-requests unzip \
 && docker-php-ext-install mysqli \
 && a2enmod rewrite \
 && sed -ri 's/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf \
 && pecl install uopz-7.1.1 \
 && printf 'extension=uopz.so\nuopz.exit=1\n' > $PHP_INI_DIR/conf.d/40-uopz.ini \
 && curl --fail --silent --show-error --location --retry 3 --connect-timeout 20 --max-time 120 --output /tmp/wp.tar.gz https://wordpress.org/wordpress-6.5.5.tar.gz \
 && tar -xzf /tmp/wp.tar.gz -C /usr/src \
 && mv /usr/src/wordpress /usr/src/wordpress-base \
 && curl --fail --silent --show-error --location --retry 3 --connect-timeout 20 --max-time 120 --output /usr/local/bin/wp https://github.com/wp-cli/wp-cli/releases/download/v2.10.0/wp-cli-2.10.0.phar \
 && chmod +x /usr/local/bin/wp \
 && rm -rf /var/lib/apt/lists/* /tmp/wp.tar.gz

COPY scripts/container-entrypoint.sh /usr/local/bin/phase11-entrypoint
COPY scripts/phase11-rest.conf /etc/apache2/sites-available/000-default.conf
RUN chmod +x /usr/local/bin/phase11-entrypoint
CMD ["/usr/local/bin/phase11-entrypoint"]
