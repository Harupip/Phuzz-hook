FROM python:3@sha256:2e376990a11f1c1e03796d08db0e99c36eadb4bb6491372b227f1e53c3482914

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git php-cli unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer

COPY static_analysis/php_ast/composer.json static_analysis/php_ast/composer.lock /app/static_analysis/php_ast/
RUN composer install \
    --working-dir=/app/static_analysis/php_ast \
    --no-dev \
    --prefer-dist \
    --no-interaction \
    --no-progress

COPY . /app

ENTRYPOINT ["python", "-m", "hook_energy.static_seed_generation.cli"]
