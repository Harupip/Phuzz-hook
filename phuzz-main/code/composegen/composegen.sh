#!/bin/bash

python ./composegen.py \
    --output-dir /app \
    --configs "wordpress/show-all-comments-in-one-page:1" \
    --application-type wordpress

# python ./composegen.py \
#     --output-dir /app \
#     --config-dir ../fuzzer/configs/wordpress \
#     --num-instances 1 \
#     --application-type wordpress

chmod 777 /app/docker-compose.yml
