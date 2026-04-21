Composegen Component
=====================

This component is used to generate a `docker-compose.yml` file for the simplified WordPress-only PHUZZ workflow.

Depending on the RAM available on your system, you might want to increase the `size` parameter in the lines defining the shared volumes `o: "size=1024m,uid=1000"` in `composegen.py`.

First, edit `composegen.sh` to set the desired arguments to `composegen.py`, and then run `docker-compose up composegen --force-recreate` from the parent directory. The new `docker-compose.yml` will be in `./composegen/`. Last, copy the new file to the parent directory: `cp docker-compose.yml ../`. 

The default example now generates a WordPress target with one PHUZZ instance against `wordpress/show-all-comments-in-one-page`. For WordPress configs, `composegen.py` will automatically set `WP_TARGET_PLUGIN` and, if no explicit value is passed, infer `FUZZER_COVERAGE_PATH` as `wp-content/plugins/<plugin-slug>/`.

```
usage: composegen.py [-h] --output-dir OUTPUT_DIR [--configs CONFIGS [CONFIGS ...]] [--application-type APPLICATION_TYPE] [--config-dir CONFIG_DIR] [--num-instances NUM_INSTANCES] [--coverage-path COVERAGE_PATH]

Generate Docker Compose file

options:
  -h, --help            show this help message and exit
  --output-dir OUTPUT_DIR
                        Directory to save the generated Docker Compose file
  --configs CONFIGS [CONFIGS ...]
                        List of configurations, specified as config_name:num_fuzzers
  --application-type APPLICATION_TYPE
                        The application type
  --config-dir CONFIG_DIR
                        Directory where JSON config files are stored
  --num-instances NUM_INSTANCES
                        Number of instances for all configs in the config directory
  --coverage-path COVERAGE_PATH
                        Path relativ to /var/www/html/ to capture coverage from
```
