FROM hookphuzz-phase11-rest-method:local

COPY research/hookphuzz-opcode/phase13/scripts/container-entrypoint.sh /usr/local/bin/phase13-entrypoint
COPY research/hookphuzz-opcode/phase13/scripts/bootstrap_plugin.sh /opt/bootstrap_plugin.sh
COPY research/hookphuzz-opcode/phase13/scripts/phase13-observer.php /opt/phase13-observer.php
COPY research/hookphuzz-opcode/phase13/scripts/phase13-containment.php /opt/phase13-containment.php
COPY phuzz-main/code/web/instrumentation/hook_coverage/uopz_hook_wp.php /opt/uopz_hook_wp.php
RUN chmod +x /usr/local/bin/phase13-entrypoint /opt/bootstrap_plugin.sh
CMD ["/usr/local/bin/phase13-entrypoint"]
