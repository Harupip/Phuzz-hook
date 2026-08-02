FROM hookphuzz-phase11-rest-method:local

COPY research/hookphuzz-opcode/phase10-cf7-rest/targets/contact-form-7.5.7.7.zip /opt/contact-form-7.zip
COPY research/hookphuzz-opcode/phase11-rest-method-generalization/phase11b-cf7/scripts/entrypoint.sh /usr/local/bin/phase11b-entrypoint

RUN chmod +x /usr/local/bin/phase11b-entrypoint

CMD ["/usr/local/bin/phase11b-entrypoint"]
