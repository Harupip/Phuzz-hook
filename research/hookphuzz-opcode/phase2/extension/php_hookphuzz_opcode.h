#ifndef PHP_HOOKPHUZZ_OPCODE_H
#define PHP_HOOKPHUZZ_OPCODE_H

extern zend_module_entry hookphuzz_opcode_module_entry;
#define phpext_hookphuzz_opcode_ptr &hookphuzz_opcode_module_entry

#define PHP_HOOKPHUZZ_OPCODE_VERSION "0.2.0"
#define HOOKPHUZZ_OPCODE_MAX_EVENTS 4096

typedef struct _hookphuzz_opcode_fetch_dim_r_event {
    zend_long sequence;
    zend_long line;
    zend_long key_int;
    zend_string *filename;
    zend_string *function_name;
    zend_string *key_string;
    const char *op1_operand_type;
    const char *container_zval_type;
    const char *op2_operand_type;
    const char *key_zval_type;
    zend_bool has_key_string;
    zend_bool has_key_int;
} hookphuzz_opcode_fetch_dim_r_event;

ZEND_BEGIN_MODULE_GLOBALS(hookphuzz_opcode)
    zend_long fetch_dim_r_count;
    zend_long dropped_event_count;
    uint32_t event_count;
    hookphuzz_opcode_fetch_dim_r_event *events;
ZEND_END_MODULE_GLOBALS(hookphuzz_opcode)

ZEND_EXTERN_MODULE_GLOBALS(hookphuzz_opcode)
#define HOOKPHUZZ_OPCODE_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(hookphuzz_opcode, v)

#endif
