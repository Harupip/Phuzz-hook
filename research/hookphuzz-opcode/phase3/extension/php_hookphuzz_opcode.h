#ifndef PHP_HOOKPHUZZ_OPCODE_H
#define PHP_HOOKPHUZZ_OPCODE_H

extern zend_module_entry hookphuzz_opcode_module_entry;
#define phpext_hookphuzz_opcode_ptr &hookphuzz_opcode_module_entry

#define PHP_HOOKPHUZZ_OPCODE_VERSION "0.3.0"
#define HOOKPHUZZ_OPCODE_MAX_EVENTS 4096

typedef enum {
    HOOKPHUZZ_SOURCE_GET,
    HOOKPHUZZ_SOURCE_POST,
    HOOKPHUZZ_SOURCE_REQUEST,
    HOOKPHUZZ_SOURCE_COOKIE
} hookphuzz_source;

typedef struct _hookphuzz_path_key {
    zend_uchar type;
    zend_long int_value;
    zend_string *string_value;
} hookphuzz_path_key;

typedef struct _hookphuzz_provenance {
    const zend_execute_data *frame;
    uint32_t result_var;
    hookphuzz_source source;
    uint32_t depth;
    hookphuzz_path_key *path;
} hookphuzz_provenance;

typedef struct _hookphuzz_superglobal_dim_event {
    zend_long line;
    hookphuzz_source source;
    zend_uchar key_type;
    zend_long key_int;
    zend_string *key_string;
    uint32_t depth;
    hookphuzz_path_key *path;
    zend_string *filename;
    const char *unsupported_reason;
    zend_bool has_key_int;
    zend_bool mapped;
} hookphuzz_superglobal_dim_event;

ZEND_BEGIN_MODULE_GLOBALS(hookphuzz_opcode)
    zend_long dropped_event_count;
    uint32_t event_count;
    hookphuzz_superglobal_dim_event *events;
    uint32_t provenance_count;
    hookphuzz_provenance *provenance;
ZEND_END_MODULE_GLOBALS(hookphuzz_opcode)

ZEND_EXTERN_MODULE_GLOBALS(hookphuzz_opcode)
#define HOOKPHUZZ_OPCODE_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(hookphuzz_opcode, v)

#endif
