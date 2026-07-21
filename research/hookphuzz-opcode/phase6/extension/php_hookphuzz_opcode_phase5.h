#ifndef PHP_HOOKPHUZZ_OPCODE_PHASE5_H
#define PHP_HOOKPHUZZ_OPCODE_PHASE5_H

extern zend_module_entry hookphuzz_opcode_phase5_module_entry;
#define phpext_hookphuzz_opcode_phase5_ptr &hookphuzz_opcode_phase5_module_entry

#define PHP_HOOKPHUZZ_OPCODE_PHASE5_VERSION "0.5.0"
#define HOOKPHUZZ_OPCODE_PHASE5_MAX_EVENTS 4096

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

typedef struct _hookphuzz_event {
    hookphuzz_source source;
    uint32_t depth;
    hookphuzz_path_key *path;
    zend_string *filename;
    zend_string *function_name;
    zend_string *class_name;
    zend_long line;
    const char *operation;
} hookphuzz_event;

ZEND_BEGIN_MODULE_GLOBALS(hookphuzz_opcode_phase5)
    zend_long dropped_event_count;
    uint32_t event_count;
    hookphuzz_event *events;
    uint32_t provenance_count;
    hookphuzz_provenance *provenance;
    zend_string *request_id;
    zend_string *request_method;
    zend_string *request_uri;
    zend_bool artifact_enabled;
    zend_bool artifact_flushed;
ZEND_END_MODULE_GLOBALS(hookphuzz_opcode_phase5)

ZEND_EXTERN_MODULE_GLOBALS(hookphuzz_opcode_phase5)
#define HOOKPHUZZ_PHASE5_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(hookphuzz_opcode_phase5, v)

#endif


