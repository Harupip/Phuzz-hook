#ifndef PHP_HOOKPHUZZ_OPCODE_PHASE8_H
#define PHP_HOOKPHUZZ_OPCODE_PHASE8_H

extern zend_module_entry hookphuzz_opcode_phase8_module_entry;
#define phpext_hookphuzz_opcode_phase8_ptr &hookphuzz_opcode_phase8_module_entry

#define PHP_HOOKPHUZZ_OPCODE_PHASE8_VERSION "0.8.0"
#define HOOKPHUZZ_OPCODE_PHASE8_MAX_EVENTS 4096
#define HOOKPHUZZ_PHASE8_MAX_REGISTRY_BYTES (1024 * 1024)
#define HOOKPHUZZ_PHASE8_MAX_TARGETS 256
#define HOOKPHUZZ_PHASE8_MAX_CALLBACK_BYTES 255
#define HOOKPHUZZ_OPCODE_PHASE5_MAX_EVENTS HOOKPHUZZ_OPCODE_PHASE8_MAX_EVENTS

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
    zend_string *root_callback;
    zend_string *current_function;
    zend_bool attributed;
    uint32_t callback_depth;
    zend_long line;
    const char *operation;
} hookphuzz_event;

typedef struct _hookphuzz_context_frame {
    const zend_execute_data *execute_data;
    zend_string *root_callback;
    zend_string *current_function;
    uint32_t depth;
} hookphuzz_context_frame;

ZEND_BEGIN_MODULE_GLOBALS(hookphuzz_opcode_phase8)
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
    uint32_t context_count;
    hookphuzz_context_frame *contexts;
    char *target_callbacks_ini;
    char *target_callbacks_file_ini;
    zend_string **target_callbacks;
    uint32_t target_callback_count;
    uint32_t static_target_count;
    uint32_t file_target_count;
    uint32_t target_duplicate_count;
    uint32_t target_rejected_count;
    zend_long registry_schema_version;
    zend_string *target_load_status;
    zend_bool file_targets_loaded;
ZEND_END_MODULE_GLOBALS(hookphuzz_opcode_phase8)

ZEND_EXTERN_MODULE_GLOBALS(hookphuzz_opcode_phase8)
#define HOOKPHUZZ_PHASE8_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(hookphuzz_opcode_phase8, v)
#define HOOKPHUZZ_PHASE5_G(v) HOOKPHUZZ_PHASE8_G(v)

#endif
