#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_hookphuzz_opcode.h"
#include "ext/json/php_json.h"
#include "ext/standard/info.h"
#include "main/SAPI.h"
#include "main/php_variables.h"
#include "Zend/zend_compile.h"
#include "Zend/zend_execute.h"
#include "Zend/zend_observer.h"
#include "Zend/zend_smart_str.h"
#include "Zend/zend_vm_opcodes.h"

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define HOOKPHUZZ_ARTIFACT_DIR "/shared/opcode-events"

ZEND_DECLARE_MODULE_GLOBALS(hookphuzz_opcode)

PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("hookphuzz_opcode.target_callbacks", "", PHP_INI_SYSTEM, OnUpdateString,
        target_callbacks_ini, zend_hookphuzz_opcode_globals, hookphuzz_opcode_globals)
    STD_PHP_INI_ENTRY("hookphuzz_opcode.target_callbacks_file", "", PHP_INI_SYSTEM, OnUpdateString,
        target_callbacks_file_ini, zend_hookphuzz_opcode_globals, hookphuzz_opcode_globals)
PHP_INI_END()

typedef enum {
    HOOKPHUZZ_TARGET_ADDED,
    HOOKPHUZZ_TARGET_DUPLICATE,
    HOOKPHUZZ_TARGET_INVALID,
    HOOKPHUZZ_TARGET_CAPACITY_EXHAUSTED
} hookphuzz_target_add_result;

static const char *hookphuzz_source_name(hookphuzz_source source)
{
    switch (source) {
        case HOOKPHUZZ_SOURCE_GET: return "GET";
        case HOOKPHUZZ_SOURCE_POST: return "POST";
        case HOOKPHUZZ_SOURCE_REQUEST: return "REQUEST";
        case HOOKPHUZZ_SOURCE_COOKIE: return "COOKIE";
        case HOOKPHUZZ_SOURCE_REST: return "REST";
    }
    return "UNKNOWN";
}

static void hookphuzz_release_path(hookphuzz_path_key *path, uint32_t depth)
{
    uint32_t index;

    if (path == NULL) return;
    for (index = 0; index < depth; index++) {
        if (path[index].string_value != NULL) zend_string_release(path[index].string_value);
    }
    efree(path);
}

static hookphuzz_path_key *hookphuzz_copy_path(const hookphuzz_path_key *path, uint32_t depth)
{
    hookphuzz_path_key *copy;
    uint32_t index;

    if (depth == 0) return NULL;
    copy = ecalloc(depth, sizeof(*copy));
    for (index = 0; index < depth; index++) {
        copy[index].type = path[index].type;
        copy[index].int_value = path[index].int_value;
        if (path[index].string_value != NULL) copy[index].string_value = zend_string_copy(path[index].string_value);
    }
    return copy;
}

static hookphuzz_path_key *hookphuzz_append_path(const hookphuzz_provenance *provenance, const zval *key)
{
    uint32_t old_depth = provenance->depth;
    hookphuzz_path_key *path = ecalloc(old_depth + 1, sizeof(*path));
    uint32_t index;

    for (index = 0; index < old_depth; index++) {
        path[index].type = provenance->path[index].type;
        path[index].int_value = provenance->path[index].int_value;
        if (provenance->path[index].string_value != NULL) path[index].string_value = zend_string_copy(provenance->path[index].string_value);
    }
    path[old_depth].type = Z_TYPE_P(key);
    if (Z_TYPE_P(key) == IS_STRING) path[old_depth].string_value = zend_string_copy(Z_STR_P(key));
    else path[old_depth].int_value = Z_LVAL_P(key);
    return path;
}

static zend_string *hookphuzz_copy_filename(const zend_execute_data *execute_data)
{
    if (execute_data != NULL && execute_data->func != NULL
        && ZEND_USER_CODE(execute_data->func->type)
        && execute_data->func->op_array.filename != NULL) {
        return zend_string_copy(execute_data->func->op_array.filename);
    }
    return zend_string_init("{unknown}", sizeof("{unknown}") - 1, 0);
}

static zend_string *hookphuzz_copy_function_name(const zend_execute_data *execute_data)
{
    if (execute_data != NULL && execute_data->func != NULL
        && execute_data->func->common.function_name != NULL) {
        return zend_string_copy(execute_data->func->common.function_name);
    }
    return NULL;
}

static zend_string *hookphuzz_copy_class_name(const zend_execute_data *execute_data)
{
    if (execute_data != NULL && execute_data->func != NULL
        && execute_data->func->common.scope != NULL
        && execute_data->func->common.scope->name != NULL) {
        return zend_string_copy(execute_data->func->common.scope->name);
    }
    return NULL;
}

static zend_string *hookphuzz_normalize_function(const zend_execute_data *execute_data)
{
    zend_function *function;

    if (execute_data == NULL || (function = execute_data->func) == NULL
        || !ZEND_USER_CODE(function->type) || function->common.function_name == NULL) return NULL;
    if (function->common.scope != NULL && function->common.scope->name != NULL) {
        return strpprintf(0, "%s::%s", ZSTR_VAL(function->common.scope->name),
            ZSTR_VAL(function->common.function_name));
    }
    if (zend_string_equals_literal(function->common.function_name, "{closure}")
        && function->op_array.filename != NULL) {
        return strpprintf(0, "closure@%s:%u", ZSTR_VAL(function->op_array.filename),
            function->op_array.line_start);
    }
    return zend_string_copy(function->common.function_name);
}

static void hookphuzz_release_targets(void)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_G(target_callback_count); index++) {
        zend_string_release(HOOKPHUZZ_G(target_callbacks)[index]);
    }
    if (HOOKPHUZZ_G(target_callbacks) != NULL) efree(HOOKPHUZZ_G(target_callbacks));
    HOOKPHUZZ_G(target_callbacks) = NULL;
    HOOKPHUZZ_G(target_callback_count) = 0;
    if (HOOKPHUZZ_G(target_load_status) != NULL) zend_string_release(HOOKPHUZZ_G(target_load_status));
    HOOKPHUZZ_G(target_load_status) = NULL;
}

static void hookphuzz_set_target_status(const char *status)
{
    if (HOOKPHUZZ_G(target_load_status) != NULL) zend_string_release(HOOKPHUZZ_G(target_load_status));
    HOOKPHUZZ_G(target_load_status) = zend_string_init(status, strlen(status), 0);
}

static zend_bool hookphuzz_valid_callback_name(const zend_string *name)
{
    const char *value;
    size_t index, separators = 0;

    if (name == NULL || ZSTR_LEN(name) == 0 || ZSTR_LEN(name) > HOOKPHUZZ_MAX_CALLBACK_BYTES) return 0;
    value = ZSTR_VAL(name);
    for (index = 0; index < ZSTR_LEN(name); index++) {
        if (isalnum((unsigned char) value[index]) || value[index] == '_' || value[index] == '\\') continue;
        if (value[index] == ':' && index + 1 < ZSTR_LEN(name) && value[index + 1] == ':') {
            separators++;
            index++;
            continue;
        }
        return 0;
    }
    return separators <= 1 && value[0] != ':' && value[ZSTR_LEN(name) - 1] != ':';
}

static hookphuzz_target_add_result hookphuzz_add_target(const zend_string *name)
{
    uint32_t index;

    if (!hookphuzz_valid_callback_name(name)) return HOOKPHUZZ_TARGET_INVALID;
    for (index = 0; index < HOOKPHUZZ_G(target_callback_count); index++) {
        if (zend_string_equals_ci(name, HOOKPHUZZ_G(target_callbacks)[index])) return HOOKPHUZZ_TARGET_DUPLICATE;
    }
    if (HOOKPHUZZ_G(target_callback_count) == HOOKPHUZZ_MAX_TARGETS) return HOOKPHUZZ_TARGET_CAPACITY_EXHAUSTED;
    HOOKPHUZZ_G(target_callbacks) = erealloc(HOOKPHUZZ_G(target_callbacks),
        sizeof(zend_string *) * (HOOKPHUZZ_G(target_callback_count) + 1));
    HOOKPHUZZ_G(target_callbacks)[HOOKPHUZZ_G(target_callback_count)++] = zend_string_copy((zend_string *) name);
    return HOOKPHUZZ_TARGET_ADDED;
}

static void hookphuzz_parse_targets(void)
{
    const char *cursor = HOOKPHUZZ_G(target_callbacks_ini);

    if (cursor == NULL) return;
    while (*cursor != '\0') {
        const char *start, *end;
        while (*cursor != '\0' && (isspace((unsigned char) *cursor) || *cursor == ',')) cursor++;
        start = cursor;
        while (*cursor != '\0' && *cursor != ',') cursor++;
        end = cursor;
        while (end > start && isspace((unsigned char) end[-1])) end--;
        if (end > start) {
            zend_string *name = zend_string_init(start, end - start, 0);
            HOOKPHUZZ_G(requested_target_count)++;
            switch (hookphuzz_add_target(name)) {
                case HOOKPHUZZ_TARGET_ADDED:
                    HOOKPHUZZ_G(static_target_count)++;
                    break;
                case HOOKPHUZZ_TARGET_DUPLICATE:
                    HOOKPHUZZ_G(target_duplicate_count)++;
                    break;
                case HOOKPHUZZ_TARGET_INVALID:
                    HOOKPHUZZ_G(target_rejected_count)++;
                    break;
                case HOOKPHUZZ_TARGET_CAPACITY_EXHAUSTED:
                    HOOKPHUZZ_G(target_capacity_exhausted_count)++;
                    break;
            }
            zend_string_release(name);
        }
    }
}

static zend_result hookphuzz_read_all(int fd, char *bytes, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t received = read(fd, bytes + offset, length - offset);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) return FAILURE;
        offset += (size_t) received;
    }
    return SUCCESS;
}

static HashTable *hookphuzz_json_hash(zval *value)
{
    if (Z_TYPE_P(value) == IS_ARRAY) return Z_ARRVAL_P(value);
    if (Z_TYPE_P(value) == IS_OBJECT) return Z_OBJPROP_P(value);
    return NULL;
}

static void hookphuzz_load_file_targets(void)
{
    char *bytes = NULL;
    int fd = -1;
    struct stat file_stat;
    zval document, *schema, *registrations, *registration;
    HashTable *document_hash, *registration_hash, *registrations_hash;

    if (HOOKPHUZZ_G(target_callbacks_file_ini) == NULL || HOOKPHUZZ_G(target_callbacks_file_ini)[0] == '\0') {
        hookphuzz_set_target_status("disabled");
        return;
    }
    fd = open(HOOKPHUZZ_G(target_callbacks_file_ini), O_RDONLY);
    if (fd < 0) {
        hookphuzz_set_target_status(errno == ENOENT ? "missing" : "malformed");
        return;
    }
    if (fstat(fd, &file_stat) != 0 || file_stat.st_size < 0 || file_stat.st_size > HOOKPHUZZ_MAX_REGISTRY_BYTES) {
        close(fd); hookphuzz_set_target_status("malformed"); return;
    }
    if (file_stat.st_size == 0) { close(fd); hookphuzz_set_target_status("empty"); return; }
    bytes = emalloc((size_t) file_stat.st_size + 1);
    if (hookphuzz_read_all(fd, bytes, (size_t) file_stat.st_size) != SUCCESS) {
        close(fd); efree(bytes); hookphuzz_set_target_status("malformed"); return;
    }
    close(fd); bytes[file_stat.st_size] = '\0';
    ZVAL_NULL(&document);
    php_json_decode_ex(&document, bytes, (size_t) file_stat.st_size, PHP_JSON_OBJECT_AS_ARRAY, 32);
    efree(bytes);
    document_hash = hookphuzz_json_hash(&document);
    if (document_hash == NULL) { zval_ptr_dtor(&document); hookphuzz_set_target_status("malformed"); return; }
    schema = zend_hash_str_find(document_hash, ZEND_STRL("schema_version"));
    if (schema == NULL || Z_TYPE_P(schema) != IS_LONG || Z_LVAL_P(schema) != 1) {
        zval_ptr_dtor(&document); hookphuzz_set_target_status("unsupported_schema"); return;
    }
    registrations = zend_hash_str_find(document_hash, ZEND_STRL("registrations"));
    registrations_hash = registrations == NULL ? NULL : hookphuzz_json_hash(registrations);
    if (registrations_hash == NULL) {
        zval_ptr_dtor(&document); hookphuzz_set_target_status("malformed"); return;
    }
    HOOKPHUZZ_G(registry_schema_version) = 1;
    ZEND_HASH_FOREACH_VAL(registrations_hash, registration) {
        zval *canonical, *type, *callback;
        HOOKPHUZZ_G(requested_target_count)++;
        registration_hash = hookphuzz_json_hash(registration);
        if (registration_hash == NULL) { HOOKPHUZZ_G(target_rejected_count)++; continue; }
        canonical = zend_hash_str_find(registration_hash, ZEND_STRL("canonical_callback"));
        type = zend_hash_str_find(registration_hash, ZEND_STRL("callback_type"));
        callback = zend_hash_str_find(registration_hash, ZEND_STRL("callback"));
        if (canonical == NULL || Z_TYPE_P(canonical) != IS_STRING || type == NULL || Z_TYPE_P(type) != IS_STRING
            || (callback != NULL && (Z_TYPE_P(callback) != IS_STRING || Z_STRLEN_P(callback) == 0
                || Z_STRLEN_P(callback) > HOOKPHUZZ_MAX_CALLBACK_BYTES))
            || (strcmp(Z_STRVAL_P(type), "function") != 0 && strcmp(Z_STRVAL_P(type), "static_method") != 0
                && strcmp(Z_STRVAL_P(type), "object_method") != 0)) {
            HOOKPHUZZ_G(target_rejected_count)++; continue;
        }
        switch (hookphuzz_add_target(Z_STR_P(canonical))) {
            case HOOKPHUZZ_TARGET_ADDED:
                HOOKPHUZZ_G(file_target_count)++;
                break;
            case HOOKPHUZZ_TARGET_DUPLICATE:
                HOOKPHUZZ_G(target_duplicate_count)++;
                break;
            case HOOKPHUZZ_TARGET_INVALID:
                HOOKPHUZZ_G(target_rejected_count)++;
                break;
            case HOOKPHUZZ_TARGET_CAPACITY_EXHAUSTED:
                HOOKPHUZZ_G(target_capacity_exhausted_count)++;
                break;
        }
    } ZEND_HASH_FOREACH_END();
    zval_ptr_dtor(&document);
    hookphuzz_set_target_status((HOOKPHUZZ_G(target_rejected_count) || HOOKPHUZZ_G(target_capacity_exhausted_count))
        ? "partially_loaded" : "loaded");
}

static zend_bool hookphuzz_is_target(const zend_string *name)
{
    uint32_t index;

    if (name == NULL) return 0;
    for (index = 0; index < HOOKPHUZZ_G(target_callback_count); index++) {
        if (zend_string_equals_ci(name, HOOKPHUZZ_G(target_callbacks)[index])) return 1;
    }
    return 0;
}

static hookphuzz_context_frame *hookphuzz_find_context(const zend_execute_data *execute_data)
{
    const zend_execute_data *cursor;
    uint32_t index;

    for (index = HOOKPHUZZ_G(context_count); index > 0; index--) {
        hookphuzz_context_frame *frame = &HOOKPHUZZ_G(contexts)[index - 1];
        if (frame->execute_data == execute_data) return frame;
    }
    for (cursor = execute_data == NULL ? NULL : execute_data->prev_execute_data;
         cursor != NULL;
         cursor = cursor->prev_execute_data) {
        for (index = HOOKPHUZZ_G(context_count); index > 0; index--) {
            hookphuzz_context_frame *frame = &HOOKPHUZZ_G(contexts)[index - 1];
            if (frame->execute_data == cursor) return frame;
        }
    }
    return NULL;
}

static void hookphuzz_release_contexts(void)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_G(context_count); index++) {
        zend_string_release(HOOKPHUZZ_G(contexts)[index].root_callback);
        zend_string_release(HOOKPHUZZ_G(contexts)[index].current_function);
    }
    if (HOOKPHUZZ_G(contexts) != NULL) efree(HOOKPHUZZ_G(contexts));
    HOOKPHUZZ_G(contexts) = NULL;
    HOOKPHUZZ_G(context_count) = 0;
}

static void hookphuzz_release_provenance(void);

static void hookphuzz_context_begin(zend_execute_data *execute_data)
{
    zend_string *name = hookphuzz_normalize_function(execute_data);
    hookphuzz_context_frame *parent = HOOKPHUZZ_G(context_count) == 0 ? NULL
        : &HOOKPHUZZ_G(contexts)[HOOKPHUZZ_G(context_count) - 1];
    hookphuzz_context_frame *frame;

    if (name == NULL) return;
    if (!hookphuzz_is_target(name) && parent == NULL) {
        zend_string_release(name);
        return;
    }
    if (parent == NULL && hookphuzz_is_target(name)) {
        hookphuzz_release_provenance();
    }
    HOOKPHUZZ_G(contexts) = erealloc(HOOKPHUZZ_G(contexts),
        sizeof(hookphuzz_context_frame) * (HOOKPHUZZ_G(context_count) + 1));
    frame = &HOOKPHUZZ_G(contexts)[HOOKPHUZZ_G(context_count)++];
    frame->execute_data = execute_data;
    frame->current_function = name;
    if (hookphuzz_is_target(name)) {
        frame->root_callback = zend_string_copy(name);
        frame->depth = 0;
    } else {
        frame->root_callback = zend_string_copy(parent->root_callback);
        frame->depth = parent->depth + 1;
    }
}

static void hookphuzz_context_end(zend_execute_data *execute_data)
{
    hookphuzz_context_frame *frame;

    if (HOOKPHUZZ_G(context_count) == 0) return;
    frame = &HOOKPHUZZ_G(contexts)[HOOKPHUZZ_G(context_count) - 1];
    if (frame->execute_data != execute_data) return;
    zend_string_release(frame->root_callback);
    zend_string_release(frame->current_function);
    HOOKPHUZZ_G(context_count)--;
}

static void hookphuzz_release_events(void)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_G(event_count); index++) {
        hookphuzz_event *event = &HOOKPHUZZ_G(events)[index];
        hookphuzz_release_path(event->path, event->depth);
        if (event->filename != NULL) zend_string_release(event->filename);
        if (event->function_name != NULL) zend_string_release(event->function_name);
        if (event->class_name != NULL) zend_string_release(event->class_name);
        if (event->root_callback != NULL) zend_string_release(event->root_callback);
        if (event->current_function != NULL) zend_string_release(event->current_function);
    }
    if (HOOKPHUZZ_G(events) != NULL) efree(HOOKPHUZZ_G(events));
    HOOKPHUZZ_G(events) = NULL;
    HOOKPHUZZ_G(event_count) = 0;
}

static void hookphuzz_release_comparison_events(void)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_G(comparison_event_count); index++) {
        hookphuzz_comparison_event *event = &HOOKPHUZZ_G(comparison_events)[index];
        hookphuzz_release_path(event->path, event->depth);
        if (event->runtime_value != NULL) zend_string_release(event->runtime_value);
        if (event->comparison_value != NULL) zend_string_release(event->comparison_value);
        if (event->root_callback != NULL) zend_string_release(event->root_callback);
        if (event->current_function != NULL) zend_string_release(event->current_function);
    }
    if (HOOKPHUZZ_G(comparison_events) != NULL) efree(HOOKPHUZZ_G(comparison_events));
    HOOKPHUZZ_G(comparison_events) = NULL;
    HOOKPHUZZ_G(comparison_event_count) = 0;
}

static void hookphuzz_release_provenance(void)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_PHASE5_G(provenance_count); index++) {
        hookphuzz_release_path(HOOKPHUZZ_PHASE5_G(provenance)[index].path,
            HOOKPHUZZ_PHASE5_G(provenance)[index].depth);
    }
    if (HOOKPHUZZ_PHASE5_G(provenance) != NULL) efree(HOOKPHUZZ_PHASE5_G(provenance));
    HOOKPHUZZ_PHASE5_G(provenance) = NULL;
    HOOKPHUZZ_PHASE5_G(provenance_count) = 0;
}

static void hookphuzz_release_element_provenance(void)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_PHASE5_G(element_provenance_count); index++) {
        hookphuzz_element_provenance *item = &HOOKPHUZZ_PHASE5_G(element_provenance)[index];
        if (item->string_key != NULL) zend_string_release(item->string_key);
        hookphuzz_release_path(item->path, item->depth);
    }
    if (HOOKPHUZZ_PHASE5_G(element_provenance) != NULL) efree(HOOKPHUZZ_PHASE5_G(element_provenance));
    HOOKPHUZZ_PHASE5_G(element_provenance) = NULL;
    HOOKPHUZZ_PHASE5_G(element_provenance_count) = 0;
}

static void hookphuzz_release_request_metadata(void)
{
    if (HOOKPHUZZ_PHASE5_G(request_id) != NULL) zend_string_release(HOOKPHUZZ_PHASE5_G(request_id));
    if (HOOKPHUZZ_PHASE5_G(request_method) != NULL) zend_string_release(HOOKPHUZZ_PHASE5_G(request_method));
    if (HOOKPHUZZ_PHASE5_G(request_uri) != NULL) zend_string_release(HOOKPHUZZ_PHASE5_G(request_uri));
    HOOKPHUZZ_PHASE5_G(request_id) = NULL;
    HOOKPHUZZ_PHASE5_G(request_method) = NULL;
    HOOKPHUZZ_PHASE5_G(request_uri) = NULL;
}

static void hookphuzz_remove_frame_provenance(const zend_execute_data *frame)
{
    uint32_t index = 0;

    while (index < HOOKPHUZZ_PHASE5_G(provenance_count)) {
        hookphuzz_provenance *item = &HOOKPHUZZ_PHASE5_G(provenance)[index];
        if (item->frame != frame) {
            index++;
            continue;
        }
        hookphuzz_release_path(item->path, item->depth);
        HOOKPHUZZ_PHASE5_G(provenance_count)--;
        if (index != HOOKPHUZZ_PHASE5_G(provenance_count)) {
            HOOKPHUZZ_PHASE5_G(provenance)[index] = HOOKPHUZZ_PHASE5_G(provenance)[HOOKPHUZZ_PHASE5_G(provenance_count)];
        }
    }
}

static hookphuzz_provenance *hookphuzz_find_provenance(const zend_execute_data *frame, uint32_t result_var)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_PHASE5_G(provenance_count); index++) {
        hookphuzz_provenance *item = &HOOKPHUZZ_PHASE5_G(provenance)[index];
        if (item->frame == frame && item->result_var == result_var) return item;
    }
    return NULL;
}

static void hookphuzz_set_provenance_for_result(const zend_execute_data *frame, uint32_t result_var,
    hookphuzz_source source, hookphuzz_path_key *path, uint32_t depth)
{
    hookphuzz_provenance *item;
    uint32_t index;

    item = hookphuzz_find_provenance(frame, result_var);
    if (item == NULL) {
        for (index = 0; index < HOOKPHUZZ_PHASE5_G(provenance_count); index++) {
            if (HOOKPHUZZ_PHASE5_G(provenance)[index].frame == NULL) {
                item = &HOOKPHUZZ_PHASE5_G(provenance)[index];
                break;
            }
        }
        if (item == NULL && HOOKPHUZZ_PHASE5_G(provenance_count) == HOOKPHUZZ_OPCODE_PHASE5_MAX_EVENTS) {
            hookphuzz_release_path(path, depth);
            return;
        }
        if (HOOKPHUZZ_PHASE5_G(provenance) == NULL) {
            HOOKPHUZZ_PHASE5_G(provenance) = ecalloc(HOOKPHUZZ_OPCODE_PHASE5_MAX_EVENTS, sizeof(hookphuzz_provenance));
        }
        if (item == NULL) item = &HOOKPHUZZ_PHASE5_G(provenance)[HOOKPHUZZ_PHASE5_G(provenance_count)++];
    } else {
        hookphuzz_release_path(item->path, item->depth);
    }
    item->frame = frame;
    item->result_var = result_var;
    item->source = source;
    item->depth = depth;
    item->path = path;
}

static void hookphuzz_clear_provenance_for_result(const zend_execute_data *frame, uint32_t result_var)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_PHASE5_G(provenance_count); index++) {
        hookphuzz_provenance *item = &HOOKPHUZZ_PHASE5_G(provenance)[index];
        if (item->frame == frame && item->result_var == result_var) {
            hookphuzz_release_path(item->path, item->depth);
            item->frame = NULL;
            item->result_var = 0;
            item->depth = 0;
            item->path = NULL;
            return;
        }
    }
}

static void hookphuzz_set_provenance(const zend_execute_data *frame, const zend_op *opline,
    hookphuzz_source source, hookphuzz_path_key *path, uint32_t depth)
{
    if (opline->result_type != IS_TMP_VAR && opline->result_type != IS_VAR && opline->result_type != IS_CV) {
        hookphuzz_release_path(path, depth);
        return;
    }
    hookphuzz_set_provenance_for_result(frame, opline->result.var, source, path, depth);
}

static zend_bool hookphuzz_element_key_matches(const hookphuzz_element_provenance *item, const zval *key)
{
    while (Z_TYPE_P(key) == IS_REFERENCE) key = Z_REFVAL_P(key);
    if (item->key_type != Z_TYPE_P(key)) return 0;
    if (item->key_type == IS_STRING) return zend_string_equals(item->string_key, Z_STR_P(key));
    if (item->key_type == IS_LONG) return item->int_key == Z_LVAL_P(key);
    return 0;
}

static hookphuzz_element_provenance *hookphuzz_find_element_provenance(HashTable *array, const zval *key)
{
    uint32_t index;

    if (array == NULL || key == NULL) return NULL;
    for (index = 0; index < HOOKPHUZZ_PHASE5_G(element_provenance_count); index++) {
        hookphuzz_element_provenance *item = &HOOKPHUZZ_PHASE5_G(element_provenance)[index];
        if (item->array == array && hookphuzz_element_key_matches(item, key)) return item;
    }
    return NULL;
}

static void hookphuzz_clear_element_provenance(HashTable *array, const zval *key)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_PHASE5_G(element_provenance_count); index++) {
        hookphuzz_element_provenance *item = &HOOKPHUZZ_PHASE5_G(element_provenance)[index];
        if (item->array != array || !hookphuzz_element_key_matches(item, key)) continue;
        if (item->string_key != NULL) zend_string_release(item->string_key);
        hookphuzz_release_path(item->path, item->depth);
        HOOKPHUZZ_PHASE5_G(element_provenance_count)--;
        if (index != HOOKPHUZZ_PHASE5_G(element_provenance_count)) {
            HOOKPHUZZ_PHASE5_G(element_provenance)[index] =
                HOOKPHUZZ_PHASE5_G(element_provenance)[HOOKPHUZZ_PHASE5_G(element_provenance_count)];
        }
        return;
    }
}

static void hookphuzz_set_element_provenance(HashTable *array, const zval *key,
    hookphuzz_source source, const hookphuzz_path_key *path, uint32_t depth)
{
    hookphuzz_element_provenance *item;

    if (array == NULL || key == NULL) return;
    while (Z_TYPE_P(key) == IS_REFERENCE) key = Z_REFVAL_P(key);
    if (Z_TYPE_P(key) != IS_STRING && Z_TYPE_P(key) != IS_LONG) return;
    item = hookphuzz_find_element_provenance(array, key);
    if (item == NULL) {
        if (HOOKPHUZZ_PHASE5_G(element_provenance_count) == HOOKPHUZZ_OPCODE_PHASE5_MAX_EVENTS) return;
        if (HOOKPHUZZ_PHASE5_G(element_provenance) == NULL) {
            HOOKPHUZZ_PHASE5_G(element_provenance) =
                ecalloc(HOOKPHUZZ_OPCODE_PHASE5_MAX_EVENTS, sizeof(hookphuzz_element_provenance));
        }
        item = &HOOKPHUZZ_PHASE5_G(element_provenance)[HOOKPHUZZ_PHASE5_G(element_provenance_count)++];
    } else {
        if (item->string_key != NULL) zend_string_release(item->string_key);
        hookphuzz_release_path(item->path, item->depth);
    }
    item->array = array;
    item->key_type = Z_TYPE_P(key);
    item->int_key = Z_TYPE_P(key) == IS_LONG ? Z_LVAL_P(key) : 0;
    item->string_key = Z_TYPE_P(key) == IS_STRING ? zend_string_copy(Z_STR_P(key)) : NULL;
    item->source = source;
    item->depth = depth;
    item->path = hookphuzz_copy_path(path, depth);
}

static void hookphuzz_clear_provenance_for_opline_result(const zend_execute_data *frame, const zend_op *opline)
{
    if (opline->result_type == IS_TMP_VAR || opline->result_type == IS_VAR || opline->result_type == IS_CV) {
        hookphuzz_clear_provenance_for_result(frame, opline->result.var);
    }
}

static hookphuzz_provenance *hookphuzz_find_operand_provenance(const zend_execute_data *frame,
    zend_uchar operand_type, const znode_op *operand)
{
    if (operand_type != IS_TMP_VAR && operand_type != IS_VAR && operand_type != IS_CV) return NULL;
    return hookphuzz_find_provenance(frame, operand->var);
}

static zval *hookphuzz_operand_zval(zend_execute_data *execute_data, const zend_op *opline,
    zend_uchar operand_type, const znode_op *operand)
{
    if (operand_type == IS_CONST) return (zval *) RT_CONSTANT(opline, *operand);
    if (operand_type == IS_TMP_VAR || operand_type == IS_VAR || operand_type == IS_CV) {
        return zend_get_zval_ptr(opline, operand_type, operand, execute_data);
    }
    return NULL;
}

static zend_string *hookphuzz_scalar_copy(const zval *value)
{
    if (value == NULL) return NULL;
    while (Z_TYPE_P(value) == IS_REFERENCE) value = Z_REFVAL_P(value);
    switch (Z_TYPE_P(value)) {
        case IS_STRING:
            if (Z_STRLEN_P(value) > HOOKPHUZZ_CMPLOG_MAX_VALUE_BYTES) return NULL;
            return zend_string_copy(Z_STR_P(value));
        case IS_LONG:
            return strpprintf(0, "%ld", (long) Z_LVAL_P(value));
        case IS_TRUE:
            return zend_string_init("true", sizeof("true") - 1, 0);
        case IS_FALSE:
            return zend_string_init("false", sizeof("false") - 1, 0);
        case IS_DOUBLE:
            return strpprintf(0, "%.17g", Z_DVAL_P(value));
        default:
            return NULL;
    }
}

static zend_bool hookphuzz_contains_ci(const zend_string *value, const char *needle)
{
    size_t value_length, needle_length, index, needle_index;

    if (value == NULL || needle == NULL) return 0;
    value_length = ZSTR_LEN(value);
    needle_length = strlen(needle);
    if (needle_length == 0 || needle_length > value_length) return 0;
    for (index = 0; index + needle_length <= value_length; index++) {
        for (needle_index = 0; needle_index < needle_length; needle_index++) {
            if (tolower((unsigned char) ZSTR_VAL(value)[index + needle_index])
                != tolower((unsigned char) needle[needle_index])) break;
        }
        if (needle_index == needle_length) return 1;
    }
    return 0;
}

static zend_bool hookphuzz_sensitive_path(const hookphuzz_provenance *provenance)
{
    const zend_string *last;

    if (provenance == NULL || provenance->depth == 0) return 1;
    last = provenance->path[provenance->depth - 1].string_value;
    if (last == NULL) return 0;
    return hookphuzz_contains_ci(last, "nonce")
        || hookphuzz_contains_ci(last, "password")
        || hookphuzz_contains_ci(last, "secret")
        || hookphuzz_contains_ci(last, "token")
        || hookphuzz_contains_ci(last, "authorization")
        || hookphuzz_contains_ci(last, "auth");
}

static const char *hookphuzz_comparison_opcode_name(zend_uchar opcode)
{
    switch (opcode) {
        case ZEND_IS_EQUAL: return "IS_EQUAL";
        case ZEND_IS_NOT_EQUAL: return "IS_NOT_EQUAL";
        case ZEND_IS_IDENTICAL: return "IS_IDENTICAL";
        case ZEND_IS_NOT_IDENTICAL: return "IS_NOT_IDENTICAL";
    }
    return NULL;
}

static zend_bool hookphuzz_same_string(const zend_string *left, const zend_string *right)
{
    return left != NULL && right != NULL && ZSTR_LEN(left) == ZSTR_LEN(right)
        && memcmp(ZSTR_VAL(left), ZSTR_VAL(right), ZSTR_LEN(left)) == 0;
}

static zend_bool hookphuzz_same_comparison_path(const hookphuzz_comparison_event *event,
    const hookphuzz_provenance *provenance)
{
    uint32_t index;

    if (event->source != provenance->source || event->depth != provenance->depth) return 0;
    for (index = 0; index < event->depth; index++) {
        if (event->path[index].type != provenance->path[index].type
            || event->path[index].int_value != provenance->path[index].int_value) return 0;
        if (event->path[index].type == IS_STRING
            && !hookphuzz_same_string(event->path[index].string_value, provenance->path[index].string_value)) return 0;
    }
    return 1;
}

static void hookphuzz_record_comparison_event(const zend_execute_data *execute_data, const zend_op *opline,
    const hookphuzz_provenance *provenance, const zval *runtime_value, const zval *comparison_value,
    const char *opcode, const char *provenance_operand)
{
    hookphuzz_context_frame *context;
    zend_string *runtime_copy, *comparison_copy;
    hookphuzz_comparison_event *event;
    uint32_t index;

    context = hookphuzz_find_context(execute_data);
    if (context == NULL || hookphuzz_sensitive_path(provenance)) return;
    runtime_copy = hookphuzz_scalar_copy(runtime_value);
    comparison_copy = hookphuzz_scalar_copy(comparison_value);
    if (runtime_copy == NULL || comparison_copy == NULL) {
        if (runtime_copy != NULL) zend_string_release(runtime_copy);
        if (comparison_copy != NULL) zend_string_release(comparison_copy);
        return;
    }
    if (hookphuzz_same_string(runtime_copy, comparison_copy)) {
        zend_string_release(runtime_copy);
        zend_string_release(comparison_copy);
        return;
    }
    for (index = 0; index < HOOKPHUZZ_G(comparison_event_count); index++) {
        event = &HOOKPHUZZ_G(comparison_events)[index];
        if (event->opcode == opcode && event->provenance_operand == provenance_operand
            && hookphuzz_same_string(event->runtime_value, runtime_copy)
            && hookphuzz_same_string(event->comparison_value, comparison_copy)
            && hookphuzz_same_string(event->root_callback, context->root_callback)
            && hookphuzz_same_comparison_path(event, provenance)) {
            zend_string_release(runtime_copy);
            zend_string_release(comparison_copy);
            return;
        }
    }
    if (HOOKPHUZZ_G(comparison_event_count) == HOOKPHUZZ_CMPLOG_MAX_EVENTS) {
        HOOKPHUZZ_G(dropped_comparison_event_count)++;
        zend_string_release(runtime_copy);
        zend_string_release(comparison_copy);
        return;
    }
    if (HOOKPHUZZ_G(comparison_events) == NULL) {
        HOOKPHUZZ_G(comparison_events) = ecalloc(HOOKPHUZZ_CMPLOG_MAX_EVENTS, sizeof(hookphuzz_comparison_event));
    }
    event = &HOOKPHUZZ_G(comparison_events)[HOOKPHUZZ_G(comparison_event_count)++];
    event->source = provenance->source;
    event->depth = provenance->depth;
    event->path = hookphuzz_copy_path(provenance->path, provenance->depth);
    event->opcode = opcode;
    event->provenance_operand = provenance_operand;
    event->runtime_value = runtime_copy;
    event->comparison_value = comparison_copy;
    event->root_callback = zend_string_copy(context->root_callback);
    event->current_function = zend_string_copy(context->current_function);
    event->attributed = 1;
    event->callback_depth = context->depth;
    event->line = opline->lineno;
}

static int hookphuzz_copy_provenance_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    zend_uchar source_type = opline->op1_type;
    const znode_op *source_operand = &opline->op1;
    hookphuzz_provenance *provenance;

    if (!HOOKPHUZZ_PHASE5_G(artifact_enabled)) return ZEND_USER_OPCODE_DISPATCH;
    if (opline->opcode == ZEND_ASSIGN) {
        source_type = opline->op2_type;
        source_operand = &opline->op2;
    }
    provenance = hookphuzz_find_operand_provenance(execute_data, source_type, source_operand);
    if (provenance != NULL) {
        hookphuzz_set_provenance(execute_data, opline, provenance->source,
            hookphuzz_copy_path(provenance->path, provenance->depth), provenance->depth);
        if (opline->opcode == ZEND_ASSIGN
            && (opline->op1_type == IS_TMP_VAR || opline->op1_type == IS_VAR || opline->op1_type == IS_CV)) {
            hookphuzz_set_provenance_for_result(execute_data, opline->op1.var, provenance->source,
                hookphuzz_copy_path(provenance->path, provenance->depth), provenance->depth);
        }
    } else {
        hookphuzz_clear_provenance_for_opline_result(execute_data, opline);
        if (opline->opcode == ZEND_ASSIGN
            && (opline->op1_type == IS_TMP_VAR || opline->op1_type == IS_VAR || opline->op1_type == IS_CV)) {
            hookphuzz_clear_provenance_for_result(execute_data, opline->op1.var);
        }
    }
    return ZEND_USER_OPCODE_DISPATCH;
}

static int hookphuzz_comparison_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    const char *opcode = hookphuzz_comparison_opcode_name(opline->opcode);
    hookphuzz_provenance *left_provenance, *right_provenance;
    zval *left, *right;

    if (!HOOKPHUZZ_PHASE5_G(artifact_enabled) || opcode == NULL) return ZEND_USER_OPCODE_DISPATCH;
    left_provenance = hookphuzz_find_operand_provenance(execute_data, opline->op1_type, &opline->op1);
    right_provenance = hookphuzz_find_operand_provenance(execute_data, opline->op2_type, &opline->op2);
    if ((left_provenance == NULL) == (right_provenance == NULL)) return ZEND_USER_OPCODE_DISPATCH;
    left = hookphuzz_operand_zval(execute_data, opline, opline->op1_type, &opline->op1);
    right = hookphuzz_operand_zval(execute_data, opline, opline->op2_type, &opline->op2);
    if (left == NULL || right == NULL) return ZEND_USER_OPCODE_DISPATCH;
    if (left_provenance != NULL) {
        hookphuzz_record_comparison_event(execute_data, opline, left_provenance, left, right, opcode, "op1");
    } else {
        hookphuzz_record_comparison_event(execute_data, opline, right_provenance, right, left, opcode, "op2");
    }
    return ZEND_USER_OPCODE_DISPATCH;
}

static int hookphuzz_switch_string_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    hookphuzz_provenance *provenance;
    zval *value, *jump_table;
    zend_string *key;
    zval *jump;

    if (!HOOKPHUZZ_PHASE5_G(artifact_enabled)) return ZEND_USER_OPCODE_DISPATCH;
    provenance = hookphuzz_find_operand_provenance(execute_data, opline->op1_type, &opline->op1);
    if (provenance == NULL) return ZEND_USER_OPCODE_DISPATCH;
    value = hookphuzz_operand_zval(execute_data, opline, opline->op1_type, &opline->op1);
    jump_table = (zval *) RT_CONSTANT(opline, opline->op2);
    if (value == NULL || jump_table == NULL || Z_TYPE_P(jump_table) != IS_ARRAY) return ZEND_USER_OPCODE_DISPATCH;
    ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(jump_table), key, jump) {
        zval target;
        (void) jump;
        if (key == NULL) continue;
        ZVAL_STR(&target, key);
        hookphuzz_record_comparison_event(execute_data, opline, provenance, value, &target,
            "SWITCH_STRING", "op1");
    } ZEND_HASH_FOREACH_END();
    return ZEND_USER_OPCODE_DISPATCH;
}

static zend_bool hookphuzz_is_call_result_opcode(zend_uchar opcode)
{
    return opcode == ZEND_DO_FCALL || opcode == ZEND_DO_UCALL || opcode == ZEND_DO_ICALL;
}

static void hookphuzz_propagate_return_provenance(zend_execute_data *execute_data)
{
    const zend_op *return_opline;
    const zend_execute_data *caller;
    const zend_op *call_opline;
    hookphuzz_provenance *provenance;

    if (!HOOKPHUZZ_PHASE5_G(artifact_enabled)) return;
    return_opline = execute_data->opline;
    if (return_opline == NULL
        || (return_opline->opcode != ZEND_RETURN && return_opline->opcode != ZEND_RETURN_BY_REF)) return;
    provenance = hookphuzz_find_operand_provenance(execute_data, return_opline->op1_type, &return_opline->op1);
    if (provenance == NULL) return;
    caller = execute_data->prev_execute_data;
    if (caller == NULL || caller->opline == NULL) return;
    call_opline = caller->opline;
    if (!hookphuzz_is_call_result_opcode(call_opline->opcode)) return;
    if (call_opline->result_type != IS_TMP_VAR && call_opline->result_type != IS_VAR) return;
    hookphuzz_set_provenance_for_result(caller, call_opline->result.var, provenance->source,
        hookphuzz_copy_path(provenance->path, provenance->depth), provenance->depth);
}

static zend_bool hookphuzz_source_from_fetch(const zend_op *opline, hookphuzz_source *source)
{
    const zval *name;

    if ((opline->extended_value & ZEND_FETCH_GLOBAL) == 0 || opline->op1_type != IS_CONST) return 0;
    name = RT_CONSTANT(opline, opline->op1);
    if (Z_TYPE_P(name) != IS_STRING) return 0;
    if (zend_string_equals_literal(Z_STR_P(name), "_GET")) *source = HOOKPHUZZ_SOURCE_GET;
    else if (zend_string_equals_literal(Z_STR_P(name), "_POST")) *source = HOOKPHUZZ_SOURCE_POST;
    else if (zend_string_equals_literal(Z_STR_P(name), "_REQUEST")) *source = HOOKPHUZZ_SOURCE_REQUEST;
    else if (zend_string_equals_literal(Z_STR_P(name), "_COOKIE")) *source = HOOKPHUZZ_SOURCE_COOKIE;
    else return 0;
    return 1;
}

static void hookphuzz_record_event_with_depth(const zend_execute_data *execute_data, const zend_op *opline,
    const hookphuzz_provenance *provenance, hookphuzz_path_key *path, uint32_t depth, const char *operation)
{
    hookphuzz_event *event;
    hookphuzz_context_frame *context;

    if (HOOKPHUZZ_PHASE5_G(event_count) == HOOKPHUZZ_OPCODE_PHASE5_MAX_EVENTS) {
        HOOKPHUZZ_PHASE5_G(dropped_event_count)++;
        hookphuzz_release_path(path, depth);
        return;
    }
    if (HOOKPHUZZ_PHASE5_G(events) == NULL) {
        HOOKPHUZZ_PHASE5_G(events) = ecalloc(HOOKPHUZZ_OPCODE_PHASE5_MAX_EVENTS, sizeof(hookphuzz_event));
    }
    event = &HOOKPHUZZ_PHASE5_G(events)[HOOKPHUZZ_PHASE5_G(event_count)++];
    event->source = provenance->source;
    event->depth = depth;
    event->path = path;
    event->filename = hookphuzz_copy_filename(execute_data);
    event->function_name = hookphuzz_copy_function_name(execute_data);
    event->class_name = hookphuzz_copy_class_name(execute_data);
    context = hookphuzz_find_context(execute_data);
    event->attributed = context != NULL;
    event->root_callback = context == NULL ? NULL : zend_string_copy(context->root_callback);
    event->current_function = context == NULL ? hookphuzz_normalize_function(execute_data)
        : zend_string_copy(context->current_function);
    event->callback_depth = context == NULL ? 0 : context->depth;
    event->line = opline->lineno;
    event->operation = operation;
}

static void hookphuzz_record_event(const zend_execute_data *execute_data, const zend_op *opline,
    const hookphuzz_provenance *provenance, hookphuzz_path_key *path, const char *operation)
{
    hookphuzz_record_event_with_depth(execute_data, opline, provenance, path,
        provenance->depth + 1, operation);
}

static int hookphuzz_fetch_handler(zend_execute_data *execute_data)
{
    hookphuzz_source source;
    const zend_op *opline = execute_data->opline;

    if (!HOOKPHUZZ_PHASE5_G(artifact_enabled)) return ZEND_USER_OPCODE_DISPATCH;
    if (hookphuzz_source_from_fetch(opline, &source)) {
        hookphuzz_set_provenance(execute_data, opline, source, NULL, 0);
    }
    return ZEND_USER_OPCODE_DISPATCH;
}

static int hookphuzz_fetch_obj_r_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    const zval *property;
    zval *object = NULL;

    if (!HOOKPHUZZ_PHASE5_G(artifact_enabled)) return ZEND_USER_OPCODE_DISPATCH;
    if (opline->op2_type != IS_CONST) return ZEND_USER_OPCODE_DISPATCH;
    property = RT_CONSTANT(opline, opline->op2);
    if (Z_TYPE_P(property) != IS_STRING || !zend_string_equals_literal(Z_STR_P(property), "params")) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    if (opline->result_type == IS_TMP_VAR || opline->result_type == IS_VAR) {
        hookphuzz_clear_provenance_for_result(execute_data, opline->result.var);
    }
    if (opline->op1_type == IS_UNUSED) {
        if (Z_TYPE(EX(This)) == IS_OBJECT) object = &EX(This);
    } else {
        object = zend_get_zval_ptr(opline, opline->op1_type, &opline->op1, execute_data);
    }
    if (object == NULL || Z_TYPE_P(object) != IS_OBJECT || Z_OBJCE_P(object)->name == NULL
        || !zend_string_equals_literal(Z_OBJCE_P(object)->name, "WP_REST_Request")) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    hookphuzz_set_provenance(execute_data, opline, HOOKPHUZZ_SOURCE_REST, NULL, 0);
    return ZEND_USER_OPCODE_DISPATCH;
}

static zend_bool hookphuzz_foreach_key(zval *iterator, zval *key)
{
    HashTable *array;
    HashPosition position;
    zend_string *string_key = NULL;
    zend_ulong int_key = 0;
    int key_type;

    while (Z_TYPE_P(iterator) == IS_REFERENCE) iterator = Z_REFVAL_P(iterator);
    if (Z_TYPE_P(iterator) != IS_ARRAY) return 0;
    array = Z_ARRVAL_P(iterator);
    position = Z_FE_POS_P(iterator);
    key_type = zend_hash_get_current_key_ex(array, &string_key, &int_key, &position);
    if (key_type == HASH_KEY_IS_STRING) {
        ZVAL_STR_COPY(key, string_key);
        return 1;
    }
    if (key_type == HASH_KEY_IS_LONG) {
        ZVAL_LONG(key, int_key);
        return 1;
    }
    return 0;
}

static int hookphuzz_fe_reset_r_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    hookphuzz_provenance *provenance;

    if (!HOOKPHUZZ_PHASE5_G(artifact_enabled)) return ZEND_USER_OPCODE_DISPATCH;
    provenance = hookphuzz_find_operand_provenance(execute_data, opline->op1_type, &opline->op1);
    if (provenance != NULL && opline->result_type == IS_VAR) {
        hookphuzz_set_provenance_for_result(execute_data, opline->result.var, provenance->source,
            hookphuzz_copy_path(provenance->path, provenance->depth), provenance->depth);
    } else if (opline->result_type == IS_VAR) {
        hookphuzz_clear_provenance_for_result(execute_data, opline->result.var);
    }
    return ZEND_USER_OPCODE_DISPATCH;
}

static int hookphuzz_fe_fetch_r_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    hookphuzz_provenance *provenance;
    hookphuzz_path_key *path;
    zval key;
    zval *iterator;

    if (!HOOKPHUZZ_PHASE5_G(artifact_enabled)) return ZEND_USER_OPCODE_DISPATCH;
    if (opline->op2_type != IS_CV && opline->op2_type != IS_VAR) return ZEND_USER_OPCODE_DISPATCH;
    provenance = hookphuzz_find_provenance(execute_data, opline->op1.var);
    iterator = EX_VAR(opline->op1.var);
    if (provenance == NULL || !hookphuzz_foreach_key(iterator, &key)) {
        hookphuzz_clear_provenance_for_result(execute_data, opline->op2.var);
        return ZEND_USER_OPCODE_DISPATCH;
    }
    path = hookphuzz_append_path(provenance, &key);
    hookphuzz_set_provenance_for_result(execute_data, opline->op2.var, provenance->source,
        path, provenance->depth + 1);
    zval_ptr_dtor(&key);
    return ZEND_USER_OPCODE_DISPATCH;
}

static int hookphuzz_assign_dim_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    zval *container;
    zval *key;
    hookphuzz_provenance *provenance;
    const zend_op *data_opline = opline + 1;

    if (!HOOKPHUZZ_PHASE5_G(artifact_enabled)) return ZEND_USER_OPCODE_DISPATCH;
    if (opline->op2_type == IS_UNUSED) return ZEND_USER_OPCODE_DISPATCH;
    container = hookphuzz_operand_zval(execute_data, opline, opline->op1_type, &opline->op1);
    key = hookphuzz_operand_zval(execute_data, opline, opline->op2_type, &opline->op2);
    if (container == NULL || key == NULL) return ZEND_USER_OPCODE_DISPATCH;
    while (Z_TYPE_P(container) == IS_REFERENCE) container = Z_REFVAL_P(container);
    if (Z_TYPE_P(container) != IS_ARRAY) return ZEND_USER_OPCODE_DISPATCH;
    provenance = hookphuzz_find_operand_provenance(execute_data, data_opline->op1_type, &data_opline->op1);
    if (provenance != NULL) {
        hookphuzz_set_element_provenance(Z_ARRVAL_P(container), key, provenance->source,
            provenance->path, provenance->depth);
    } else {
        hookphuzz_clear_element_provenance(Z_ARRVAL_P(container), key);
    }
    return ZEND_USER_OPCODE_DISPATCH;
}

static int hookphuzz_fetch_dim_handler(zend_execute_data *execute_data, const char *operation)
{
    const zend_op *opline = execute_data->opline;
    const zval *key;
    zval *container;
    hookphuzz_element_provenance *element_provenance;
    hookphuzz_provenance *provenance;
    hookphuzz_provenance element_as_provenance;
    hookphuzz_path_key *path;

    if (!HOOKPHUZZ_PHASE5_G(artifact_enabled)) return ZEND_USER_OPCODE_DISPATCH;
    if (opline->op1_type != IS_TMP_VAR && opline->op1_type != IS_VAR && opline->op1_type != IS_CV) {
        hookphuzz_clear_provenance_for_opline_result(execute_data, opline);
        return ZEND_USER_OPCODE_DISPATCH;
    }
    key = zend_get_zval_ptr(opline, opline->op2_type, &opline->op2, execute_data);
    if (key == NULL || (Z_TYPE_P(key) != IS_STRING && Z_TYPE_P(key) != IS_LONG)) {
        hookphuzz_clear_provenance_for_opline_result(execute_data, opline);
        return ZEND_USER_OPCODE_DISPATCH;
    }
    container = hookphuzz_operand_zval(execute_data, opline, opline->op1_type, &opline->op1);
    while (container != NULL && Z_TYPE_P(container) == IS_REFERENCE) container = Z_REFVAL_P(container);
    element_provenance = container != NULL && Z_TYPE_P(container) == IS_ARRAY
        ? hookphuzz_find_element_provenance(Z_ARRVAL_P(container), key) : NULL;
    if (element_provenance != NULL) {
        element_as_provenance.source = element_provenance->source;
        element_as_provenance.depth = element_provenance->depth;
        element_as_provenance.path = element_provenance->path;
        hookphuzz_record_event_with_depth(execute_data, opline, &element_as_provenance,
            hookphuzz_copy_path(element_provenance->path, element_provenance->depth),
            element_provenance->depth, operation);
        hookphuzz_set_provenance(execute_data, opline, element_provenance->source,
            hookphuzz_copy_path(element_provenance->path, element_provenance->depth),
            element_provenance->depth);
        return ZEND_USER_OPCODE_DISPATCH;
    }
    provenance = hookphuzz_find_provenance(execute_data, opline->op1.var);
    if (provenance == NULL) {
        hookphuzz_clear_provenance_for_opline_result(execute_data, opline);
        return ZEND_USER_OPCODE_DISPATCH;
    }
    path = hookphuzz_append_path(provenance, key);
    hookphuzz_record_event(execute_data, opline, provenance,
        hookphuzz_copy_path(path, provenance->depth + 1), operation);
    hookphuzz_set_provenance(execute_data, opline, provenance->source, path, provenance->depth + 1);
    return ZEND_USER_OPCODE_DISPATCH;
}

static int hookphuzz_fetch_dim_r_handler(zend_execute_data *execute_data)
{
    return hookphuzz_fetch_dim_handler(execute_data, "read");
}

static int hookphuzz_fetch_dim_is_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    return hookphuzz_fetch_dim_handler(execute_data,
        (opline + 1)->opcode == ZEND_COALESCE ? "null_coalesce" : "silent_read");
}

static int hookphuzz_isempty_dim_obj_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    const zval *key;
    hookphuzz_provenance *provenance;
    hookphuzz_path_key *path;
    const char *operation = (opline->extended_value & ZEND_ISEMPTY) ? "empty" : "isset";

    if (!HOOKPHUZZ_PHASE5_G(artifact_enabled)) return ZEND_USER_OPCODE_DISPATCH;
    if (opline->op1_type != IS_TMP_VAR && opline->op1_type != IS_VAR) return ZEND_USER_OPCODE_DISPATCH;
    provenance = hookphuzz_find_provenance(execute_data, opline->op1.var);
    if (provenance == NULL) return ZEND_USER_OPCODE_DISPATCH;
    key = zend_get_zval_ptr(opline, opline->op2_type, &opline->op2, execute_data);
    if (key == NULL || (Z_TYPE_P(key) != IS_STRING && Z_TYPE_P(key) != IS_LONG)) return ZEND_USER_OPCODE_DISPATCH;
    path = hookphuzz_append_path(provenance, key);
    hookphuzz_record_event(execute_data, opline, provenance, path, operation);
    return ZEND_USER_OPCODE_DISPATCH;
}

static int hookphuzz_return_handler(zend_execute_data *execute_data)
{
    hookphuzz_propagate_return_provenance(execute_data);
    return ZEND_USER_OPCODE_DISPATCH;
}

static void hookphuzz_frame_end_handler(zend_execute_data *execute_data, zval *retval)
{
    (void) retval;
    hookphuzz_remove_frame_provenance(execute_data);
    hookphuzz_context_end(execute_data);
}

static void hookphuzz_frame_begin_handler(zend_execute_data *execute_data)
{
    hookphuzz_context_begin(execute_data);
}

static zend_observer_fcall_handlers hookphuzz_observer_init(zend_execute_data *execute_data)
{
    zend_observer_fcall_handlers handlers = {NULL, NULL};
    zend_string *name;
    zend_bool observe;

    if (!HOOKPHUZZ_PHASE5_G(artifact_enabled) || execute_data == NULL || execute_data->func == NULL
        || !ZEND_USER_CODE(execute_data->func->type)) return handlers;
    name = hookphuzz_normalize_function(execute_data);
    observe = hookphuzz_is_target(name) || HOOKPHUZZ_G(context_count) > 0;
    if (name != NULL) zend_string_release(name);
    if (observe) {
        handlers.begin = hookphuzz_frame_begin_handler;
        handlers.end = hookphuzz_frame_end_handler;
    }
    return handlers;
}

static zend_bool hookphuzz_valid_request_id(const zend_string *request_id)
{
    size_t index;
    const unsigned char *value = (const unsigned char *) ZSTR_VAL(request_id);

    if (ZSTR_LEN(request_id) == 0 || ZSTR_LEN(request_id) > 128) return 0;
    if (!isalnum(value[0])) return 0;
    for (index = 1; index < ZSTR_LEN(request_id); index++) {
        if (!isalnum(value[index]) && value[index] != '.' && value[index] != '_' && value[index] != '-') return 0;
    }
    return 1;
}

static zend_string *hookphuzz_redact_uri(const char *request_uri)
{
    const char *query;
    const char *cursor;
    smart_str output = {0};

    if (request_uri == NULL || request_uri[0] == '\0') return zend_string_init("/", 1, 0);
    query = strchr(request_uri, '?');
    if (query == NULL) return zend_string_init(request_uri, strlen(request_uri), 0);
    smart_str_appendl(&output, request_uri, query - request_uri + 1);
    cursor = query + 1;
    while (*cursor != '\0') {
        const char *end = cursor;
        const char *equals;
        while (*end != '\0' && *end != '&' && *end != ';') end++;
        equals = memchr(cursor, '=', end - cursor);
        if (equals != NULL) smart_str_appendl(&output, cursor, equals - cursor + 1);
        else if (end != cursor) {
            smart_str_appendl(&output, cursor, end - cursor);
            smart_str_appendc(&output, '=');
        }
        if (end != cursor) smart_str_appends(&output, "<redacted>");
        if (*end != '\0') smart_str_appendc(&output, *end);
        cursor = *end == '\0' ? end : end + 1;
    }
    smart_str_0(&output);
    return output.s == NULL ? zend_string_init("/", 1, 0) : output.s;
}

static void hookphuzz_log(const char *message)
{
    if (sapi_module.log_message != NULL) sapi_module.log_message(message, 0);
}

static zend_string *hookphuzz_request_id_from_server(void)
{
    zval *server;
    zval *header;

    if (!zend_is_auto_global_str(ZEND_STRL("_SERVER"))) return NULL;
    server = &PG(http_globals)[TRACK_VARS_SERVER];
    if (Z_TYPE_P(server) != IS_ARRAY) return NULL;
    header = zend_hash_str_find(Z_ARRVAL_P(server), ZEND_STRL("HTTP_X_FUZZER_COVID"));
    if (header == NULL || Z_TYPE_P(header) != IS_STRING) return NULL;
    return zend_string_copy(Z_STR_P(header));
}

static zend_string *hookphuzz_controlled_marker_from_server(void)
{
    zval *server;
    zval *header;

    if (!zend_is_auto_global_str(ZEND_STRL("_SERVER"))) return NULL;
    server = &PG(http_globals)[TRACK_VARS_SERVER];
    if (Z_TYPE_P(server) != IS_ARRAY) return NULL;
    header = zend_hash_str_find(Z_ARRVAL_P(server), ZEND_STRL("HTTP_X_HOOKPHUZZ_MARKER"));
    if (header == NULL || Z_TYPE_P(header) != IS_STRING
        || Z_STRLEN_P(header) < sizeof("HOOKPHUZZ_") - 1
        || memcmp(Z_STRVAL_P(header), "HOOKPHUZZ_", sizeof("HOOKPHUZZ_") - 1) != 0) return NULL;
    return zend_string_copy(Z_STR_P(header));
}

/* The run id is correlation metadata only.  Parameter proof remains the
 * marker returned by the fixture after reading hookphuzz_key. */
static zend_string *hookphuzz_run_id_from_server(void)
{
    zval *server;
    zval *header;

    if (!zend_is_auto_global_str(ZEND_STRL("_SERVER"))) return NULL;
    server = &PG(http_globals)[TRACK_VARS_SERVER];
    if (Z_TYPE_P(server) != IS_ARRAY) return NULL;
    header = zend_hash_str_find(Z_ARRVAL_P(server), ZEND_STRL("HTTP_X_HOOKPHUZZ_RUN_ID"));
    if (header == NULL || Z_TYPE_P(header) != IS_STRING || !hookphuzz_valid_request_id(Z_STR_P(header))) return NULL;
    return zend_string_copy(Z_STR_P(header));
}

static zend_string *hookphuzz_parameter_key(const hookphuzz_event *event)
{
    smart_str key = {0};
    uint32_t index;

    smart_str_appends(&key, hookphuzz_source_name(event->source));
    smart_str_appendc(&key, '|');
    smart_str_appends(&key, event->operation);
    for (index = 0; index < event->depth; index++) {
        smart_str_appendc(&key, '|');
        if (event->path[index].type == IS_STRING) {
            smart_str_appendc(&key, 's');
            smart_str_append_long(&key, ZSTR_LEN(event->path[index].string_value));
            smart_str_appendc(&key, ':');
            smart_str_append(&key, event->path[index].string_value);
        } else {
            smart_str_appendc(&key, 'i');
            smart_str_append_long(&key, event->path[index].int_value);
        }
    }
    smart_str_0(&key);
    return key.s;
}

static void hookphuzz_add_summaries(zval *document)
{
    zval by_root, summaries;
    zval *summary;
    uint32_t index, path_index;

    array_init(&by_root);
    for (index = 0; index < HOOKPHUZZ_PHASE5_G(event_count); index++) {
        const hookphuzz_event *event = &HOOKPHUZZ_PHASE5_G(events)[index];
        zval *summary, *count, *seen;
        zend_string *parameter_key;
        if (!event->attributed) continue;
        summary = zend_hash_find(Z_ARRVAL(by_root), event->root_callback);
        if (summary == NULL) {
            zval entry, unique_seen;
            array_init(&entry);
            add_assoc_str(&entry, "callback", zend_string_copy(event->root_callback));
            add_assoc_long(&entry, "event_count", 0);
            array_init(&unique_seen);
            add_assoc_zval(&entry, "unique_seen", &unique_seen);
            summary = zend_hash_update(Z_ARRVAL(by_root), event->root_callback, &entry);
        }
        count = zend_hash_str_find(Z_ARRVAL_P(summary), ZEND_STRL("event_count"));
        Z_LVAL_P(count)++;
        seen = zend_hash_str_find(Z_ARRVAL_P(summary), ZEND_STRL("unique_seen"));
        parameter_key = hookphuzz_parameter_key(event);
        if (!zend_hash_exists(Z_ARRVAL_P(seen), parameter_key)) {
            zval parameter, path;
            array_init(&parameter);
            add_assoc_string(&parameter, "source", (char *) hookphuzz_source_name(event->source));
            {
                zval forms;
                array_init(&forms);
                add_next_index_string(&forms, (char *) event->operation);
                add_assoc_zval(&parameter, "access_forms", &forms);
            }
            add_assoc_long(&parameter, "observed_count", 0);
            add_assoc_long(&parameter, "helper_depth", event->callback_depth);
            array_init_size(&path, event->depth);
            for (path_index = 0; path_index < event->depth; path_index++) {
                if (event->path[path_index].type == IS_STRING) {
                    add_next_index_str(&path, zend_string_copy(event->path[path_index].string_value));
                } else {
                    add_next_index_long(&path, event->path[path_index].int_value);
                }
            }
            add_assoc_zval(&parameter, "path", &path);
            zend_hash_update(Z_ARRVAL_P(seen), parameter_key, &parameter);
        }
        {
            zval *parameter = zend_hash_find(Z_ARRVAL_P(seen), parameter_key);
            zval *observed = parameter == NULL ? NULL : zend_hash_str_find(Z_ARRVAL_P(parameter), ZEND_STRL("observed_count"));
            if (observed != NULL) Z_LVAL_P(observed)++;
        }
        zend_string_release(parameter_key);
    }
    array_init(&summaries);
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL(by_root), summary) {
        zval output, parameters;
        zval *callback = zend_hash_str_find(Z_ARRVAL_P(summary), ZEND_STRL("callback"));
        zval *count = zend_hash_str_find(Z_ARRVAL_P(summary), ZEND_STRL("event_count"));
        zval *seen = zend_hash_str_find(Z_ARRVAL_P(summary), ZEND_STRL("unique_seen"));
        array_init(&output);
        add_assoc_str(&output, "callback", zend_string_copy(Z_STR_P(callback)));
        add_assoc_long(&output, "event_count", Z_LVAL_P(count));
        array_init(&parameters);
        zval *parameter;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(seen), parameter) {
            zval copy;
            ZVAL_COPY(&copy, parameter);
            add_next_index_zval(&parameters, &copy);
        } ZEND_HASH_FOREACH_END();
        add_assoc_zval(&output, "unique_parameters", &parameters);
        add_next_index_zval(&summaries, &output);
    } ZEND_HASH_FOREACH_END();
    add_assoc_zval(document, "callback_summaries", &summaries);
    zval_ptr_dtor(&by_root);
}

static void hookphuzz_add_target_loading(zval *document)
{
    zval loading, loaded_callbacks;
    uint32_t index;

    array_init(&loading);
    add_assoc_long(&loading, "static_target_count", HOOKPHUZZ_G(static_target_count));
    add_assoc_long(&loading, "file_target_count", HOOKPHUZZ_G(file_target_count));
    add_assoc_long(&loading, "effective_target_count", HOOKPHUZZ_G(target_callback_count));
    add_assoc_long(&loading, "target_capacity", HOOKPHUZZ_MAX_TARGETS);
    add_assoc_long(&loading, "requested_target_count", HOOKPHUZZ_G(requested_target_count));
    add_assoc_string(&loading, "load_status", HOOKPHUZZ_G(target_load_status) == NULL ? "disabled"
        : ZSTR_VAL(HOOKPHUZZ_G(target_load_status)));
    if (HOOKPHUZZ_G(registry_schema_version) > 0) {
        add_assoc_long(&loading, "registry_schema_version", HOOKPHUZZ_G(registry_schema_version));
    } else add_assoc_null(&loading, "registry_schema_version");
    add_assoc_long(&loading, "duplicate_count", HOOKPHUZZ_G(target_duplicate_count));
    add_assoc_long(&loading, "rejected_count", HOOKPHUZZ_G(target_rejected_count));
    add_assoc_long(&loading, "capacity_exhausted_count", HOOKPHUZZ_G(target_capacity_exhausted_count));
    array_init_size(&loaded_callbacks, HOOKPHUZZ_G(target_callback_count));
    for (index = 0; index < HOOKPHUZZ_G(target_callback_count); index++) {
        add_next_index_str(&loaded_callbacks, zend_string_copy(HOOKPHUZZ_G(target_callbacks)[index]));
    }
    add_assoc_zval(&loading, "loaded_callbacks", &loaded_callbacks);
    add_assoc_zval(document, "target_loading", &loading);
}

static zend_bool hookphuzz_rest_events_export_allowed(void)
{
    if (HOOKPHUZZ_PHASE5_G(dropped_event_count) > 0) return 0;
    if (HOOKPHUZZ_G(target_callbacks_file_ini) == NULL || HOOKPHUZZ_G(target_callbacks_file_ini)[0] == '\0') return 1;
    return HOOKPHUZZ_G(target_load_status) != NULL
        && zend_string_equals_literal(HOOKPHUZZ_G(target_load_status), "loaded");
}

static void hookphuzz_add_rest_parameter_events(zval *document)
{
    zval rest_events;
    uint32_t index, path_index;

    array_init(&rest_events);
    if (!hookphuzz_rest_events_export_allowed()) {
        add_assoc_zval(document, "rest_parameter_events", &rest_events);
        return;
    }
    for (index = 0; index < HOOKPHUZZ_PHASE5_G(event_count); index++) {
        const hookphuzz_event *event = &HOOKPHUZZ_PHASE5_G(events)[index];
        zval rest_event, path;
        smart_str parameter = {0};
        zend_bool supported_path = 1;
        if (event->source != HOOKPHUZZ_SOURCE_REST || event->depth < 2
            || event->path[0].type != IS_STRING
            || strcmp(event->operation, "read") != 0 || !event->attributed) {
            continue;
        }
        for (path_index = 1; path_index < event->depth; path_index++) {
            if (event->path[path_index].type != IS_STRING && event->path[path_index].type != IS_LONG) {
                supported_path = 0;
                break;
            }
            if (path_index > 1) smart_str_appendc(&parameter, '[');
            if (event->path[path_index].type == IS_STRING) {
                smart_str_append(&parameter, event->path[path_index].string_value);
            } else {
                smart_str_append_long(&parameter, event->path[path_index].int_value);
            }
            if (path_index > 1) smart_str_appendc(&parameter, ']');
        }
        if (!supported_path) {
            smart_str_free(&parameter);
            continue;
        }
        smart_str_0(&parameter);
        if (parameter.s == NULL) continue;
        array_init(&rest_event);
        add_assoc_string(&rest_event, "source", "REST");
        add_assoc_str(&rest_event, "bucket", zend_string_copy(event->path[0].string_value));
        add_assoc_str(&rest_event, "parameter", parameter.s);
        add_assoc_str(&rest_event, "callback", zend_string_copy(event->root_callback));
        add_assoc_long(&rest_event, "observed_count", 1);
        array_init_size(&path, event->depth);
        for (path_index = 0; path_index < event->depth; path_index++) {
            if (event->path[path_index].type == IS_STRING) {
                add_next_index_str(&path, zend_string_copy(event->path[path_index].string_value));
            } else {
                add_next_index_long(&path, event->path[path_index].int_value);
            }
        }
        add_assoc_zval(&rest_event, "path", &path);
        add_next_index_zval(&rest_events, &rest_event);
    }
    add_assoc_zval(document, "rest_parameter_events", &rest_events);
}

static void hookphuzz_add_comparison_events(zval *document)
{
    zval comparison_events;
    uint32_t index, path_index;

    if (HOOKPHUZZ_G(comparison_event_count) == 0) return;
    array_init_size(&comparison_events, HOOKPHUZZ_G(comparison_event_count));
    for (index = 0; index < HOOKPHUZZ_G(comparison_event_count); index++) {
        const hookphuzz_comparison_event *event = &HOOKPHUZZ_G(comparison_events)[index];
        zval comparison, path, context;

        array_init(&comparison);
        add_assoc_str(&comparison, "request_id", zend_string_copy(HOOKPHUZZ_PHASE5_G(request_id)));
        if (event->root_callback != NULL) add_assoc_str(&comparison, "callback", zend_string_copy(event->root_callback));
        else add_assoc_null(&comparison, "callback");
        add_assoc_string(&comparison, "opcode", (char *) event->opcode);
        add_assoc_string(&comparison, "source", (char *) hookphuzz_source_name(event->source));
        array_init_size(&path, event->depth);
        for (path_index = 0; path_index < event->depth; path_index++) {
            if (event->path[path_index].type == IS_STRING) {
                add_next_index_str(&path, zend_string_copy(event->path[path_index].string_value));
            } else {
                add_next_index_long(&path, event->path[path_index].int_value);
            }
        }
        add_assoc_zval(&comparison, "path", &path);
        add_assoc_str(&comparison, "runtime_value", zend_string_copy(event->runtime_value));
        add_assoc_str(&comparison, "comparison_value", zend_string_copy(event->comparison_value));
        add_assoc_string(&comparison, "provenance_operand", (char *) event->provenance_operand);
        add_assoc_long(&comparison, "line", event->line);
        array_init(&context);
        add_assoc_bool(&context, "attributed", event->attributed);
        if (event->current_function != NULL) add_assoc_str(&context, "current_function", zend_string_copy(event->current_function));
        else add_assoc_null(&context, "current_function");
        add_assoc_long(&context, "depth", event->callback_depth);
        add_assoc_zval(&comparison, "callback_context", &context);
        add_next_index_zval(&comparison_events, &comparison);
    }
    add_assoc_zval(document, "comparison_events", &comparison_events);
}

static zend_result hookphuzz_encode_artifact(smart_str *json)
{
    zval document, events;
    uint32_t index, path_index;

    array_init(&document);
    add_assoc_long(&document, "schema_version", 4);
    add_assoc_str(&document, "request_id", zend_string_copy(HOOKPHUZZ_PHASE5_G(request_id)));
    add_assoc_long(&document, "pid", (zend_long) getpid());
    add_assoc_str(&document, "method", zend_string_copy(HOOKPHUZZ_PHASE5_G(request_method)));
    add_assoc_str(&document, "uri", zend_string_copy(HOOKPHUZZ_PHASE5_G(request_uri)));
    {
        zend_string *marker = hookphuzz_controlled_marker_from_server();
        if (marker != NULL) add_assoc_str(&document, "controlled_marker", marker);
    }
    {
        zend_string *run_id = hookphuzz_run_id_from_server();
        if (run_id != NULL) add_assoc_str(&document, "run_id", run_id);
    }
    add_assoc_long(&document, "event_capacity", HOOKPHUZZ_OPCODE_PHASE5_MAX_EVENTS);
    add_assoc_long(&document, "event_count", HOOKPHUZZ_PHASE5_G(event_count));
    add_assoc_long(&document, "dropped_event_count", HOOKPHUZZ_PHASE5_G(dropped_event_count));
    array_init_size(&events, HOOKPHUZZ_PHASE5_G(event_count));
    for (index = 0; index < HOOKPHUZZ_PHASE5_G(event_count); index++) {
        const hookphuzz_event *event = &HOOKPHUZZ_PHASE5_G(events)[index];
        zval event_array, path;
        array_init(&event_array);
        add_assoc_string(&event_array, "source", (char *) hookphuzz_source_name(event->source));
        array_init_size(&path, event->depth);
        for (path_index = 0; path_index < event->depth; path_index++) {
            if (event->path[path_index].type == IS_STRING) {
                add_next_index_str(&path, zend_string_copy(event->path[path_index].string_value));
            } else {
                add_next_index_long(&path, event->path[path_index].int_value);
            }
        }
        add_assoc_zval(&event_array, "path", &path);
        add_assoc_string(&event_array, "operation", (char *) event->operation);
        add_assoc_str(&event_array, "file", zend_string_copy(event->filename));
        add_assoc_long(&event_array, "line", event->line);
        if (event->function_name != NULL) add_assoc_str(&event_array, "function", zend_string_copy(event->function_name));
        else add_assoc_null(&event_array, "function");
        if (event->class_name != NULL) add_assoc_str(&event_array, "class", zend_string_copy(event->class_name));
        else add_assoc_null(&event_array, "class");
        {
            zval context;
            array_init(&context);
            add_assoc_bool(&context, "attributed", event->attributed);
            if (event->root_callback != NULL) add_assoc_str(&context, "root_callback", zend_string_copy(event->root_callback));
            else add_assoc_null(&context, "root_callback");
            if (event->current_function != NULL) add_assoc_str(&context, "current_function", zend_string_copy(event->current_function));
            else add_assoc_null(&context, "current_function");
            if (event->attributed) add_assoc_long(&context, "depth", event->callback_depth);
            else add_assoc_null(&context, "depth");
            add_assoc_zval(&event_array, "callback_context", &context);
        }
        add_next_index_zval(&events, &event_array);
    }
    add_assoc_zval(&document, "events", &events);
    hookphuzz_add_target_loading(&document);
    hookphuzz_add_summaries(&document);
    hookphuzz_add_rest_parameter_events(&document);
    hookphuzz_add_comparison_events(&document);
    php_json_encode(json, &document, PHP_JSON_UNESCAPED_SLASHES);
    zval_ptr_dtor(&document);
    smart_str_0(json);
    return json->s == NULL ? FAILURE : SUCCESS;
}

static zend_result hookphuzz_write_all(int fd, const char *bytes, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, bytes + offset, length - offset);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) return FAILURE;
        offset += (size_t) written;
    }
    return SUCCESS;
}

static void hookphuzz_flush_artifact(void)
{
    char final_path[512], temp_path[640], message[768];
    smart_str json = {0};
    int fd = -1;

    HOOKPHUZZ_PHASE5_G(artifact_flushed) = 1;
    if (hookphuzz_encode_artifact(&json) != SUCCESS) {
        hookphuzz_log("hookphuzz_opcode: artifact JSON encoding failed");
        return;
    }
    snprintf(final_path, sizeof(final_path), HOOKPHUZZ_ARTIFACT_DIR "/%s.json", ZSTR_VAL(HOOKPHUZZ_PHASE5_G(request_id)));
    snprintf(temp_path, sizeof(temp_path), HOOKPHUZZ_ARTIFACT_DIR "/.%s.%ld.tmp",
        ZSTR_VAL(HOOKPHUZZ_PHASE5_G(request_id)), (long) getpid());
    fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || hookphuzz_write_all(fd, ZSTR_VAL(json.s), ZSTR_LEN(json.s)) != SUCCESS || fsync(fd) != 0 || close(fd) != 0) {
        int error_code = errno;
        if (fd >= 0) close(fd);
        unlink(temp_path);
        snprintf(message, sizeof(message), "hookphuzz_opcode: artifact write failed for %s: %s",
            ZSTR_VAL(HOOKPHUZZ_PHASE5_G(request_id)), strerror(error_code));
        hookphuzz_log(message);
        smart_str_free(&json);
        return;
    }
    fd = -1;
    if (syscall(SYS_renameat2, AT_FDCWD, temp_path, AT_FDCWD, final_path, RENAME_NOREPLACE) != 0) {
        int error_code = errno;
        unlink(temp_path);
        snprintf(message, sizeof(message), "hookphuzz_opcode: artifact finalization failed for %s: %s",
            ZSTR_VAL(HOOKPHUZZ_PHASE5_G(request_id)), strerror(error_code));
        hookphuzz_log(message);
    }
    smart_str_free(&json);
}

PHP_MINIT_FUNCTION(hookphuzz_opcode)
{
    if (zend_get_user_opcode_handler(ZEND_FETCH_R) != NULL
        || zend_get_user_opcode_handler(ZEND_FETCH_OBJ_R) != NULL
        || zend_get_user_opcode_handler(ZEND_FETCH_DIM_R) != NULL
        || zend_get_user_opcode_handler(ZEND_FETCH_DIM_FUNC_ARG) != NULL
        || zend_get_user_opcode_handler(ZEND_FE_RESET_R) != NULL
        || zend_get_user_opcode_handler(ZEND_FE_FETCH_R) != NULL
        || zend_get_user_opcode_handler(ZEND_ASSIGN_DIM) != NULL
        || zend_get_user_opcode_handler(ZEND_FETCH_IS) != NULL
        || zend_get_user_opcode_handler(ZEND_FETCH_DIM_IS) != NULL
        || zend_get_user_opcode_handler(ZEND_ISSET_ISEMPTY_DIM_OBJ) != NULL
        || zend_get_user_opcode_handler(ZEND_RETURN) != NULL
        || zend_get_user_opcode_handler(ZEND_RETURN_BY_REF) != NULL
        || zend_get_user_opcode_handler(ZEND_COALESCE) != NULL
        || zend_get_user_opcode_handler(ZEND_QM_ASSIGN) != NULL
        || zend_get_user_opcode_handler(ZEND_CAST) != NULL
        || zend_get_user_opcode_handler(ZEND_ASSIGN) != NULL
        || zend_get_user_opcode_handler(ZEND_JMP_SET) != NULL
        || zend_get_user_opcode_handler(ZEND_IS_EQUAL) != NULL
        || zend_get_user_opcode_handler(ZEND_IS_NOT_EQUAL) != NULL
        || zend_get_user_opcode_handler(ZEND_IS_IDENTICAL) != NULL
        || zend_get_user_opcode_handler(ZEND_IS_NOT_IDENTICAL) != NULL
        || zend_get_user_opcode_handler(ZEND_SWITCH_STRING) != NULL) return FAILURE;
    REGISTER_INI_ENTRIES();
    zend_observer_fcall_register(hookphuzz_observer_init);
    if (zend_set_user_opcode_handler(ZEND_FETCH_R, hookphuzz_fetch_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_FETCH_OBJ_R, hookphuzz_fetch_obj_r_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_FETCH_DIM_R, hookphuzz_fetch_dim_r_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_FETCH_DIM_FUNC_ARG, hookphuzz_fetch_dim_r_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_FE_RESET_R, hookphuzz_fe_reset_r_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_FE_FETCH_R, hookphuzz_fe_fetch_r_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_ASSIGN_DIM, hookphuzz_assign_dim_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_FETCH_IS, hookphuzz_fetch_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_FETCH_DIM_IS, hookphuzz_fetch_dim_is_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_ISSET_ISEMPTY_DIM_OBJ, hookphuzz_isempty_dim_obj_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_RETURN, hookphuzz_return_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_RETURN_BY_REF, hookphuzz_return_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_COALESCE, hookphuzz_copy_provenance_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_QM_ASSIGN, hookphuzz_copy_provenance_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_CAST, hookphuzz_copy_provenance_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_ASSIGN, hookphuzz_copy_provenance_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_JMP_SET, hookphuzz_copy_provenance_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_IS_EQUAL, hookphuzz_comparison_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_IS_NOT_EQUAL, hookphuzz_comparison_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_IS_IDENTICAL, hookphuzz_comparison_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_IS_NOT_IDENTICAL, hookphuzz_comparison_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_SWITCH_STRING, hookphuzz_switch_string_handler) != SUCCESS) return FAILURE;
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(hookphuzz_opcode)
{
    if (zend_get_user_opcode_handler(ZEND_FETCH_R) == hookphuzz_fetch_handler) zend_set_user_opcode_handler(ZEND_FETCH_R, NULL);
    if (zend_get_user_opcode_handler(ZEND_FETCH_OBJ_R) == hookphuzz_fetch_obj_r_handler) zend_set_user_opcode_handler(ZEND_FETCH_OBJ_R, NULL);
    if (zend_get_user_opcode_handler(ZEND_FETCH_DIM_R) == hookphuzz_fetch_dim_r_handler) zend_set_user_opcode_handler(ZEND_FETCH_DIM_R, NULL);
    if (zend_get_user_opcode_handler(ZEND_FETCH_DIM_FUNC_ARG) == hookphuzz_fetch_dim_r_handler) zend_set_user_opcode_handler(ZEND_FETCH_DIM_FUNC_ARG, NULL);
    if (zend_get_user_opcode_handler(ZEND_FE_RESET_R) == hookphuzz_fe_reset_r_handler) zend_set_user_opcode_handler(ZEND_FE_RESET_R, NULL);
    if (zend_get_user_opcode_handler(ZEND_FE_FETCH_R) == hookphuzz_fe_fetch_r_handler) zend_set_user_opcode_handler(ZEND_FE_FETCH_R, NULL);
    if (zend_get_user_opcode_handler(ZEND_ASSIGN_DIM) == hookphuzz_assign_dim_handler) zend_set_user_opcode_handler(ZEND_ASSIGN_DIM, NULL);
    if (zend_get_user_opcode_handler(ZEND_FETCH_IS) == hookphuzz_fetch_handler) zend_set_user_opcode_handler(ZEND_FETCH_IS, NULL);
    if (zend_get_user_opcode_handler(ZEND_FETCH_DIM_IS) == hookphuzz_fetch_dim_is_handler) zend_set_user_opcode_handler(ZEND_FETCH_DIM_IS, NULL);
    if (zend_get_user_opcode_handler(ZEND_ISSET_ISEMPTY_DIM_OBJ) == hookphuzz_isempty_dim_obj_handler) zend_set_user_opcode_handler(ZEND_ISSET_ISEMPTY_DIM_OBJ, NULL);
    if (zend_get_user_opcode_handler(ZEND_RETURN) == hookphuzz_return_handler) zend_set_user_opcode_handler(ZEND_RETURN, NULL);
    if (zend_get_user_opcode_handler(ZEND_RETURN_BY_REF) == hookphuzz_return_handler) zend_set_user_opcode_handler(ZEND_RETURN_BY_REF, NULL);
    if (zend_get_user_opcode_handler(ZEND_COALESCE) == hookphuzz_copy_provenance_handler) zend_set_user_opcode_handler(ZEND_COALESCE, NULL);
    if (zend_get_user_opcode_handler(ZEND_QM_ASSIGN) == hookphuzz_copy_provenance_handler) zend_set_user_opcode_handler(ZEND_QM_ASSIGN, NULL);
    if (zend_get_user_opcode_handler(ZEND_CAST) == hookphuzz_copy_provenance_handler) zend_set_user_opcode_handler(ZEND_CAST, NULL);
    if (zend_get_user_opcode_handler(ZEND_ASSIGN) == hookphuzz_copy_provenance_handler) zend_set_user_opcode_handler(ZEND_ASSIGN, NULL);
    if (zend_get_user_opcode_handler(ZEND_JMP_SET) == hookphuzz_copy_provenance_handler) zend_set_user_opcode_handler(ZEND_JMP_SET, NULL);
    if (zend_get_user_opcode_handler(ZEND_IS_EQUAL) == hookphuzz_comparison_handler) zend_set_user_opcode_handler(ZEND_IS_EQUAL, NULL);
    if (zend_get_user_opcode_handler(ZEND_IS_NOT_EQUAL) == hookphuzz_comparison_handler) zend_set_user_opcode_handler(ZEND_IS_NOT_EQUAL, NULL);
    if (zend_get_user_opcode_handler(ZEND_IS_IDENTICAL) == hookphuzz_comparison_handler) zend_set_user_opcode_handler(ZEND_IS_IDENTICAL, NULL);
    if (zend_get_user_opcode_handler(ZEND_IS_NOT_IDENTICAL) == hookphuzz_comparison_handler) zend_set_user_opcode_handler(ZEND_IS_NOT_IDENTICAL, NULL);
    if (zend_get_user_opcode_handler(ZEND_SWITCH_STRING) == hookphuzz_switch_string_handler) zend_set_user_opcode_handler(ZEND_SWITCH_STRING, NULL);
    UNREGISTER_INI_ENTRIES();
    return SUCCESS;
}

PHP_RINIT_FUNCTION(hookphuzz_opcode)
{
    zend_string *header;

#if defined(ZTS) && defined(COMPILE_DL_HOOKPHUZZ_OPCODE)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    HOOKPHUZZ_PHASE5_G(dropped_event_count) = 0;
    HOOKPHUZZ_PHASE5_G(event_count) = 0;
    HOOKPHUZZ_PHASE5_G(events) = NULL;
    HOOKPHUZZ_G(dropped_comparison_event_count) = 0;
    HOOKPHUZZ_G(comparison_event_count) = 0;
    HOOKPHUZZ_G(comparison_events) = NULL;
    HOOKPHUZZ_PHASE5_G(provenance_count) = 0;
    HOOKPHUZZ_PHASE5_G(provenance) = NULL;
    HOOKPHUZZ_PHASE5_G(element_provenance_count) = 0;
    HOOKPHUZZ_PHASE5_G(element_provenance) = NULL;
    HOOKPHUZZ_PHASE5_G(request_id) = NULL;
    HOOKPHUZZ_PHASE5_G(request_method) = NULL;
    HOOKPHUZZ_PHASE5_G(request_uri) = NULL;
    HOOKPHUZZ_PHASE5_G(artifact_enabled) = 0;
    HOOKPHUZZ_PHASE5_G(artifact_flushed) = 0;
    HOOKPHUZZ_G(context_count) = 0;
    HOOKPHUZZ_G(contexts) = NULL;
    HOOKPHUZZ_G(target_callbacks) = NULL;
    HOOKPHUZZ_G(target_callback_count) = 0;
    HOOKPHUZZ_G(static_target_count) = 0;
    HOOKPHUZZ_G(file_target_count) = 0;
    HOOKPHUZZ_G(requested_target_count) = 0;
    HOOKPHUZZ_G(target_duplicate_count) = 0;
    HOOKPHUZZ_G(target_rejected_count) = 0;
    HOOKPHUZZ_G(target_capacity_exhausted_count) = 0;
    HOOKPHUZZ_G(registry_schema_version) = 0;
    HOOKPHUZZ_G(target_load_status) = NULL;
    HOOKPHUZZ_G(file_targets_loaded) = 1;
    hookphuzz_parse_targets();
    hookphuzz_load_file_targets();

    header = hookphuzz_request_id_from_server();
    if (header == NULL) {
        hookphuzz_log("hookphuzz_opcode: request artifact skipped: missing X-Fuzzer-Covid");
        return SUCCESS;
    }
    if (!hookphuzz_valid_request_id(header)) {
        hookphuzz_log("hookphuzz_opcode: request artifact skipped: invalid X-Fuzzer-Covid");
        zend_string_release(header);
        return SUCCESS;
    }
    HOOKPHUZZ_PHASE5_G(request_id) = header;
    HOOKPHUZZ_PHASE5_G(request_method) = zend_string_init(
        SG(request_info).request_method == NULL ? "" : SG(request_info).request_method,
        SG(request_info).request_method == NULL ? 0 : strlen(SG(request_info).request_method), 0);
    HOOKPHUZZ_PHASE5_G(request_uri) = hookphuzz_redact_uri(SG(request_info).request_uri);
    HOOKPHUZZ_PHASE5_G(artifact_enabled) = 1;
    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(hookphuzz_opcode)
{
    if (HOOKPHUZZ_PHASE5_G(artifact_enabled) && !HOOKPHUZZ_PHASE5_G(artifact_flushed)) hookphuzz_flush_artifact();
    hookphuzz_release_events();
    hookphuzz_release_comparison_events();
    hookphuzz_release_element_provenance();
    hookphuzz_release_provenance();
    hookphuzz_release_contexts();
    hookphuzz_release_targets();
    hookphuzz_release_request_metadata();
    HOOKPHUZZ_PHASE5_G(dropped_event_count) = 0;
    return SUCCESS;
}

PHP_MINFO_FUNCTION(hookphuzz_opcode)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "hookphuzz_opcode support", "enabled");
    php_info_print_table_row(2, "configured user opcodes", "ZEND_FETCH_R, ZEND_FETCH_OBJ_R, ZEND_FETCH_DIM_R, ZEND_FETCH_DIM_FUNC_ARG, ZEND_FE_RESET_R, ZEND_FE_FETCH_R, ZEND_ASSIGN_DIM, ZEND_FETCH_IS, ZEND_FETCH_DIM_IS, ZEND_ISSET_ISEMPTY_DIM_OBJ, ZEND_RETURN, ZEND_RETURN_BY_REF, ZEND_COALESCE, ZEND_QM_ASSIGN, ZEND_CAST, ZEND_ASSIGN, ZEND_JMP_SET, ZEND_IS_EQUAL, ZEND_IS_NOT_EQUAL, ZEND_IS_IDENTICAL, ZEND_IS_NOT_IDENTICAL, ZEND_SWITCH_STRING");
    php_info_print_table_row(2, "artifact output", HOOKPHUZZ_ARTIFACT_DIR);
    php_info_print_table_row(2, "event limit per request", "65536");
    php_info_print_table_end();
}

zend_module_entry hookphuzz_opcode_module_entry = {
    STANDARD_MODULE_HEADER, "hookphuzz_opcode", NULL,
    PHP_MINIT(hookphuzz_opcode), PHP_MSHUTDOWN(hookphuzz_opcode),
    PHP_RINIT(hookphuzz_opcode), PHP_RSHUTDOWN(hookphuzz_opcode),
    PHP_MINFO(hookphuzz_opcode), PHP_HOOKPHUZZ_OPCODE_VERSION, STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_HOOKPHUZZ_OPCODE
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
# endif
ZEND_GET_MODULE(hookphuzz_opcode)
#endif
