#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_hookphuzz_opcode_phase5.h"
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
#include <sys/types.h>
#include <unistd.h>

#define HOOKPHUZZ_ARTIFACT_DIR "/shared/opcode-events"

ZEND_DECLARE_MODULE_GLOBALS(hookphuzz_opcode_phase5)

static const char *hookphuzz_source_name(hookphuzz_source source)
{
    switch (source) {
        case HOOKPHUZZ_SOURCE_GET: return "GET";
        case HOOKPHUZZ_SOURCE_POST: return "POST";
        case HOOKPHUZZ_SOURCE_REQUEST: return "REQUEST";
        case HOOKPHUZZ_SOURCE_COOKIE: return "COOKIE";
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

static void hookphuzz_release_events(void)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_PHASE5_G(event_count); index++) {
        hookphuzz_event *event = &HOOKPHUZZ_PHASE5_G(events)[index];
        hookphuzz_release_path(event->path, event->depth);
        if (event->filename != NULL) zend_string_release(event->filename);
        if (event->function_name != NULL) zend_string_release(event->function_name);
        if (event->class_name != NULL) zend_string_release(event->class_name);
    }
    if (HOOKPHUZZ_PHASE5_G(events) != NULL) efree(HOOKPHUZZ_PHASE5_G(events));
    HOOKPHUZZ_PHASE5_G(events) = NULL;
    HOOKPHUZZ_PHASE5_G(event_count) = 0;
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

static void hookphuzz_set_provenance(const zend_execute_data *frame, const zend_op *opline,
    hookphuzz_source source, hookphuzz_path_key *path, uint32_t depth)
{
    hookphuzz_provenance *item;

    if (opline->result_type != IS_TMP_VAR && opline->result_type != IS_VAR) {
        hookphuzz_release_path(path, depth);
        return;
    }
    item = hookphuzz_find_provenance(frame, opline->result.var);
    if (item == NULL) {
        if (HOOKPHUZZ_PHASE5_G(provenance_count) == HOOKPHUZZ_OPCODE_PHASE5_MAX_EVENTS) {
            hookphuzz_release_path(path, depth);
            return;
        }
        if (HOOKPHUZZ_PHASE5_G(provenance) == NULL) {
            HOOKPHUZZ_PHASE5_G(provenance) = ecalloc(HOOKPHUZZ_OPCODE_PHASE5_MAX_EVENTS, sizeof(hookphuzz_provenance));
        }
        item = &HOOKPHUZZ_PHASE5_G(provenance)[HOOKPHUZZ_PHASE5_G(provenance_count)++];
    } else {
        hookphuzz_release_path(item->path, item->depth);
    }
    item->frame = frame;
    item->result_var = opline->result.var;
    item->source = source;
    item->depth = depth;
    item->path = path;
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

static void hookphuzz_record_event(const zend_execute_data *execute_data, const zend_op *opline,
    const hookphuzz_provenance *provenance, hookphuzz_path_key *path, const char *operation)
{
    hookphuzz_event *event;

    if (HOOKPHUZZ_PHASE5_G(event_count) == HOOKPHUZZ_OPCODE_PHASE5_MAX_EVENTS) {
        HOOKPHUZZ_PHASE5_G(dropped_event_count)++;
        hookphuzz_release_path(path, provenance->depth + 1);
        return;
    }
    if (HOOKPHUZZ_PHASE5_G(events) == NULL) {
        HOOKPHUZZ_PHASE5_G(events) = ecalloc(HOOKPHUZZ_OPCODE_PHASE5_MAX_EVENTS, sizeof(hookphuzz_event));
    }
    event = &HOOKPHUZZ_PHASE5_G(events)[HOOKPHUZZ_PHASE5_G(event_count)++];
    event->source = provenance->source;
    event->depth = provenance->depth + 1;
    event->path = path;
    event->filename = hookphuzz_copy_filename(execute_data);
    event->function_name = hookphuzz_copy_function_name(execute_data);
    event->class_name = hookphuzz_copy_class_name(execute_data);
    event->line = opline->lineno;
    event->operation = operation;
}

static int hookphuzz_fetch_handler(zend_execute_data *execute_data)
{
    hookphuzz_source source;
    const zend_op *opline = execute_data->opline;

    if (hookphuzz_source_from_fetch(opline, &source)) {
        hookphuzz_set_provenance(execute_data, opline, source, NULL, 0);
    }
    return ZEND_USER_OPCODE_DISPATCH;
}

static int hookphuzz_fetch_dim_handler(zend_execute_data *execute_data, const char *operation)
{
    const zend_op *opline = execute_data->opline;
    const zval *key;
    hookphuzz_provenance *provenance;
    hookphuzz_path_key *path;

    if (opline->op1_type != IS_TMP_VAR && opline->op1_type != IS_VAR) return ZEND_USER_OPCODE_DISPATCH;
    provenance = hookphuzz_find_provenance(execute_data, opline->op1.var);
    if (provenance == NULL) return ZEND_USER_OPCODE_DISPATCH;
    key = zend_get_zval_ptr(opline, opline->op2_type, &opline->op2, execute_data);
    if (key == NULL || (Z_TYPE_P(key) != IS_STRING && Z_TYPE_P(key) != IS_LONG)) return ZEND_USER_OPCODE_DISPATCH;
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
    return hookphuzz_fetch_dim_handler(execute_data, "silent_read");
}

static int hookphuzz_isempty_dim_obj_handler(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    const zval *key;
    hookphuzz_provenance *provenance;
    hookphuzz_path_key *path;
    const char *operation = (opline->extended_value & ZEND_ISEMPTY) ? "empty" : "isset";

    if (opline->op1_type != IS_TMP_VAR && opline->op1_type != IS_VAR) return ZEND_USER_OPCODE_DISPATCH;
    provenance = hookphuzz_find_provenance(execute_data, opline->op1.var);
    if (provenance == NULL) return ZEND_USER_OPCODE_DISPATCH;
    key = zend_get_zval_ptr(opline, opline->op2_type, &opline->op2, execute_data);
    if (key == NULL || (Z_TYPE_P(key) != IS_STRING && Z_TYPE_P(key) != IS_LONG)) return ZEND_USER_OPCODE_DISPATCH;
    path = hookphuzz_append_path(provenance, key);
    hookphuzz_record_event(execute_data, opline, provenance, path, operation);
    return ZEND_USER_OPCODE_DISPATCH;
}

static void hookphuzz_frame_end_handler(zend_execute_data *execute_data, zval *retval)
{
    (void) retval;
    hookphuzz_remove_frame_provenance(execute_data);
}

static zend_observer_fcall_handlers hookphuzz_observer_init(zend_execute_data *execute_data)
{
    zend_observer_fcall_handlers handlers = {NULL, NULL};

    if (execute_data != NULL && execute_data->func != NULL && ZEND_USER_CODE(execute_data->func->type)) {
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

static zend_result hookphuzz_encode_artifact(smart_str *json)
{
    zval document, events;
    uint32_t index, path_index;

    array_init(&document);
    add_assoc_long(&document, "schema_version", 1);
    add_assoc_str(&document, "request_id", zend_string_copy(HOOKPHUZZ_PHASE5_G(request_id)));
    add_assoc_long(&document, "pid", (zend_long) getpid());
    add_assoc_str(&document, "method", zend_string_copy(HOOKPHUZZ_PHASE5_G(request_method)));
    add_assoc_str(&document, "uri", zend_string_copy(HOOKPHUZZ_PHASE5_G(request_uri)));
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
        add_next_index_zval(&events, &event_array);
    }
    add_assoc_zval(&document, "events", &events);
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
        hookphuzz_log("hookphuzz_opcode_phase5: artifact JSON encoding failed");
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
        snprintf(message, sizeof(message), "hookphuzz_opcode_phase5: artifact write failed for %s: %s",
            ZSTR_VAL(HOOKPHUZZ_PHASE5_G(request_id)), strerror(error_code));
        hookphuzz_log(message);
        smart_str_free(&json);
        return;
    }
    fd = -1;
    if (syscall(SYS_renameat2, AT_FDCWD, temp_path, AT_FDCWD, final_path, RENAME_NOREPLACE) != 0) {
        int error_code = errno;
        unlink(temp_path);
        snprintf(message, sizeof(message), "hookphuzz_opcode_phase5: artifact finalization failed for %s: %s",
            ZSTR_VAL(HOOKPHUZZ_PHASE5_G(request_id)), strerror(error_code));
        hookphuzz_log(message);
    }
    smart_str_free(&json);
}

PHP_MINIT_FUNCTION(hookphuzz_opcode_phase5)
{
    if (zend_get_user_opcode_handler(ZEND_FETCH_R) != NULL
        || zend_get_user_opcode_handler(ZEND_FETCH_DIM_R) != NULL
        || zend_get_user_opcode_handler(ZEND_FETCH_IS) != NULL
        || zend_get_user_opcode_handler(ZEND_FETCH_DIM_IS) != NULL
        || zend_get_user_opcode_handler(ZEND_ISSET_ISEMPTY_DIM_OBJ) != NULL) return FAILURE;
    zend_observer_fcall_register(hookphuzz_observer_init);
    if (zend_set_user_opcode_handler(ZEND_FETCH_R, hookphuzz_fetch_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_FETCH_DIM_R, hookphuzz_fetch_dim_r_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_FETCH_IS, hookphuzz_fetch_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_FETCH_DIM_IS, hookphuzz_fetch_dim_is_handler) != SUCCESS
        || zend_set_user_opcode_handler(ZEND_ISSET_ISEMPTY_DIM_OBJ, hookphuzz_isempty_dim_obj_handler) != SUCCESS) return FAILURE;
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(hookphuzz_opcode_phase5)
{
    if (zend_get_user_opcode_handler(ZEND_FETCH_R) == hookphuzz_fetch_handler) zend_set_user_opcode_handler(ZEND_FETCH_R, NULL);
    if (zend_get_user_opcode_handler(ZEND_FETCH_DIM_R) == hookphuzz_fetch_dim_r_handler) zend_set_user_opcode_handler(ZEND_FETCH_DIM_R, NULL);
    if (zend_get_user_opcode_handler(ZEND_FETCH_IS) == hookphuzz_fetch_handler) zend_set_user_opcode_handler(ZEND_FETCH_IS, NULL);
    if (zend_get_user_opcode_handler(ZEND_FETCH_DIM_IS) == hookphuzz_fetch_dim_is_handler) zend_set_user_opcode_handler(ZEND_FETCH_DIM_IS, NULL);
    if (zend_get_user_opcode_handler(ZEND_ISSET_ISEMPTY_DIM_OBJ) == hookphuzz_isempty_dim_obj_handler) zend_set_user_opcode_handler(ZEND_ISSET_ISEMPTY_DIM_OBJ, NULL);
    return SUCCESS;
}

PHP_RINIT_FUNCTION(hookphuzz_opcode_phase5)
{
    zend_string *header;

#if defined(ZTS) && defined(COMPILE_DL_HOOKPHUZZ_OPCODE_PHASE5)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    HOOKPHUZZ_PHASE5_G(dropped_event_count) = 0;
    HOOKPHUZZ_PHASE5_G(event_count) = 0;
    HOOKPHUZZ_PHASE5_G(events) = NULL;
    HOOKPHUZZ_PHASE5_G(provenance_count) = 0;
    HOOKPHUZZ_PHASE5_G(provenance) = NULL;
    HOOKPHUZZ_PHASE5_G(request_id) = NULL;
    HOOKPHUZZ_PHASE5_G(request_method) = NULL;
    HOOKPHUZZ_PHASE5_G(request_uri) = NULL;
    HOOKPHUZZ_PHASE5_G(artifact_enabled) = 0;
    HOOKPHUZZ_PHASE5_G(artifact_flushed) = 0;

    header = hookphuzz_request_id_from_server();
    if (header == NULL) {
        hookphuzz_log("hookphuzz_opcode_phase5: request artifact skipped: missing X-Fuzzer-Covid");
        return SUCCESS;
    }
    if (!hookphuzz_valid_request_id(header)) {
        hookphuzz_log("hookphuzz_opcode_phase5: request artifact skipped: invalid X-Fuzzer-Covid");
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

PHP_RSHUTDOWN_FUNCTION(hookphuzz_opcode_phase5)
{
    if (HOOKPHUZZ_PHASE5_G(artifact_enabled) && !HOOKPHUZZ_PHASE5_G(artifact_flushed)) hookphuzz_flush_artifact();
    hookphuzz_release_events();
    hookphuzz_release_provenance();
    hookphuzz_release_request_metadata();
    HOOKPHUZZ_PHASE5_G(dropped_event_count) = 0;
    return SUCCESS;
}

PHP_MINFO_FUNCTION(hookphuzz_opcode_phase5)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "hookphuzz_opcode_phase5 support", "enabled");
    php_info_print_table_row(2, "configured user opcodes", "ZEND_FETCH_R, ZEND_FETCH_DIM_R, ZEND_FETCH_IS, ZEND_FETCH_DIM_IS, ZEND_ISSET_ISEMPTY_DIM_OBJ");
    php_info_print_table_row(2, "artifact output", HOOKPHUZZ_ARTIFACT_DIR);
    php_info_print_table_row(2, "event limit per request", "4096");
    php_info_print_table_end();
}

zend_module_entry hookphuzz_opcode_phase5_module_entry = {
    STANDARD_MODULE_HEADER, "hookphuzz_opcode_phase5", NULL,
    PHP_MINIT(hookphuzz_opcode_phase5), PHP_MSHUTDOWN(hookphuzz_opcode_phase5),
    PHP_RINIT(hookphuzz_opcode_phase5), PHP_RSHUTDOWN(hookphuzz_opcode_phase5),
    PHP_MINFO(hookphuzz_opcode_phase5), PHP_HOOKPHUZZ_OPCODE_PHASE5_VERSION, STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_HOOKPHUZZ_OPCODE_PHASE5
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
# endif
ZEND_GET_MODULE(hookphuzz_opcode_phase5)
#endif
