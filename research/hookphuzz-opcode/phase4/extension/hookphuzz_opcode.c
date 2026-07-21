#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_hookphuzz_opcode.h"
#include "ext/standard/info.h"
#include "Zend/zend_compile.h"
#include "Zend/zend_execute.h"
#include "Zend/zend_observer.h"
#include "Zend/zend_vm_opcodes.h"

ZEND_DECLARE_MODULE_GLOBALS(hookphuzz_opcode)

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

static const char *hookphuzz_zval_type_name(zend_uchar type)
{
    switch (type) {
        case IS_UNDEF: return "undefined";
        case IS_NULL: return "null";
        case IS_FALSE:
        case IS_TRUE: return "bool";
        case IS_LONG: return "int";
        case IS_DOUBLE: return "float";
        case IS_STRING: return "string";
        case IS_ARRAY: return "array";
        case IS_OBJECT: return "object";
        case IS_RESOURCE: return "resource";
        case IS_REFERENCE: return "reference";
        default: return "other";
    }
}

static const char *hookphuzz_opcode_name(zend_uchar opcode)
{
    switch (opcode) {
        case ZEND_FETCH_DIM_R: return "ZEND_FETCH_DIM_R";
        case ZEND_FETCH_DIM_IS: return "ZEND_FETCH_DIM_IS";
        case ZEND_ISSET_ISEMPTY_DIM_OBJ: return "ZEND_ISSET_ISEMPTY_DIM_OBJ";
        default: return "UNKNOWN";
    }
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

static void hookphuzz_release_events(void)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_OPCODE_G(event_count); index++) {
        hookphuzz_superglobal_dim_event *event = &HOOKPHUZZ_OPCODE_G(events)[index];
        if (event->filename != NULL) zend_string_release(event->filename);
        if (event->key_string != NULL) zend_string_release(event->key_string);
        hookphuzz_release_path(event->path, event->depth);
    }
    if (HOOKPHUZZ_OPCODE_G(events) != NULL) efree(HOOKPHUZZ_OPCODE_G(events));
    HOOKPHUZZ_OPCODE_G(events) = NULL;
    HOOKPHUZZ_OPCODE_G(event_count) = 0;
}

static void hookphuzz_release_provenance(void)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_OPCODE_G(provenance_count); index++) {
        hookphuzz_release_path(HOOKPHUZZ_OPCODE_G(provenance)[index].path,
            HOOKPHUZZ_OPCODE_G(provenance)[index].depth);
    }
    if (HOOKPHUZZ_OPCODE_G(provenance) != NULL) efree(HOOKPHUZZ_OPCODE_G(provenance));
    HOOKPHUZZ_OPCODE_G(provenance) = NULL;
    HOOKPHUZZ_OPCODE_G(provenance_count) = 0;
}

static void hookphuzz_remove_frame_provenance(const zend_execute_data *frame)
{
    uint32_t index = 0;

    while (index < HOOKPHUZZ_OPCODE_G(provenance_count)) {
        hookphuzz_provenance *item = &HOOKPHUZZ_OPCODE_G(provenance)[index];
        if (item->frame != frame) {
            index++;
            continue;
        }
        hookphuzz_release_path(item->path, item->depth);
        HOOKPHUZZ_OPCODE_G(provenance_count)--;
        if (index != HOOKPHUZZ_OPCODE_G(provenance_count)) {
            HOOKPHUZZ_OPCODE_G(provenance)[index] = HOOKPHUZZ_OPCODE_G(provenance)[HOOKPHUZZ_OPCODE_G(provenance_count)];
        }
    }
}

static hookphuzz_provenance *hookphuzz_find_provenance(const zend_execute_data *frame, uint32_t result_var)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_OPCODE_G(provenance_count); index++) {
        hookphuzz_provenance *item = &HOOKPHUZZ_OPCODE_G(provenance)[index];
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
        if (HOOKPHUZZ_OPCODE_G(provenance_count) == HOOKPHUZZ_OPCODE_MAX_EVENTS) {
            hookphuzz_release_path(path, depth);
            return;
        }
        if (HOOKPHUZZ_OPCODE_G(provenance) == NULL) {
            HOOKPHUZZ_OPCODE_G(provenance) = ecalloc(HOOKPHUZZ_OPCODE_MAX_EVENTS, sizeof(hookphuzz_provenance));
        }
        item = &HOOKPHUZZ_OPCODE_G(provenance)[HOOKPHUZZ_OPCODE_G(provenance_count)++];
    } else {
        hookphuzz_release_path(item->path, item->depth);
    }
    item->frame = frame;
    item->result_var = opline->result.var;
    item->source = source;
    item->depth = depth;
    item->path = path;
}

static zend_bool hookphuzz_source_from_fetch(const zend_execute_data *execute_data,
    const zend_op *opline, hookphuzz_source *source)
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
    return execute_data != NULL;
}

static void hookphuzz_record_event(const zend_execute_data *execute_data, const zend_op *opline,
    const hookphuzz_provenance *provenance, const zval *key, hookphuzz_path_key *path,
    zend_bool mapped, const char *access_context)
{
    hookphuzz_superglobal_dim_event *event;

    if (HOOKPHUZZ_OPCODE_G(event_count) == HOOKPHUZZ_OPCODE_MAX_EVENTS) {
        HOOKPHUZZ_OPCODE_G(dropped_event_count)++;
        hookphuzz_release_path(path, provenance->depth + (mapped ? 1 : 0));
        return;
    }
    if (HOOKPHUZZ_OPCODE_G(events) == NULL) {
        HOOKPHUZZ_OPCODE_G(events) = ecalloc(HOOKPHUZZ_OPCODE_MAX_EVENTS, sizeof(hookphuzz_superglobal_dim_event));
    }
    event = &HOOKPHUZZ_OPCODE_G(events)[HOOKPHUZZ_OPCODE_G(event_count)++];
    event->line = opline->lineno;
    event->source = provenance->source;
    event->opcode = opline->opcode;
    event->access_context = access_context;
    event->key_type = key == NULL ? IS_UNDEF : Z_TYPE_P(key);
    event->filename = hookphuzz_copy_filename(execute_data);
    event->mapped = mapped;
    event->depth = mapped ? provenance->depth + 1 : 0;
    event->path = path;
    if (key != NULL && Z_TYPE_P(key) == IS_STRING) event->key_string = zend_string_copy(Z_STR_P(key));
    else if (key != NULL && Z_TYPE_P(key) == IS_LONG) {
        event->has_key_int = 1;
        event->key_int = Z_LVAL_P(key);
    } else {
        event->unsupported_reason = "unsupported_key_type";
    }
}

static int hookphuzz_fetch_handler(zend_execute_data *execute_data)
{
    hookphuzz_source source;
    const zend_op *opline = execute_data->opline;

    if (hookphuzz_source_from_fetch(execute_data, opline, &source)) {
        hookphuzz_set_provenance(execute_data, opline, source, NULL, 0);
    }
    return ZEND_USER_OPCODE_DISPATCH;
}

static int hookphuzz_fetch_dim_handler(zend_execute_data *execute_data, const char *access_context)
{
    const zend_op *opline = execute_data->opline;
    const zval *key;
    hookphuzz_provenance *provenance;
    hookphuzz_path_key *path;

    if (opline->op1_type != IS_TMP_VAR && opline->op1_type != IS_VAR) return ZEND_USER_OPCODE_DISPATCH;
    provenance = hookphuzz_find_provenance(execute_data, opline->op1.var);
    if (provenance == NULL) return ZEND_USER_OPCODE_DISPATCH;
    key = zend_get_zval_ptr(opline, opline->op2_type, &opline->op2, execute_data);
    if (key == NULL || (Z_TYPE_P(key) != IS_STRING && Z_TYPE_P(key) != IS_LONG)) {
        hookphuzz_record_event(execute_data, opline, provenance, key, NULL, 0, access_context);
        return ZEND_USER_OPCODE_DISPATCH;
    }
    path = hookphuzz_append_path(provenance, key);
    hookphuzz_record_event(execute_data, opline, provenance, key,
        hookphuzz_copy_path(path, provenance->depth + 1), 1, access_context);
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
    const char *access_context = (opline->extended_value & ZEND_ISEMPTY) ? "empty" : "isset";

    if (opline->op1_type != IS_TMP_VAR && opline->op1_type != IS_VAR) return ZEND_USER_OPCODE_DISPATCH;
    provenance = hookphuzz_find_provenance(execute_data, opline->op1.var);
    if (provenance == NULL) return ZEND_USER_OPCODE_DISPATCH;
    key = zend_get_zval_ptr(opline, opline->op2_type, &opline->op2, execute_data);
    if (key == NULL || (Z_TYPE_P(key) != IS_STRING && Z_TYPE_P(key) != IS_LONG)) {
        hookphuzz_record_event(execute_data, opline, provenance, key, NULL, 0, access_context);
        return ZEND_USER_OPCODE_DISPATCH;
    }
    path = hookphuzz_append_path(provenance, key);
    hookphuzz_record_event(execute_data, opline, provenance, key, path, 1, access_context);
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

PHP_FUNCTION(hookphuzz_opcode_get_superglobal_dim_read_events)
{
    uint32_t index, key_index;
    ZEND_PARSE_PARAMETERS_NONE();
    array_init_size(return_value, HOOKPHUZZ_OPCODE_G(event_count));
    for (index = 0; index < HOOKPHUZZ_OPCODE_G(event_count); index++) {
        const hookphuzz_superglobal_dim_event *event = &HOOKPHUZZ_OPCODE_G(events)[index];
        zval event_array, path;
        array_init(&event_array);
        add_assoc_string(&event_array, "event_type", "superglobal_dim_read");
        add_assoc_string(&event_array, "source", (char *) hookphuzz_source_name(event->source));
        add_assoc_string(&event_array, "opcode", (char *) hookphuzz_opcode_name(event->opcode));
        add_assoc_string(&event_array, "access_context", (char *) event->access_context);
        add_assoc_string(&event_array, "key_type", (char *) hookphuzz_zval_type_name(event->key_type));
        if (event->key_string != NULL) add_assoc_str(&event_array, "key", zend_string_copy(event->key_string));
        else if (event->has_key_int) add_assoc_long(&event_array, "key", event->key_int);
        else add_assoc_null(&event_array, "key");
        array_init_size(&path, event->depth);
        for (key_index = 0; key_index < event->depth; key_index++) {
            zval path_key;
            array_init(&path_key);
            add_assoc_string(&path_key, "type", (char *) hookphuzz_zval_type_name(event->path[key_index].type));
            if (event->path[key_index].type == IS_STRING) add_assoc_str(&path_key, "value", zend_string_copy(event->path[key_index].string_value));
            else add_assoc_long(&path_key, "value", event->path[key_index].int_value);
            add_next_index_zval(&path, &path_key);
        }
        add_assoc_zval(&event_array, "path", &path);
        add_assoc_long(&event_array, "depth", event->depth);
        add_assoc_bool(&event_array, "parameter_candidate", event->mapped && event->key_type == IS_STRING);
        add_assoc_bool(&event_array, "mapped", event->mapped);
        if (event->unsupported_reason != NULL) add_assoc_string(&event_array, "reason", (char *) event->unsupported_reason);
        add_assoc_str(&event_array, "filename", zend_string_copy(event->filename));
        add_assoc_long(&event_array, "line", event->line);
        add_next_index_zval(return_value, &event_array);
    }
}

PHP_FUNCTION(hookphuzz_opcode_get_dropped_event_count)
{
    ZEND_PARSE_PARAMETERS_NONE();
    RETURN_LONG(HOOKPHUZZ_OPCODE_G(dropped_event_count));
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_hookphuzz_opcode_get_events, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_hookphuzz_opcode_get_dropped, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry hookphuzz_opcode_functions[] = {
    PHP_FE(hookphuzz_opcode_get_superglobal_dim_read_events, arginfo_hookphuzz_opcode_get_events)
    PHP_FE(hookphuzz_opcode_get_dropped_event_count, arginfo_hookphuzz_opcode_get_dropped)
    PHP_FE_END
};

PHP_MINIT_FUNCTION(hookphuzz_opcode)
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

PHP_MSHUTDOWN_FUNCTION(hookphuzz_opcode)
{
    if (zend_get_user_opcode_handler(ZEND_FETCH_R) == hookphuzz_fetch_handler) zend_set_user_opcode_handler(ZEND_FETCH_R, NULL);
    if (zend_get_user_opcode_handler(ZEND_FETCH_DIM_R) == hookphuzz_fetch_dim_r_handler) zend_set_user_opcode_handler(ZEND_FETCH_DIM_R, NULL);
    if (zend_get_user_opcode_handler(ZEND_FETCH_IS) == hookphuzz_fetch_handler) zend_set_user_opcode_handler(ZEND_FETCH_IS, NULL);
    if (zend_get_user_opcode_handler(ZEND_FETCH_DIM_IS) == hookphuzz_fetch_dim_is_handler) zend_set_user_opcode_handler(ZEND_FETCH_DIM_IS, NULL);
    if (zend_get_user_opcode_handler(ZEND_ISSET_ISEMPTY_DIM_OBJ) == hookphuzz_isempty_dim_obj_handler) zend_set_user_opcode_handler(ZEND_ISSET_ISEMPTY_DIM_OBJ, NULL);
    return SUCCESS;
}

PHP_RINIT_FUNCTION(hookphuzz_opcode)
{
#if defined(ZTS) && defined(COMPILE_DL_HOOKPHUZZ_OPCODE)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    HOOKPHUZZ_OPCODE_G(dropped_event_count) = 0;
    HOOKPHUZZ_OPCODE_G(event_count) = 0;
    HOOKPHUZZ_OPCODE_G(events) = NULL;
    HOOKPHUZZ_OPCODE_G(provenance_count) = 0;
    HOOKPHUZZ_OPCODE_G(provenance) = NULL;
    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(hookphuzz_opcode)
{
    hookphuzz_release_events();
    hookphuzz_release_provenance();
    return SUCCESS;
}

PHP_MINFO_FUNCTION(hookphuzz_opcode)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "hookphuzz_opcode support", "enabled");
    php_info_print_table_row(2, "configured user opcodes", "ZEND_FETCH_R, ZEND_FETCH_DIM_R, ZEND_FETCH_IS, ZEND_FETCH_DIM_IS, ZEND_ISSET_ISEMPTY_DIM_OBJ");
    php_info_print_table_row(2, "frame cleanup", "user-code fcall end observer");
    php_info_print_table_row(2, "event limit per request", "4096");
    php_info_print_table_end();
}

zend_module_entry hookphuzz_opcode_module_entry = {
    STANDARD_MODULE_HEADER, "hookphuzz_opcode", hookphuzz_opcode_functions,
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
