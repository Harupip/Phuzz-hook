#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_hookphuzz_opcode.h"
#include "ext/standard/info.h"
#include "Zend/zend_execute.h"

ZEND_DECLARE_MODULE_GLOBALS(hookphuzz_opcode)

static const char *hookphuzz_opcode_operand_type_name(zend_uchar type)
{
    switch (type) {
        case IS_CONST:
            return "CONST";
        case IS_CV:
            return "CV";
        case IS_TMP_VAR:
            return "TMP_VAR";
        case IS_VAR:
            return "VAR";
        case IS_UNUSED:
            return "UNUSED";
        default:
            return "OTHER";
    }
}

static const char *hookphuzz_opcode_zval_type_name(const zval *value)
{
    if (value == NULL) {
        return "unavailable";
    }

    switch (Z_TYPE_P(value)) {
        case IS_UNDEF:
            return "undefined";
        case IS_NULL:
            return "null";
        case IS_FALSE:
        case IS_TRUE:
            return "bool";
        case IS_LONG:
            return "int";
        case IS_DOUBLE:
            return "float";
        case IS_STRING:
            return "string";
        case IS_ARRAY:
            return "array";
        case IS_OBJECT:
            return "object";
        case IS_RESOURCE:
            return "resource";
        case IS_REFERENCE:
            return "reference";
        default:
            return "other";
    }
}

static zend_string *hookphuzz_opcode_copy_filename(const zend_execute_data *execute_data)
{
    if (execute_data != NULL
        && execute_data->func != NULL
        && ZEND_USER_CODE(execute_data->func->type)
        && execute_data->func->op_array.filename != NULL) {
        return zend_string_copy(execute_data->func->op_array.filename);
    }

    return zend_string_init("{unknown}", sizeof("{unknown}") - 1, 0);
}

static zend_string *hookphuzz_opcode_copy_function_name(const zend_execute_data *execute_data)
{
    if (execute_data != NULL
        && execute_data->func != NULL
        && execute_data->func->common.function_name != NULL) {
        return zend_string_copy(execute_data->func->common.function_name);
    }

    return zend_string_init("{main}", sizeof("{main}") - 1, 0);
}

static void hookphuzz_opcode_release_events(void)
{
    uint32_t index;

    for (index = 0; index < HOOKPHUZZ_OPCODE_G(event_count); index++) {
        hookphuzz_opcode_fetch_dim_r_event *event = &HOOKPHUZZ_OPCODE_G(events)[index];

        if (event->filename != NULL) {
            zend_string_release(event->filename);
        }
        if (event->function_name != NULL) {
            zend_string_release(event->function_name);
        }
        if (event->key_string != NULL) {
            zend_string_release(event->key_string);
        }
    }

    if (HOOKPHUZZ_OPCODE_G(events) != NULL) {
        efree(HOOKPHUZZ_OPCODE_G(events));
    }

    HOOKPHUZZ_OPCODE_G(events) = NULL;
    HOOKPHUZZ_OPCODE_G(event_count) = 0;
}

static void hookphuzz_opcode_record_fetch_dim_r(zend_execute_data *execute_data)
{
    const zend_op *opline = execute_data->opline;
    const zval *container = zend_get_zval_ptr(opline, opline->op1_type, &opline->op1, execute_data);
    const zval *key = zend_get_zval_ptr(opline, opline->op2_type, &opline->op2, execute_data);
    hookphuzz_opcode_fetch_dim_r_event *event;

    if (HOOKPHUZZ_OPCODE_G(event_count) == HOOKPHUZZ_OPCODE_MAX_EVENTS) {
        HOOKPHUZZ_OPCODE_G(dropped_event_count)++;
        return;
    }

    if (HOOKPHUZZ_OPCODE_G(events) == NULL) {
        HOOKPHUZZ_OPCODE_G(events) = ecalloc(
            HOOKPHUZZ_OPCODE_MAX_EVENTS,
            sizeof(hookphuzz_opcode_fetch_dim_r_event)
        );
    }

    event = &HOOKPHUZZ_OPCODE_G(events)[HOOKPHUZZ_OPCODE_G(event_count)++];
    event->sequence = HOOKPHUZZ_OPCODE_G(fetch_dim_r_count);
    event->line = opline->lineno;
    event->filename = hookphuzz_opcode_copy_filename(execute_data);
    event->function_name = hookphuzz_opcode_copy_function_name(execute_data);
    event->op1_operand_type = hookphuzz_opcode_operand_type_name(opline->op1_type);
    event->container_zval_type = hookphuzz_opcode_zval_type_name(container);
    event->op2_operand_type = hookphuzz_opcode_operand_type_name(opline->op2_type);
    event->key_zval_type = hookphuzz_opcode_zval_type_name(key);

    if (key != NULL && Z_TYPE_P(key) == IS_STRING) {
        event->key_string = zend_string_copy(Z_STR_P(key));
        event->has_key_string = 1;
    } else if (key != NULL && Z_TYPE_P(key) == IS_LONG) {
        event->key_int = Z_LVAL_P(key);
        event->has_key_int = 1;
    }
}

static int hookphuzz_opcode_fetch_dim_r_handler(zend_execute_data *execute_data)
{
    HOOKPHUZZ_OPCODE_G(fetch_dim_r_count)++;
    hookphuzz_opcode_record_fetch_dim_r(execute_data);

    return ZEND_USER_OPCODE_DISPATCH;
}

PHP_FUNCTION(hookphuzz_opcode_get_fetch_dim_r_count)
{
    ZEND_PARSE_PARAMETERS_NONE();

    RETURN_LONG(HOOKPHUZZ_OPCODE_G(fetch_dim_r_count));
}

PHP_FUNCTION(hookphuzz_opcode_get_fetch_dim_r_events)
{
    uint32_t index;

    ZEND_PARSE_PARAMETERS_NONE();

    array_init_size(return_value, HOOKPHUZZ_OPCODE_G(event_count));
    for (index = 0; index < HOOKPHUZZ_OPCODE_G(event_count); index++) {
        const hookphuzz_opcode_fetch_dim_r_event *event = &HOOKPHUZZ_OPCODE_G(events)[index];
        zval event_array;

        array_init(&event_array);
        add_assoc_long(&event_array, "sequence", event->sequence);
        add_assoc_string(&event_array, "opcode", "ZEND_FETCH_DIM_R");
        add_assoc_str(&event_array, "filename", zend_string_copy(event->filename));
        add_assoc_long(&event_array, "line", event->line);
        add_assoc_str(&event_array, "function", zend_string_copy(event->function_name));
        add_assoc_string(&event_array, "op1_operand_type", (char *) event->op1_operand_type);
        add_assoc_string(&event_array, "container_zval_type", (char *) event->container_zval_type);
        add_assoc_string(&event_array, "op2_operand_type", (char *) event->op2_operand_type);
        add_assoc_string(&event_array, "key_zval_type", (char *) event->key_zval_type);

        if (event->has_key_string) {
            add_assoc_str(&event_array, "key_string", zend_string_copy(event->key_string));
        } else {
            add_assoc_null(&event_array, "key_string");
        }
        if (event->has_key_int) {
            add_assoc_long(&event_array, "key_int", event->key_int);
        } else {
            add_assoc_null(&event_array, "key_int");
        }

        add_next_index_zval(return_value, &event_array);
    }
}

PHP_FUNCTION(hookphuzz_opcode_get_dropped_event_count)
{
    ZEND_PARSE_PARAMETERS_NONE();

    RETURN_LONG(HOOKPHUZZ_OPCODE_G(dropped_event_count));
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_hookphuzz_opcode_get_fetch_dim_r_count, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_hookphuzz_opcode_get_fetch_dim_r_events, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_hookphuzz_opcode_get_dropped_event_count, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry hookphuzz_opcode_functions[] = {
    PHP_FE(hookphuzz_opcode_get_fetch_dim_r_count, arginfo_hookphuzz_opcode_get_fetch_dim_r_count)
    PHP_FE(hookphuzz_opcode_get_fetch_dim_r_events, arginfo_hookphuzz_opcode_get_fetch_dim_r_events)
    PHP_FE(hookphuzz_opcode_get_dropped_event_count, arginfo_hookphuzz_opcode_get_dropped_event_count)
    PHP_FE_END
};

PHP_MINIT_FUNCTION(hookphuzz_opcode)
{
    if (zend_get_user_opcode_handler(ZEND_FETCH_DIM_R) != NULL) {
        php_error_docref(NULL, E_WARNING, "ZEND_FETCH_DIM_R already has a user opcode handler; hookphuzz_opcode will not overwrite it");
        return FAILURE;
    }

    if (zend_set_user_opcode_handler(ZEND_FETCH_DIM_R, hookphuzz_opcode_fetch_dim_r_handler) != SUCCESS) {
        php_error_docref(NULL, E_WARNING, "could not register the ZEND_FETCH_DIM_R user opcode handler");
        return FAILURE;
    }

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(hookphuzz_opcode)
{
    if (zend_get_user_opcode_handler(ZEND_FETCH_DIM_R) == hookphuzz_opcode_fetch_dim_r_handler) {
        zend_set_user_opcode_handler(ZEND_FETCH_DIM_R, NULL);
    }

    return SUCCESS;
}

PHP_RINIT_FUNCTION(hookphuzz_opcode)
{
#if defined(ZTS) && defined(COMPILE_DL_HOOKPHUZZ_OPCODE)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif

    HOOKPHUZZ_OPCODE_G(fetch_dim_r_count) = 0;
    HOOKPHUZZ_OPCODE_G(dropped_event_count) = 0;
    HOOKPHUZZ_OPCODE_G(event_count) = 0;
    HOOKPHUZZ_OPCODE_G(events) = NULL;

    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(hookphuzz_opcode)
{
    hookphuzz_opcode_release_events();

    return SUCCESS;
}

PHP_MINFO_FUNCTION(hookphuzz_opcode)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "hookphuzz_opcode support", "enabled");
    php_info_print_table_row(2, "configured user opcode", "ZEND_FETCH_DIM_R");
    php_info_print_table_row(2, "event limit per request", "4096");
    php_info_print_table_end();
}

zend_module_entry hookphuzz_opcode_module_entry = {
    STANDARD_MODULE_HEADER,
    "hookphuzz_opcode",
    hookphuzz_opcode_functions,
    PHP_MINIT(hookphuzz_opcode),
    PHP_MSHUTDOWN(hookphuzz_opcode),
    PHP_RINIT(hookphuzz_opcode),
    PHP_RSHUTDOWN(hookphuzz_opcode),
    PHP_MINFO(hookphuzz_opcode),
    PHP_HOOKPHUZZ_OPCODE_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_HOOKPHUZZ_OPCODE
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE();
# endif
ZEND_GET_MODULE(hookphuzz_opcode)
#endif
