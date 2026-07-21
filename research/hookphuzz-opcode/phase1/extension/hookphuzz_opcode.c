#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php.h"
#include "php_hookphuzz_opcode.h"
#include "Zend/zend_execute.h"

ZEND_DECLARE_MODULE_GLOBALS(hookphuzz_opcode)

static int hookphuzz_opcode_fetch_dim_r_handler(zend_execute_data *execute_data)
{
    (void) execute_data;
    HOOKPHUZZ_OPCODE_G(fetch_dim_r_count)++;

    return ZEND_USER_OPCODE_DISPATCH;
}

PHP_FUNCTION(hookphuzz_opcode_get_fetch_dim_r_count)
{
    ZEND_PARSE_PARAMETERS_NONE();

    RETURN_LONG(HOOKPHUZZ_OPCODE_G(fetch_dim_r_count));
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_hookphuzz_opcode_get_fetch_dim_r_count, 0, 0, IS_LONG, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry hookphuzz_opcode_functions[] = {
    PHP_FE(hookphuzz_opcode_get_fetch_dim_r_count, arginfo_hookphuzz_opcode_get_fetch_dim_r_count)
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

    return SUCCESS;
}

PHP_MINFO_FUNCTION(hookphuzz_opcode)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "hookphuzz_opcode support", "enabled");
    php_info_print_table_row(2, "configured user opcode", "ZEND_FETCH_DIM_R");
    php_info_print_table_end();
}

zend_module_entry hookphuzz_opcode_module_entry = {
    STANDARD_MODULE_HEADER,
    "hookphuzz_opcode",
    hookphuzz_opcode_functions,
    PHP_MINIT(hookphuzz_opcode),
    PHP_MSHUTDOWN(hookphuzz_opcode),
    PHP_RINIT(hookphuzz_opcode),
    NULL,
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
