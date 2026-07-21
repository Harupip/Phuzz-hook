#ifndef PHP_HOOKPHUZZ_OPCODE_H
#define PHP_HOOKPHUZZ_OPCODE_H

extern zend_module_entry hookphuzz_opcode_module_entry;
#define phpext_hookphuzz_opcode_ptr &hookphuzz_opcode_module_entry

#define PHP_HOOKPHUZZ_OPCODE_VERSION "0.1.0"

ZEND_BEGIN_MODULE_GLOBALS(hookphuzz_opcode)
    zend_long fetch_dim_r_count;
ZEND_END_MODULE_GLOBALS(hookphuzz_opcode)

ZEND_EXTERN_MODULE_GLOBALS(hookphuzz_opcode)
#define HOOKPHUZZ_OPCODE_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(hookphuzz_opcode, v)

#endif
