PHP_ARG_ENABLE([hookphuzz_opcode],
  [whether to enable hookphuzz_opcode support],
  [AS_HELP_STRING([--enable-hookphuzz_opcode], [Enable hookphuzz_opcode support])],
  [no])

if test "$PHP_HOOKPHUZZ_OPCODE" != "no"; then
  PHP_NEW_EXTENSION([hookphuzz_opcode], [hookphuzz_opcode.c], [$ext_shared])
fi
