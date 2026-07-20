PHP_ARG_ENABLE([hookphuzz_opcode_phase9],
  [whether to enable HookPhuzz opcode Phase 9 support],
  [AS_HELP_STRING([--enable-hookphuzz_opcode_phase9], [Enable HookPhuzz opcode Phase 9])],
  [no])

if test "$PHP_HOOKPHUZZ_OPCODE_PHASE9" != "no"; then
  PHP_NEW_EXTENSION([hookphuzz_opcode_phase9], [hookphuzz_opcode_phase9.c], [$ext_shared])
fi

