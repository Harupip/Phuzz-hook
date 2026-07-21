PHP_ARG_ENABLE([hookphuzz_opcode_phase8],
  [whether to enable HookPhuzz opcode Phase 8 support],
  [AS_HELP_STRING([--enable-hookphuzz_opcode_phase8], [Enable HookPhuzz opcode Phase 8])],
  [no])

if test "$PHP_HOOKPHUZZ_OPCODE_PHASE8" != "no"; then
  PHP_NEW_EXTENSION([hookphuzz_opcode_phase8], [hookphuzz_opcode_phase8.c], [$ext_shared])
fi

