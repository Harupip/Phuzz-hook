PHP_ARG_ENABLE([hookphuzz_opcode_phase5],
  [whether to enable HookPhuzz opcode Phase 5 support],
  [AS_HELP_STRING([--enable-hookphuzz_opcode_phase5], [Enable HookPhuzz opcode Phase 5])],
  [no])

if test "$PHP_HOOKPHUZZ_OPCODE_PHASE5" != "no"; then
  PHP_NEW_EXTENSION([hookphuzz_opcode_phase5], [hookphuzz_opcode_phase5.c], [$ext_shared])
fi
