PHP_ARG_ENABLE([hookphuzz_opcode_phase7],
  [whether to enable HookPhuzz opcode Phase 7 support],
  [AS_HELP_STRING([--enable-hookphuzz_opcode_phase7], [Enable HookPhuzz opcode Phase 7])],
  [no])

if test "$PHP_HOOKPHUZZ_OPCODE_PHASE7" != "no"; then
  PHP_NEW_EXTENSION([hookphuzz_opcode_phase7], [hookphuzz_opcode_phase7.c], [$ext_shared])
fi

