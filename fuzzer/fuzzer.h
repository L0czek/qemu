#include "qemu/osdep.h"
#include "exec/cpu-defs.h"

typedef struct DisasContext DisasContext;

int fuzzer_translate_instr(DisasContext *s);
void fuzzer_maybe_log_pc(target_ulong );
