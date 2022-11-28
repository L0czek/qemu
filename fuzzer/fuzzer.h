#include "qemu/osdep.h"
#include "exec/exec-all.h"

typedef struct DisasContext DisasContext;

int fuzzer_translate_instr(DisasContext *s);
void fuzzer_set_testcase_file(const char *);
void fuzzer_maybe_log_pc(target_ulong );
void fuzzer_init(void);
