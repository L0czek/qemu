#include "fuzzer.h"
#include "qemu/osdep.h"

#include "cpu.h"
#include "internals.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "qemu/qemu-print.h"
#include "qemu/typedefs.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-op-gvec.h"
#include "qemu/log.h"
#include "qemu/bitops.h"
#include "arm_ldst.h"
#include "semihosting/semihost.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

#include "exec/log.h"
#include "tcg/tcg.h"
#include "translate.h"
#include <bits/pthreadtypes.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static void log_to_file(FILE *f, const char * file, int line, const char *fmt, va_list list) {
    qemu_fprintf(f, "FUZZER_DEBUG [%s:%d]: ", file, line);
    qemu_vfprintf(f, fmt, list);
}

static void _log(const char * file, int line, const char *fmt, ...) {
    va_list list;
    va_start(list, fmt);

    if (getenv("FUZZER_DEBUG_LOG")) {
        if (getenv("FUZZER_LOG_STDERR")) {
            log_to_file(stderr, file, line, fmt, list);
        } else {
            FILE *f = qemu_log_lock();
            log_to_file(f, file, line, fmt, list);
            qemu_log_unlock(f);
        }
    }

    va_end(list);
}

#define LOG_VA_ARGS(...) ,##__VA_ARGS__
#define LOG(fmt, ...) _log(__FILE__, __LINE__, fmt LOG_VA_ARGS(__VA_ARGS__))

#ifdef TARGET_AARCH64

#define FUZZER_FORKSERVER           137 // udf 137
#define FUZZER_BEGIN                138 // udf 138
#define FUZZER_END                  139 // udf 139
#define FUZZER_RESTRICT_COVERAGE    140 // udf 140
#define FUZZER_FETCH_TESTCASE       141 // udf 141
#define FUZZER_KILL                 142 // udf 142
#define FUZZER_EXIT                 143 // udf 143
#define FUZZER_LOG                  144 // udf 144

int fuzzer_translate_instr(DisasContext *s) {
    switch (s->insn) {
        case FUZZER_FORKSERVER:
            LOG("Translating instruction FUZZER_FORKSERVER\n");
            gen_helper_fuzzer_forkserver();
            break;
        case FUZZER_BEGIN:
            LOG("Translating instruction FUZZER_BEGIN\n");
            gen_helper_fuzzer_begin();
            break;
        case FUZZER_END:
            LOG("Translating instruction FUZZER_END\n");
            gen_helper_fuzzer_end();
            break;
        case FUZZER_RESTRICT_COVERAGE:
            LOG("Translating instruction FUZZER_RESTRICT_COVERAGE\n");
            gen_helper_fuzzer_restrict_coverage();
            break;
        case FUZZER_FETCH_TESTCASE:
            LOG("Translating instruction FUZZER_FETCH_TESTCASE\n");
            gen_helper_fuzzer_fetch_testcase();
            break;
        case FUZZER_KILL:
            LOG("Translating instruction FUZZER_KILL\n");
            gen_helper_fuzzer_kill();
            break;
        case FUZZER_EXIT:
            LOG("Translating instruction FUZZER_EXIT\n");
            gen_helper_fuzzer_exit();
            break;
        case FUZZER_LOG:
            LOG("Translating instruction FUZZER_LOG\n");
            gen_helper_fuzzer_log();
            break;
        default: 
            return 0;
    }

    return 1;
}

static target_ulong reg(uint8_t n) {
    CPUARMState *arm = &ARM_CPU(current_cpu)->env;

    if (arm->aarch64 == 1) {
        return arm->xregs[n];
    } else {
        return (target_ulong) arm->regs[n];
    }
}
static void set_reg(uint8_t n, target_ulong v) {
    CPUARMState *arm = &ARM_CPU(current_cpu)->env;

    if (arm->aarch64 == 1) {
        arm->xregs[n] = v;
    } else {
        arm->regs[n] = v;
    }
}

#else

#error "Selected arch is not implemented"

#endif

#define FUZZER_FAIL -69

#define FUZZER_OS_STATE_FD 199
#define FUZZER_BITMAP_SIZE 1 << 16

typedef struct {
    sem_t sem;
    int v;
} __attribute__((packed)) os_state_t;

typedef struct {
    pthread_mutex_t mutex;

    bool coverage_active;
    target_ulong base;
    target_ulong limit;
    const char *testcase_path;
    char *testcase;
    size_t testcase_size;
    os_state_t *os_state;
    bool do_restore;
    char bitmap[FUZZER_BITMAP_SIZE];
} fuzzer_t;

static fuzzer_t gFuzzer = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .coverage_active = false
};

static fuzzer_t *fuzzer_lock(void) {
    pthread_mutex_lock(&gFuzzer.mutex);
    return &gFuzzer;
}

static void fuzzer_unlock(fuzzer_t *fuzzer) {
    pthread_mutex_unlock(&fuzzer->mutex);
}

static void await_fuzzer(fuzzer_t *f) {
    kill(getpid(), SIGSTOP);
    sem_wait(&f->os_state->sem);
}

static void send_state(fuzzer_t *f, int v) {
    LOG("Sending OS state: %d\n", v);

    if (f->os_state) {
        f->os_state->v = v;
        await_fuzzer(f);
    }

    if (f->do_restore) {
        //TODO: restore here
    } else {
        exit(0);
    }
}

void HELPER(fuzzer_forkserver)(void) {

}

void HELPER(fuzzer_begin)(void) {
    fuzzer_t *f = fuzzer_lock();
    f->coverage_active = true;
    fuzzer_unlock(f);
}

void HELPER(fuzzer_end)(void) {
    fuzzer_t *f = fuzzer_lock();
    f->coverage_active = false;
    fuzzer_unlock(f);
}

void HELPER(fuzzer_restrict_coverage)(void) {
    fuzzer_t *f = fuzzer_lock();
    f->base = reg(0);
    f->limit = reg(1);
    fuzzer_unlock(f);
}

void HELPER(fuzzer_fetch_testcase)(void) {
    fuzzer_t *f = fuzzer_lock();
    
    if (!f->testcase) {
        FILE *file = fopen(f->testcase_path, "r");
        fseek(file, 0, SEEK_END);
        size_t size = ftell(file);
        rewind(file);
        f->testcase = malloc(size);
        f->testcase_size = size;

        if (fread(f->testcase, sizeof(char), size, file) == -1) {
            LOG("Cannot read testcase from file %s, reason: %s", f->testcase_path, strerror(errno));
            exit(FUZZER_FAIL);
        }
    }

    target_ulong dst = reg(0);
    target_ulong dst_size = reg(1);

    if (dst_size >= f->testcase_size) {
        cpu_memory_rw_debug(current_cpu, dst, f->testcase, f->testcase_size, true);
        free(f->testcase);
        f->testcase = NULL;
    }

    set_reg(0, f->testcase_size);
    fuzzer_unlock(f);
}

void HELPER(fuzzer_kill)(void) {
    fuzzer_t *f = fuzzer_lock();
    send_state(f, __W_EXITCODE(0, reg(0)));
    fuzzer_unlock(f);
}

void HELPER(fuzzer_exit)(void) {
    fuzzer_t *f = fuzzer_lock();
    send_state(f, __W_EXITCODE(reg(0), 0));
    fuzzer_unlock(f);
}

void HELPER(fuzzer_log)(void) {
    target_ulong ptr = reg(0);
    target_ulong len = reg(1);

    char *msg = (char *) malloc(len + 1);
    cpu_memory_rw_debug(current_cpu, ptr, msg, len, false);
    msg[len] = 0;
    LOG("Message from OS [%s]\n", msg);
    free(msg);
}

void HELPER(fuzzer_log_pc)(uint64_t h) {
    fuzzer_t *f = fuzzer_lock();
    f->bitmap[h]++;
    fuzzer_unlock(f);
}

void fuzzer_set_testcase_file(const char *path) {
    fuzzer_t *f = fuzzer_lock();
    f->testcase_path = path;
    fuzzer_unlock(f);
}

void fuzzer_init(void) {
    fuzzer_t *f = fuzzer_lock();
    
    f->os_state = (os_state_t *) mmap(
        NULL, 
        sizeof(os_state_t), 
        PROT_READ | PROT_WRITE, 
        MAP_SHARED, 
        FUZZER_OS_STATE_FD, 
        0
    );

    if (!f->os_state) {
        LOG("Didn't connect to shared mem for passing OS state\n");
    }

    fuzzer_unlock(f);
}

void fuzzer_maybe_log_pc(target_ulong pc) {
    fuzzer_t *f = fuzzer_lock();

    if (f->coverage_active && (pc >= f->base && f->base + f->limit <= pc)) {
        target_ulong hash = pc << 1 ^ pc;
        TCGv_i64 h = tcg_const_i64(hash);
        gen_helper_fuzzer_log_pc(h);
    }

    fuzzer_unlock(f);
}
