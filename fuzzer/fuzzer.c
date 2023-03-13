#include "fuzzer.h"
#include "block/aio.h"
#include "exec/hwaddr.h"
#include "exec/memory.h"
#include "fuzzer_api.h"
#include "hw/core/cpu.h"
#include "migration/snapshot.h"
#include "qemu/int128.h"
#include "qemu/osdep.h"

#include "cpu.h"
#include "internals.h"
#include "disas/disas.h"
#include "exec/exec-all.h"
#include "qemu/qemu-print.h"
#include "qemu/typedefs.h"
#include "sysemu/cpus.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg-op-gvec.h"
#include "qemu/log.h"
#include "qemu/bitops.h"
#include "arm_ldst.h"
#include "semihosting/semihost.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "qemu/main-loop.h"
#include "qapi/error.h"

#include "exec/log.h"
#include "tcg/tcg.h"
#include "translate.h"
#include <bits/pthreadtypes.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <unistd.h>

typedef struct {
    sem_t sem;
    int v;
} os_state_t;

typedef struct {
    pthread_mutex_t mutex;

    bool coverage_active;
    target_ulong base;
    target_ulong limit;
    const char *testcase_path;
    char *testcase;
    size_t testcase_size;
    os_state_t *os_state;
    bool state_saved;
    bool do_restore;

    QEMUBH *savevm_cb;
    QEMUBH *loadvm_cb;

    target_ulong prev_pc;
    char *bitmap;

#if defined(TARGET_AARCH64)
    CPUARMState env;
    uint8_t *mpu_regs;
    GList *saved_mem;
    bool do_fast_save_restore;
#endif

} fuzzer_t;

typedef struct {
    const char *name;
    uint8_t *mem;
    MemoryRegion *mr;
    Int128 len;
} SavedMemRegion;

#define FUZZER_FAIL -69

#define FUZZER_OS_STATE_FD 399
#define FUZZER_RESTORE_EVENT_FD 400
#define FUZZER_BITMAP_SIZE 1 << 16

static fuzzer_t gFuzzer = {
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .coverage_active = false,
    .base = 0,
    .limit = (target_ulong) 0xffffffffffffffffULL,
    .do_fast_save_restore = false
};

static fuzzer_t *fuzzer_lock(void) {
    pthread_mutex_lock(&gFuzzer.mutex);
    return &gFuzzer;
}

static void fuzzer_unlock(fuzzer_t *fuzzer) {
    pthread_mutex_unlock(&fuzzer->mutex);
}
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

static void mark_as_jump(DisasContext *s) {
    fuzzer_t *f = fuzzer_lock();
    if (f->do_fast_save_restore)
        s->base.is_jmp = DISAS_JUMP;
    fuzzer_unlock(f);
}

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
            mark_as_jump(s);
            break;
        case FUZZER_EXIT:
            LOG("Translating instruction FUZZER_EXIT\n");
            gen_helper_fuzzer_exit();
            mark_as_jump(s);
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

static void fast_save_cpu(fuzzer_t *f) {
    memcpy(&f->env, &ARM_CPU(current_cpu)->env, sizeof(f->env));
    LOG("CPU state saved fast\n");
}

static void fast_restore_cpu(fuzzer_t *f) {
    memcpy(&ARM_CPU(current_cpu)->env, &f->env, sizeof(f->env));
    LOG("CPU state loaded fast\n");
}

static void fast_save_mpu_regs(fuzzer_t *f) {
    ARMCPU *arm = ARM_CPU(current_cpu);

    size_t size = 
        2 * M_REG_NUM_BANKS * arm->pmsav7_dregion * sizeof(uint32_t) + 
        2 * arm->sau_sregion * sizeof(uint32_t) + 
        3 * arm->pmsav7_dregion * sizeof(uint32_t);

    uint8_t *buffer = (uint8_t *) malloc(size);
    uint8_t *ptr = buffer;

    for (uint32_t i=0; i < M_REG_NUM_BANKS; ++i) {
        memcpy(ptr, arm->env.pmsav8.rbar[i], arm->pmsav7_dregion * sizeof(uint32_t));
        ptr += arm->pmsav7_dregion * sizeof(uint32_t);
    }

    for (uint32_t i=0; i < M_REG_NUM_BANKS; ++i) {
        memcpy(ptr, arm->env.pmsav8.rlar[i], arm->pmsav7_dregion * sizeof(uint32_t));
        ptr += arm->pmsav7_dregion * sizeof(uint32_t);
    }

    memcpy(ptr, arm->env.sau.rbar, arm->sau_sregion * sizeof(uint32_t));
    ptr += arm->sau_sregion * sizeof(uint32_t);

    memcpy(ptr, arm->env.sau.rlar, arm->sau_sregion * sizeof(uint32_t));
    ptr += arm->sau_sregion * sizeof(uint32_t);

    f->mpu_regs = buffer;
}

static void fast_restore_mpu_regs(fuzzer_t *f) {
    ARMCPU *arm = ARM_CPU(current_cpu);
    uint8_t *ptr = f->mpu_regs;

    for (uint32_t i=0; i < M_REG_NUM_BANKS; ++i) {
        memcpy(arm->env.pmsav8.rbar[i], ptr, arm->pmsav7_dregion * sizeof(uint32_t));
        ptr += arm->pmsav7_dregion * sizeof(uint32_t);
    }

    for (uint32_t i=0; i < M_REG_NUM_BANKS; ++i) {
        memcpy(arm->env.pmsav8.rlar[i], ptr, arm->pmsav7_dregion * sizeof(uint32_t));
        ptr += arm->pmsav7_dregion * sizeof(uint32_t);
    }

    memcpy(arm->env.sau.rbar, ptr, arm->sau_sregion * sizeof(uint32_t));
    ptr += arm->sau_sregion * sizeof(uint32_t);

    memcpy(arm->env.sau.rlar, ptr, arm->sau_sregion * sizeof(uint32_t));
    ptr += arm->sau_sregion * sizeof(uint32_t);
}

static bool fast_save_memory_region(Int128 start, Int128 len,
        const MemoryRegion *mr, hwaddr addr, void *ctx) {
    fuzzer_t *f = (fuzzer_t *) ctx;

    if (mr->ram && !mr->readonly) {
        SavedMemRegion *sm = (SavedMemRegion *) malloc(sizeof(SavedMemRegion));
        sm->name = mr->name;
        sm->mem = malloc(len);
        sm->len = len;
        sm->mr = (MemoryRegion *) mr;
        void *ptr = memory_region_get_ram_ptr((MemoryRegion *) mr);
        memcpy(sm->mem, ptr, len);
        f->saved_mem = g_list_append(f->saved_mem, sm);
        LOG("Saved fast memory region: name = %s, addr = 0x%X, len = 0x%X\n", sm->name, sm->mr->addr, len);
    }

    return false;
}

static void fast_restore_memory_region(gpointer data, gpointer ctx) {
    SavedMemRegion *sm = (SavedMemRegion *) data;
    void *ptr = memory_region_get_ram_ptr(sm->mr);
    memcpy(ptr, sm->mem, sm->len);
    LOG("Resotred fast memory region: name = %s, addr = 0x%X, len = 0x%X\n", sm->name, sm->mr->addr, sm->len);
}

static void fast_restore_memory(fuzzer_t *f) {
    g_list_foreach(f->saved_mem, &fast_restore_memory_region, NULL);
}

static void fast_save_memory(fuzzer_t *f, AddressSpace *as) {
    FlatView *fv = address_space_to_flatview(as);
    flatview_for_each_range(fv, &fast_save_memory_region, (void *) f);
}

static void fast_vmsave(fuzzer_t *f) {
    fast_save_cpu(f);
    fast_save_mpu_regs(f);
    fast_save_memory(f, 
        cpu_get_address_space(current_cpu, ARMASIdx_S)
    );
}

static void fast_vmload(fuzzer_t *f) {
    tlb_flush(current_cpu);
    fast_restore_cpu(f);
    fast_restore_mpu_regs(f);
    fast_restore_memory(f);
}

#else

#error "Selected arch is not implemented"

#endif


static void vmsave_cb(void *_) {
    LOG("Saving snapshot\n");

    Error *errp = NULL;
    if (!save_snapshot("fuzzer", true, NULL, false, NULL, &errp)) {
        LOG("Failed to save snapshot, exiting\n");
        error_report_err(errp); 
        exit(FUZZER_FAIL);
    }
    LOG("Snapshot saved\n");

    resume_all_vcpus();
    LOG("vCPUs resumed\n");
}

static void loadvm_cb(void *_) {
    LOG("Loading vm snapshot\n");
    
    Error *errp = NULL;
    if (!load_snapshot("fuzzer", NULL, false, NULL, &errp)) {
        LOG("Failed to load vm snapshot, exiting\n");
        error_report_err(errp);
        exit(FUZZER_FAIL);
    }
    LOG("Snapshot loaded successfully\n");

    resume_all_vcpus();
    LOG("All vCPUs resumed\n");
}

static void vmsave(fuzzer_t *f) {
    qemu_mutex_lock_iothread();

    fuzzer_unlock(f);
    pause_all_vcpus();
    fuzzer_lock();
    
    f->savevm_cb = qemu_bh_new(&vmsave_cb, NULL);
    f->loadvm_cb = qemu_bh_new(&loadvm_cb, NULL);
    qemu_bh_schedule(f->savevm_cb);

    qemu_mutex_unlock_iothread();
    LOG("vmsave: All vcpu paused\n");
}

static void vmload(fuzzer_t *f) {

    // Close all other vCPUs
    fuzzer_unlock(f);
    qemu_mutex_lock_iothread();
    pause_all_vcpus();

    qemu_bh_schedule(f->loadvm_cb);

    qemu_mutex_unlock_iothread();
    fuzzer_lock();

    LOG("vmload: All vcpus paused\n");
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
        if (!f->state_saved) {
            LOG("VM state not saved, exiting\n");
            exit(FUZZER_FAIL);
        }

        if (f->do_fast_save_restore)
            fast_vmload(f);
        else
            vmload(f);
    } else {
        exit(v);
    }
}

void HELPER(fuzzer_forkserver)(void) {
    fuzzer_t *f = fuzzer_lock();

    if (!f->state_saved) {
        if (f->do_fast_save_restore) 
            fast_vmsave(f);
        else
            vmsave(f);
        f->state_saved = true;
    }
    
    fuzzer_unlock(f);
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
        if (!f->testcase_path) {
            LOG("No testcase specyfing, exitting\n");
            exit(FUZZER_FAIL);
        }

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
    f->bitmap[h % FUZZER_BITMAP_SIZE]++;
    fuzzer_unlock(f);
}

void fuzzer_set_testcase_file(const char *path) {
    fuzzer_t *f = fuzzer_lock();
    f->testcase_path = path;
    fuzzer_unlock(f);
}

static void restore_event_handler(void *_) {
    fuzzer_t *f = fuzzer_lock();
    LOG("Requested to restore vm\n");
    send_state(f, __W_EXITCODE(0, SIGUSR1));
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

    if (f->os_state == MAP_FAILED) {
        f->os_state = NULL;
        LOG("Didn't connect to shared mem for passing OS state\n");
    }

    f->do_restore = !getenv("FUZZER_RUN_SINGLE");

    if (fcntl(FUZZER_RESTORE_EVENT_FD, F_GETFD) != -1) {
        // restore event is valid
        qemu_set_fd_handler(FUZZER_RESTORE_EVENT_FD, &restore_event_handler, NULL, NULL);
    }

    const char *shmid = getenv("__AFL_SHM_ID");
    if (shmid) {
        int id = atoi(shmid);

        if (id == -1) {
            LOG("Invalid AFL's shared memory id `%s`, exiting\n", shmid);
            exit(FUZZER_FAIL);
        }

        f->bitmap = shmat(id, NULL, 0);
        if (f->bitmap == (void *) -1) {
            LOG("Failed to mount AFL's shared memory: %s\n", strerror(errno));
            exit(FUZZER_FAIL);
        }

    } else {
        f->bitmap = NULL;
    }

    f->do_fast_save_restore = !getenv("FUZZER_FAST_VMSAVE");

    fuzzer_unlock(f);
}

void fuzzer_maybe_log_pc(target_ulong pc) {
    fuzzer_t *f = fuzzer_lock();

    if (f->coverage_active && (pc >= f->base && pc < f->base + f->limit) && f->bitmap) {
        target_ulong hash = pc << 4 ^ f->prev_pc;
        f->prev_pc = pc;
        TCGv_i64 h = tcg_const_i64(hash);
        gen_helper_fuzzer_log_pc(h);
    }

    fuzzer_unlock(f);
}
