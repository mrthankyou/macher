/*
 * mach_fuzzer.c — Generalized Mach message fuzzer for macOS
 *
 * Discovers and fuzzes Mach service ports: bootstrap services, raw port rights,
 * and (via --webkit) WebKit UIProcess IPC with a structured seed corpus.
 *
 * Build:
 *   clang -O1 -g -Wall -Wextra -o mach_fuzzer mach_fuzzer.c
 *
 * Targets: macOS 15.x, arm64 (Apple Silicon)
 * No SIP bypass required — targets only ports reachable from user context.
 */

#include <mach/mach.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <mach/bootstrap.h>
#include <servers/bootstrap.h>

/* bootstrap_info was removed from the public SDK header but is still exported
 * from libSystem.B.dylib.  Forward-declare it so we can call it directly. */
extern kern_return_t bootstrap_info(
    mach_port_t              bp,
    name_array_t            *service_names,
    mach_msg_type_number_t  *service_names_cnt,
    bootstrap_status_array_t *service_active,
    mach_msg_type_number_t  *service_active_cnt
);
#include <signal.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>

/* ─── limits ─────────────────────────────────────────────────────────────── */

#define MAX_MSG_BODY        4096
#define MAX_MSG_TOTAL       (MAX_MSG_BODY + sizeof(mach_msg_header_t) + 64)
#define SEND_TIMEOUT_MS     50
#define FINDINGS_DIR        "findings"
#define PROGRESS_INTERVAL   10000ULL

/* ─── webkit ipc constants ───────────────────────────────────────────────── */

/*
 * WebKit IPC body layout (open-source: webkit.org/WebKit IPC/MessageNames.h)
 * All integers are little-endian.
 *
 * Async message:
 *   [0]      MessageFlags  (uint8_t)
 *   [1..2]   MessageName   (uint16_t)  -- enum class MessageName : uint16_t
 *   [3..10]  DestinationID (uint64_t)  -- WebPage/WebView instance id
 *   [11..]   payload       (length-prefixed, no type tags)
 *
 * Sync message (MessageFlags & WK_FLAG_SYNC):
 *   [0]      MessageFlags  (uint8_t)
 *   [1..2]   MessageName   (uint16_t)
 *   [3..10]  DestinationID (uint64_t)
 *   [11..18] SyncRequestID (uint64_t)
 *   [19..]   payload
 */

#define WK_FLAG_SYNC            0x01u
#define WK_FLAG_DISPATCH        0x02u
#define WK_FLAG_STOP_QUEUE      0x04u

/* Approximate MessageName enum values from WebKit open source.
 * Exact values depend on macOS version; use webkit_ipc_target --list-messages. */
#define WK_MSG_LOAD_URL             ((uint16_t)0x0001)
#define WK_MSG_GO_BACK              ((uint16_t)0x0002)
#define WK_MSG_GO_FORWARD           ((uint16_t)0x0003)
#define WK_MSG_RELOAD               ((uint16_t)0x0004)
#define WK_MSG_STOP_LOADING         ((uint16_t)0x0005)
#define WK_MSG_SCALE_PAGE           ((uint16_t)0x0010)
#define WK_MSG_SET_INITIAL_FOCUS    ((uint16_t)0x0020)
#define WK_MSG_NAVIGATE             ((uint16_t)0x0030)
#define WK_MSG_CLOSE                ((uint16_t)0x00FF)

#define N_WK_SEEDS  8

/* ─── types ──────────────────────────────────────────────────────────────── */

typedef enum { MODE_RANDOM, MODE_MUTATE } fuzz_mode_t;

typedef struct {
    uint8_t  data[MAX_MSG_BODY];
    size_t   size;
    const char *label;
} seed_t;

typedef struct {
    mach_port_t   port;
    fuzz_mode_t   mode;
    size_t        max_body;
    uint64_t      iterations;   /* 0 = run forever */
    const char   *out_dir;
    bool          webkit_mode;
    pid_t         target_pid;   /* 0 = not monitoring */
    uint8_t      *seed_data;
    size_t        seed_size;
} fuzz_config_t;

/* ─── global crash-detection state ──────────────────────────────────────── */

static sigjmp_buf            g_crash_jmp;
static volatile sig_atomic_t g_in_fuzz   = 0;
static volatile sig_atomic_t g_crash_sig = 0;

/* Pre-allocated so crash handler can read it async-signal-safely. */
static uint8_t  g_last_msg[MAX_MSG_TOTAL];
static size_t   g_last_msg_size = 0;

/* Stats (only touched outside signal handler). */
static uint64_t g_iters       = 0;
static uint64_t g_crashes     = 0;
static uint64_t g_send_errors = 0;

/* ─── interesting mutation values ────────────────────────────────────────── */

static const uint8_t kIB[] = { 0x00,0x01,0x7f,0x80,0xfe,0xff };
static const uint16_t kIW[] = {
    0x0000,0x0001,0x007f,0x0080,0x00ff,
    0x7fff,0x8000,0xfffe,0xffff };
static const uint32_t kID[] = {
    0x00000000,0x00000001,0x0000007f,0x00000080,0x000000ff,
    0x0000ffff,0x7fffffff,0x80000000,0xfffffffe,0xffffffff };
static const uint64_t kIQ[] = {
    0x0ULL, 0x1ULL, 0x7fffffffULL, 0x80000000ULL,
    0xffffffffULL, 0x7fffffffffffffffULL,
    0x8000000000000000ULL, 0xfffffffffffffffeULL, 0xffffffffffffffffULL };

/* ─── prng (xorshift32, no stdlib) ──────────────────────────────────────── */

static uint32_t g_rng_state = 0;

static void rng_seed(void) {
    g_rng_state = (uint32_t)(getpid() ^ (uint32_t)time(NULL));
    if (!g_rng_state) g_rng_state = 0xdeadbeef;
}

static inline uint32_t rand32(void) {
    g_rng_state ^= g_rng_state << 13;
    g_rng_state ^= g_rng_state >> 17;
    g_rng_state ^= g_rng_state << 5;
    return g_rng_state;
}

static inline uint64_t rand64(void) {
    return ((uint64_t)rand32() << 32) | rand32();
}

static inline size_t rand_range(size_t lo, size_t hi) {
    if (lo >= hi) return lo;
    return lo + (size_t)(rand32() % (uint32_t)(hi - lo));
}

static void fill_random(uint8_t *buf, size_t n) {
    size_t i = 0;
    for (; i + 4 <= n; i += 4) {
        uint32_t v = rand32();
        memcpy(buf + i, &v, 4);
    }
    if (i < n) {
        uint32_t v = rand32();
        memcpy(buf + i, &v, n - i);
    }
}

/* ─── mutation engine (AFL-style havoc) ─────────────────────────────────── */

static void mutate_buffer(uint8_t *buf, size_t *size, size_t max_size) {
    if (*size == 0) return;

    int rounds = 1 + (int)(rand32() % 8);
    for (int r = 0; r < rounds; r++) {
        size_t pos, n, src;
        switch (rand32() % 10) {

        case 0: /* random byte */
            buf[rand32() % *size] = (uint8_t)rand32();
            break;

        case 1: /* bit flip */
            pos = rand32() % *size;
            buf[pos] ^= (uint8_t)(1u << (rand32() % 8));
            break;

        case 2: /* interesting byte */
            buf[rand32() % *size] = kIB[rand32() % (sizeof kIB)];
            break;

        case 3: /* interesting uint16 */
            if (*size >= 2) {
                pos = rand32() % (*size - 1);
                uint16_t v = kIW[rand32() % (sizeof(kIW)/sizeof(*kIW))];
                memcpy(buf + pos, &v, 2);
            }
            break;

        case 4: /* interesting uint32 */
            if (*size >= 4) {
                pos = rand32() % (*size - 3);
                uint32_t v = kID[rand32() % (sizeof(kID)/sizeof(*kID))];
                memcpy(buf + pos, &v, 4);
            }
            break;

        case 5: /* interesting uint64 (allocation-wraparound probe) */
            if (*size >= 8) {
                pos = rand32() % (*size - 7);
                uint64_t v = kIQ[rand32() % (sizeof(kIQ)/sizeof(*kIQ))];
                memcpy(buf + pos, &v, 8);
            }
            break;

        case 6: /* block delete */
            if (*size > 1) {
                n   = rand_range(1, *size / 2 + 1);
                pos = rand32() % (*size - n + 1);
                memmove(buf + pos, buf + pos + n, *size - pos - n);
                *size -= n;
            }
            break;

        case 7: /* block copy (covers repetition/overlap) */
            if (*size >= 2) {
                n   = rand_range(1, *size / 2);
                src = rand32() % (*size - n + 1);
                pos = rand32() % (*size - n + 1);
                memmove(buf + pos, buf + src, n);
            }
            break;

        case 8: /* insert random bytes */
            if (*size < max_size - 8) {
                n   = rand_range(1, 8);
                n   = (*size + n > max_size) ? (max_size - *size) : n;
                pos = rand32() % (*size + 1);
                memmove(buf + pos + n, buf + pos, *size - pos);
                fill_random(buf + pos, n);
                *size += n;
            }
            break;

        case 9: /* arithmetic: add/sub small value at a byte */
            pos = rand32() % *size;
            buf[pos] = (uint8_t)(buf[pos] + (rand32() % 35) - 17);
            break;
        }
    }
}

/* ─── webkit ipc body builder ────────────────────────────────────────────── */

static size_t wk_build_body(uint8_t *body, size_t cap,
                             uint8_t flags, uint16_t name,
                             uint64_t dest_id,
                             const uint8_t *payload, size_t plen)
{
    size_t off = 0;

    if (off + 1 > cap) return off;
    body[off++] = flags;

    if (off + 2 > cap) return off;
    memcpy(body + off, &name, 2);    off += 2;

    if (off + 8 > cap) return off;
    memcpy(body + off, &dest_id, 8); off += 8;

    if ((flags & WK_FLAG_SYNC) && off + 8 <= cap) {
        uint64_t sync_id = rand64() | 1ULL; /* non-zero sync id */
        memcpy(body + off, &sync_id, 8); off += 8;
    }

    if (payload && plen > 0) {
        size_t copy = plen < (cap - off) ? plen : (cap - off);
        memcpy(body + off, payload, copy);
        off += copy;
    }

    return off;
}

/* ─── webkit seed corpus ─────────────────────────────────────────────────── */

static seed_t g_wk_seeds[N_WK_SEEDS];

static void init_webkit_seeds(void) {
    size_t sz;

    /* 0: async LoadURL, empty payload */
    sz = wk_build_body(g_wk_seeds[0].data, sizeof g_wk_seeds[0].data,
                       0x00, WK_MSG_LOAD_URL, 1ULL, NULL, 0);
    g_wk_seeds[0].size = sz; g_wk_seeds[0].label = "async_load_url_empty";

    /* 1: sync ScalePage, empty payload */
    sz = wk_build_body(g_wk_seeds[1].data, sizeof g_wk_seeds[1].data,
                       WK_FLAG_SYNC, WK_MSG_SCALE_PAGE, 1ULL, NULL, 0);
    g_wk_seeds[1].size = sz; g_wk_seeds[1].label = "sync_scale_page_empty";

    /* 2: allocation-wraparound — uint64_t length field near UINT64_MAX */
    {
        uint8_t pl[16];
        uint64_t big = 0xffffffffffffffffULL;
        memcpy(pl, &big, 8);
        memset(pl + 8, 0, 8);
        sz = wk_build_body(g_wk_seeds[2].data, sizeof g_wk_seeds[2].data,
                           0x00, WK_MSG_LOAD_URL, 1ULL, pl, 16);
        g_wk_seeds[2].size = sz; g_wk_seeds[2].label = "overflow_maxuint64_length";
    }

    /* 3: truncated — stops mid-DestinationID (triggers short-read path) */
    {
        uint8_t raw[5];
        raw[0] = 0x00;                  /* flags    */
        raw[1] = WK_MSG_RELOAD & 0xFF;  /* name lo  */
        raw[2] = WK_MSG_RELOAD >> 8;    /* name hi  */
        raw[3] = 0x01; raw[4] = 0x00;   /* partial DestinationID */
        memcpy(g_wk_seeds[3].data, raw, 5);
        g_wk_seeds[3].size = 5; g_wk_seeds[3].label = "truncated_mid_dest_id";
    }

    /* 4: misaligned — 1-byte prefix shifts all subsequent fields by 1 */
    {
        uint8_t pl[9];
        pl[0] = 0xAA; /* misalignment byte */
        uint64_t v = 0x0102030405060708ULL;
        memcpy(pl + 1, &v, 8);
        sz = wk_build_body(g_wk_seeds[4].data, sizeof g_wk_seeds[4].data,
                           0x00, WK_MSG_GO_BACK, 1ULL, pl, 9);
        g_wk_seeds[4].size = sz; g_wk_seeds[4].label = "misaligned_payload";
    }

    /* 5: valid header, wrong payload type (string where uint64 expected) */
    {
        const char *str = "AAAAAAAAAAAAAAAA"; /* 16 'A's */
        sz = wk_build_body(g_wk_seeds[5].data, sizeof g_wk_seeds[5].data,
                           0x00, WK_MSG_SCALE_PAGE, 1ULL,
                           (const uint8_t *)str, 16);
        g_wk_seeds[5].size = sz; g_wk_seeds[5].label = "wrong_type_string_as_uint";
    }

    /* 6: sync with SyncRequestID=0 (degenerate / zero-id sync) */
    {
        uint8_t pl[8]; memset(pl, 0, 8);
        sz = wk_build_body(g_wk_seeds[6].data, sizeof g_wk_seeds[6].data,
                           WK_FLAG_SYNC, WK_MSG_CLOSE, 1ULL, pl, 8);
        g_wk_seeds[6].size = sz; g_wk_seeds[6].label = "sync_zero_request_id";
    }

    /* 7: dispatch + stop-queue flag combo, Navigate message */
    {
        uint8_t flags = WK_FLAG_DISPATCH | WK_FLAG_STOP_QUEUE;
        sz = wk_build_body(g_wk_seeds[7].data, sizeof g_wk_seeds[7].data,
                           flags, WK_MSG_NAVIGATE, 1ULL, NULL, 0);
        g_wk_seeds[7].size = sz; g_wk_seeds[7].label = "dispatch_stop_queue_navigate";
    }
}

/* ─── port discovery ─────────────────────────────────────────────────────── */

static mach_port_t lookup_bootstrap_service(const char *name) {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, name, &port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[!] bootstrap_look_up(%s): %s (%d)\n",
                name, mach_error_string(kr), kr);
        return MACH_PORT_NULL;
    }
    fprintf(stderr, "[+] Looked up '%s' → port 0x%x\n", name, port);
    return port;
}

static void cmd_list_services(void) {
    name_array_t            snames     = NULL;
    mach_msg_type_number_t  snames_cnt = 0;
    bootstrap_status_array_t sstatus   = NULL;
    mach_msg_type_number_t  sstatus_cnt = 0;

    kern_return_t kr = bootstrap_info(bootstrap_port,
                                       &snames,  &snames_cnt,
                                       &sstatus, &sstatus_cnt);

    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[!] bootstrap_info: %s (%d)\n",
                mach_error_string(kr), kr);
        fprintf(stderr, "    Note: bootstrap_info is restricted on macOS 15.\n"
                        "    Use 'launchctl list' or 'launchctl print system/'\n"
                        "    to enumerate services, then --port <name> to target.\n");
        return;
    }

    printf("[*] Bootstrap services visible to this process (%u):\n", snames_cnt);
    for (mach_msg_type_number_t i = 0; i < snames_cnt; i++) {
        int active = (i < sstatus_cnt) ? (int)sstatus[i] : -1;
        printf("  %-8s  %s\n", active > 0 ? "active" : "inactive", snames[i]);
    }

    vm_deallocate(mach_task_self(), (vm_address_t)snames,
                  snames_cnt  * sizeof *snames);
    vm_deallocate(mach_task_self(), (vm_address_t)sstatus,
                  sstatus_cnt * sizeof *sstatus);
}

static void cmd_list_ports(void) {
    mach_port_name_array_t  names     = NULL;
    mach_msg_type_number_t  names_cnt = 0;
    mach_port_type_array_t  types     = NULL;
    mach_msg_type_number_t  types_cnt = 0;

    kern_return_t kr = mach_port_names(mach_task_self(),
                                        &names, &names_cnt,
                                        &types, &types_cnt);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "[!] mach_port_names: %s\n", mach_error_string(kr));
        return;
    }

    printf("[*] Task port rights (%u):\n", names_cnt);
    for (mach_msg_type_number_t i = 0; i < names_cnt; i++) {
        mach_port_type_t t = (i < types_cnt) ? types[i] : 0;
        const char *kind;
        if      (t & MACH_PORT_TYPE_SEND)       kind = "SEND";
        else if (t & MACH_PORT_TYPE_RECEIVE)     kind = "RECEIVE";
        else if (t & MACH_PORT_TYPE_SEND_ONCE)   kind = "SEND_ONCE";
        else if (t & MACH_PORT_TYPE_DEAD_NAME)   kind = "DEAD";
        else                                      kind = "OTHER";
        printf("  0x%08x  type=0x%08x  %s\n", names[i], t, kind);
    }

    vm_deallocate(mach_task_self(), (vm_address_t)names,
                  names_cnt * sizeof *names);
    vm_deallocate(mach_task_self(), (vm_address_t)types,
                  types_cnt * sizeof *types);
}

/* ─── message assembly ───────────────────────────────────────────────────── */

static size_t build_message(uint8_t *buf, size_t cap,
                             mach_port_t target, mach_msg_id_t msg_id,
                             const uint8_t *body, size_t body_size)
{
    size_t hdr_sz = sizeof(mach_msg_header_t);
    size_t total  = hdr_sz + body_size;
    if (total > cap) total = cap;

    mach_msg_header_t *hdr = (mach_msg_header_t *)buf;
    memset(hdr, 0, hdr_sz);
    hdr->msgh_bits         = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    hdr->msgh_size         = (mach_msg_size_t)total;
    hdr->msgh_remote_port  = target;
    hdr->msgh_local_port   = MACH_PORT_NULL;
    hdr->msgh_voucher_port = MACH_PORT_NULL;
    hdr->msgh_id           = msg_id;

    size_t copy = (body_size < cap - hdr_sz) ? body_size : (cap - hdr_sz);
    memcpy(buf + hdr_sz, body, copy);

    return hdr_sz + copy;
}

/* ─── crash handler ──────────────────────────────────────────────────────── */

static void crash_handler(int sig,
                           siginfo_t *info __attribute__((unused)),
                           void *uctx __attribute__((unused)))
{
    if (g_in_fuzz) {
        g_crash_sig = (sig_atomic_t)sig;
        g_in_fuzz   = 0;
        siglongjmp(g_crash_jmp, sig);
    }
    /* Crash outside fuzzing window: restore default and re-raise. */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL;
    sigaction(sig, &sa, NULL);
    raise(sig);
}

static void install_crash_handlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
}

/* ─── crash archiving ────────────────────────────────────────────────────── */

static void save_crash(int sig, const uint8_t *msg, size_t msg_size,
                        const char *out_dir, uint64_t iter)
{
    char path[512];
    snprintf(path, sizeof path, "%s/crash_%llu_sig%d.bin",
             out_dir, (unsigned long long)iter, sig);

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror("open crash file"); return; }

    const uint8_t *p = msg;
    ssize_t left = (ssize_t)msg_size;
    while (left > 0) {
        ssize_t n = write(fd, p, (size_t)left);
        if (n <= 0) break;
        p += n; left -= n;
    }
    close(fd);

    fprintf(stderr, "[CRASH] sig=%d  iter=%-10llu  → %s  (%zu bytes)\n",
            sig, (unsigned long long)iter, path, msg_size);
}

/* ─── main fuzzing loop ──────────────────────────────────────────────────── */

static void fuzz_loop(const fuzz_config_t *cfg) {
    static uint8_t body[MAX_MSG_BODY];
    static uint8_t msg[MAX_MSG_TOTAL];

    mkdir(cfg->out_dir, 0755);

    fprintf(stderr, "[*] port=0x%x  mode=%s  webkit=%s  max_body=%zu  iters=%llu\n",
            cfg->port,
            cfg->mode == MODE_RANDOM ? "random" : "mutate",
            cfg->webkit_mode ? "yes" : "no",
            cfg->max_body,
            (unsigned long long)cfg->iterations);

    int  seed_idx  = 0;
    bool port_dead = false;

    for (uint64_t iter = 0;
         !port_dead && (cfg->iterations == 0 || iter < cfg->iterations);
         iter++)
    {
        /* ── Generate body ── */
        size_t body_sz = 0;

        if (cfg->mode == MODE_RANDOM) {
            body_sz = rand_range(0, cfg->max_body + 1);
            fill_random(body, body_sz);

        } else { /* MODE_MUTATE */
            const uint8_t *src    = NULL;
            size_t         src_sz = 0;

            if (cfg->webkit_mode) {
                src    = g_wk_seeds[seed_idx].data;
                src_sz = g_wk_seeds[seed_idx].size;
                seed_idx = (seed_idx + 1) % N_WK_SEEDS;
            } else if (cfg->seed_data && cfg->seed_size > 0) {
                src    = cfg->seed_data;
                src_sz = cfg->seed_size;
            } else {
                /* No seed: fall back to random. */
                body_sz = rand_range(0, cfg->max_body + 1);
                fill_random(body, body_sz);
                goto have_body;
            }

            body_sz = (src_sz < cfg->max_body) ? src_sz : cfg->max_body;
            memcpy(body, src, body_sz);
            mutate_buffer(body, &body_sz, cfg->max_body);
        }
have_body:;

        /* ── Choose msgh_id ── */
        mach_msg_id_t msg_id;
        if (cfg->webkit_mode)
            msg_id = (mach_msg_id_t)(rand32() & 0xFFFF);
        else
            msg_id = (mach_msg_id_t)rand32();

        /* ── Assemble Mach message ── */
        size_t msg_sz = build_message(msg, sizeof msg,
                                       cfg->port, msg_id, body, body_sz);

        /* Save copy for crash handler (no alloc in signal context). */
        memcpy(g_last_msg, msg, msg_sz);
        g_last_msg_size = msg_sz;

        /* ── Send with in-process crash protection ── */
        int crash_sig = sigsetjmp(g_crash_jmp, 1);
        if (crash_sig != 0) {
            /* We jumped here from crash_handler. */
            g_crashes++;
            save_crash(crash_sig, g_last_msg, g_last_msg_size,
                       cfg->out_dir, iter);
            install_crash_handlers(); /* refresh after SA_RESETHAND would clear */
            continue;
        }

        g_in_fuzz = 1;

        kern_return_t kr = mach_msg(
            (mach_msg_header_t *)msg,
            MACH_SEND_MSG | MACH_SEND_TIMEOUT,
            (mach_msg_size_t)msg_sz,
            0,
            MACH_PORT_NULL,
            SEND_TIMEOUT_MS,
            MACH_PORT_NULL
        );

        g_in_fuzz = 0;

        if (kr != MACH_MSG_SUCCESS) {
            g_send_errors++;
            if (kr == MACH_SEND_INVALID_DEST) {
                fprintf(stderr, "[!] Port 0x%x is dead — target process exited.\n",
                        cfg->port);
                g_crashes++;
                save_crash(0, g_last_msg, g_last_msg_size, cfg->out_dir, iter);
                port_dead = true;
                continue;
            }
            /* MACH_SEND_TIMED_OUT / NO_BUFFER: target is busy, keep going. */
        }

        /* Periodically check out-of-process target liveness. */
        if (cfg->target_pid > 0 && iter % 500 == 0) {
            if (kill(cfg->target_pid, 0) < 0 && errno == ESRCH) {
                fprintf(stderr, "[!] Target PID %d is gone (iter=%llu).\n",
                        (int)cfg->target_pid, (unsigned long long)iter);
                g_crashes++;
                save_crash(0, g_last_msg, g_last_msg_size, cfg->out_dir, iter);
                port_dead = true;
                continue;
            }
        }

        g_iters++;

        if (iter > 0 && iter % PROGRESS_INTERVAL == 0) {
            fprintf(stderr, "[*] iter=%-12llu  crashes=%-6llu  errors=%llu\n",
                    (unsigned long long)iter,
                    (unsigned long long)g_crashes,
                    (unsigned long long)g_send_errors);
        }
    }

    fprintf(stderr, "[*] Finished: %llu iters  %llu crashes  %llu errors\n",
            (unsigned long long)g_iters,
            (unsigned long long)g_crashes,
            (unsigned long long)g_send_errors);
}

/* ─── cli ────────────────────────────────────────────────────────────────── */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "Port selection (one required for fuzzing):\n"
        "  --port <svc>           Bootstrap service name (bootstrap_look_up)\n"
        "  --port-right <n>       Raw Mach port name in this task (hex OK)\n"
        "  --list-services        List bootstrap-visible services and exit\n"
        "  --list-ports           List task port rights and exit\n"
        "\n"
        "Fuzzing options:\n"
        "  --webkit               WebKit IPC seed corpus + message format\n"
        "  --mode random|mutate   Body generation (default: random)\n"
        "  --seed <file>          Seed file for mutate mode\n"
        "  --max-size <n>         Max body bytes (default: 4096)\n"
        "  --iterations <n>       Iteration count, 0=infinite (default: 0)\n"
        "  --pid <pid>            Monitor target PID; stop if it exits\n"
        "  --out <dir>            Crash directory (default: findings/)\n"
        "  --help                 Show this message\n"
        "\n"
        "Examples:\n"
        "  # List all bootstrap services\n"
        "  %s --list-services\n"
        "\n"
        "  # Fuzz coreaudiod indefinitely\n"
        "  %s --port com.apple.coreaudiod --mode random\n"
        "\n"
        "  # Mutate-fuzz with a seed file, 1M iterations\n"
        "  %s --port com.apple.windowserver --mode mutate --seed seed.bin \\\n"
        "         --iterations 1000000 --out crashes/\n"
        "\n"
        "  # Use raw port right (from webkit_ipc_target --find-port)\n"
        "  %s --port-right 0x1207 --webkit --mode mutate\n"
        "\n",
        prog, prog, prog, prog, prog);
}

int main(int argc, char *argv[]) {
    static const struct option long_opts[] = {
        { "port",          required_argument, NULL, 'p' },
        { "port-right",    required_argument, NULL, 'r' },
        { "list-services", no_argument,       NULL, 'L' },
        { "list-ports",    no_argument,       NULL, 'P' },
        { "webkit",        no_argument,       NULL, 'w' },
        { "mode",          required_argument, NULL, 'm' },
        { "seed",          required_argument, NULL, 's' },
        { "max-size",      required_argument, NULL, 'z' },
        { "iterations",    required_argument, NULL, 'i' },
        { "pid",           required_argument, NULL, 'd' },
        { "out",           required_argument, NULL, 'o' },
        { "help",          no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    fuzz_config_t cfg = {
        .port        = MACH_PORT_NULL,
        .mode        = MODE_RANDOM,
        .max_body    = MAX_MSG_BODY,
        .iterations  = 0,
        .out_dir     = FINDINGS_DIR,
        .webkit_mode = false,
        .target_pid  = 0,
        .seed_data   = NULL,
        .seed_size   = 0,
    };

    bool do_list_svc   = false;
    bool do_list_ports = false;

    int opt;
    while ((opt = getopt_long(argc, argv, "p:r:LPwm:s:z:i:d:o:h",
                               long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            cfg.port = lookup_bootstrap_service(optarg);
            if (cfg.port == MACH_PORT_NULL) return 1;
            break;
        case 'r':
            cfg.port = (mach_port_t)strtoul(optarg, NULL, 0);
            fprintf(stderr, "[*] Using raw port right 0x%x\n", cfg.port);
            break;
        case 'L':
            do_list_svc = true;
            break;
        case 'P':
            do_list_ports = true;
            break;
        case 'w':
            cfg.webkit_mode = true;
            break;
        case 'm':
            if      (strcmp(optarg, "random") == 0) cfg.mode = MODE_RANDOM;
            else if (strcmp(optarg, "mutate") == 0) cfg.mode = MODE_MUTATE;
            else { fprintf(stderr, "[!] Unknown mode: %s\n", optarg); return 1; }
            break;
        case 's': {
            FILE *f = fopen(optarg, "rb");
            if (!f) { perror(optarg); return 1; }
            fseek(f, 0, SEEK_END);
            long fsz = ftell(f); rewind(f);
            if (fsz > 0) {
                cfg.seed_data = (uint8_t *)malloc((size_t)fsz);
                if (!cfg.seed_data) { perror("malloc"); fclose(f); return 1; }
                cfg.seed_size = fread(cfg.seed_data, 1, (size_t)fsz, f);
            }
            fclose(f);
            fprintf(stderr, "[+] Seed: %zu bytes from %s\n", cfg.seed_size, optarg);
            break;
        }
        case 'z':
            cfg.max_body = (size_t)strtoul(optarg, NULL, 0);
            if (cfg.max_body > MAX_MSG_BODY) cfg.max_body = MAX_MSG_BODY;
            break;
        case 'i':
            cfg.iterations = strtoull(optarg, NULL, 0);
            break;
        case 'd':
            cfg.target_pid = (pid_t)atoi(optarg);
            break;
        case 'o':
            cfg.out_dir = optarg;
            break;
        case 'h':
            usage(argv[0]); return 0;
        default:
            usage(argv[0]); return 1;
        }
    }

    if (do_list_svc)   { cmd_list_services(); }
    if (do_list_ports) { cmd_list_ports(); }
    if (do_list_svc || do_list_ports) return 0;

    if (cfg.port == MACH_PORT_NULL) {
        fprintf(stderr, "[!] No target port. Use --port, --port-right, "
                        "--list-services, or --list-ports.\n");
        usage(argv[0]);
        return 1;
    }

    rng_seed();

    if (cfg.webkit_mode)
        init_webkit_seeds();

    /* Alternate signal stack (catches stack-overflow variants). */
    static uint8_t alt_stack_mem[65536];
    stack_t ss = {
        .ss_sp    = alt_stack_mem,
        .ss_size  = sizeof alt_stack_mem,
        .ss_flags = 0,
    };
    sigaltstack(&ss, NULL);
    install_crash_handlers();

    fuzz_loop(&cfg);

    mach_port_deallocate(mach_task_self(), cfg.port);
    free(cfg.seed_data);

    /* Exit code: 0 = clean, 2 = crashes found. */
    return (g_crashes > 0) ? 2 : 0;
}
