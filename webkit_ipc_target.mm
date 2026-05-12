/*
 * webkit_ipc_target.mm — ObjC++ WebKit IPC fuzzing harness
 *
 * Embeds a WKWebView in-process (making this process the UIProcess), discovers
 * the Mach send rights that appeared after WebContent launched, and fires
 * fuzzed WebKit IPC messages at them.  Crashes in the IPC dispatch path are
 * caught with sigsetjmp/siglongjmp and archived to the findings/ directory.
 *
 * Build:
 *   clang++ -ObjC++ -O1 -g -Wall \
 *     -framework WebKit -framework AppKit -framework Foundation \
 *     -o webkit_ipc_target webkit_ipc_target.mm
 *
 * Usage:
 *   webkit_ipc_target [--find-port]           # print send rights added by WKWebView
 *   webkit_ipc_target [--fuzz]                # default: fuzz in-process
 *   webkit_ipc_target [--fuzz --out <dir>]    # specify crash output dir
 *   webkit_ipc_target [--fuzz --iterations N] # stop after N sends
 *   webkit_ipc_target [--fuzz --mode random|mutate]
 *
 * Target: macOS 15.x, arm64 (Apple Silicon)
 */

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <WebKit/WebKit.h>

#include <mach/mach.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <signal.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>

/* ─── constants ────────────────────────────────────────────────────────── */

#define WK_MAX_BODY       4096
#define WK_SEND_TIMEOUT   50   /* ms */
#define WK_WEBVIEW_SETTLE 2.5  /* seconds for WebContent to launch */

/* WebKit IPC flags (from open source webkit.org) */
#define WK_FLAG_SYNC        0x01u
#define WK_FLAG_DISPATCH    0x02u
#define WK_FLAG_STOP_QUEUE  0x04u

/* Approximate MessageName values (uint16_t); exact values depend on OS version.
 * Dump live values with: webkit_ipc_target --find-port --list-messages */
#define WK_MSG_LOAD_URL             ((uint16_t)0x0001)
#define WK_MSG_GO_BACK              ((uint16_t)0x0002)
#define WK_MSG_GO_FORWARD           ((uint16_t)0x0003)
#define WK_MSG_RELOAD               ((uint16_t)0x0004)
#define WK_MSG_STOP_LOADING         ((uint16_t)0x0005)
#define WK_MSG_SCALE_PAGE           ((uint16_t)0x0010)
#define WK_MSG_NAVIGATE             ((uint16_t)0x0030)
#define WK_MSG_CLOSE                ((uint16_t)0x00FF)

#define N_SEEDS 8
#define MAX_MSG_TOTAL (WK_MAX_BODY + sizeof(mach_msg_header_t) + 64)

/* ─── port snapshot ─────────────────────────────────────────────────────── */

typedef struct {
    mach_port_name_t names[8192];
    mach_port_type_t types[8192];
    int              count;
} PortSnapshot;

static void take_snapshot(PortSnapshot *snap) {
    mach_port_name_array_t  names     = NULL;
    mach_msg_type_number_t  names_cnt = 0;
    mach_port_type_array_t  types     = NULL;
    mach_msg_type_number_t  types_cnt = 0;

    kern_return_t kr = mach_port_names(mach_task_self(),
                                        &names, &names_cnt,
                                        &types, &types_cnt);
    snap->count = 0;
    if (kr != KERN_SUCCESS) return;

    for (mach_msg_type_number_t i = 0;
         i < names_cnt && snap->count < 8192; i++)
    {
        snap->names[snap->count] = names[i];
        snap->types[snap->count] = (i < types_cnt) ? types[i] : 0;
        snap->count++;
    }

    vm_deallocate(mach_task_self(), (vm_address_t)names,
                  names_cnt * sizeof *names);
    vm_deallocate(mach_task_self(), (vm_address_t)types,
                  types_cnt * sizeof *types);
}

/* Return send rights present in 'after' but not in 'before'. */
static int diff_snapshots(const PortSnapshot *before, const PortSnapshot *after,
                           mach_port_name_t *out, int out_cap)
{
    int found = 0;
    for (int i = 0; i < after->count && found < out_cap; i++) {
        if (!(after->types[i] & MACH_PORT_TYPE_SEND)) continue;
        bool seen = false;
        for (int j = 0; j < before->count; j++) {
            if (before->names[j] == after->names[i]) { seen = true; break; }
        }
        if (!seen) out[found++] = after->names[i];
    }
    return found;
}

/* ─── prng ──────────────────────────────────────────────────────────────── */

static uint32_t g_rng = 0;

static void rng_seed(void) {
    g_rng = (uint32_t)(getpid() ^ (uint32_t)time(NULL));
    if (!g_rng) g_rng = 0x12345678;
}

static inline uint32_t rand32(void) {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}

static inline uint64_t rand64(void) {
    return ((uint64_t)rand32() << 32) | rand32();
}

static void fill_random(uint8_t *b, size_t n) {
    size_t i = 0;
    for (; i + 4 <= n; i += 4) {
        uint32_t v = rand32();
        memcpy(b + i, &v, 4);
    }
    if (i < n) {
        uint32_t v = rand32();
        memcpy(b + i, &v, n - i);
    }
}

/* ─── mutation ──────────────────────────────────────────────────────────── */

static const uint64_t kIQ[] = {
    0ULL, 1ULL, 0x7fffffffULL, 0x80000000ULL,
    0xffffffffULL, 0x7fffffffffffffffULL,
    0x8000000000000000ULL, 0xfffffffffffffffeULL, 0xffffffffffffffffULL
};

static void mutate(uint8_t *buf, size_t *sz, size_t cap) {
    if (!*sz) return;
    int r = 1 + (int)(rand32() % 6);
    for (int i = 0; i < r; i++) {
        size_t pos, n;
        switch (rand32() % 8) {
        case 0: buf[rand32() % *sz] = (uint8_t)rand32(); break;
        case 1: { pos = rand32() % *sz;
                  buf[pos] ^= (uint8_t)(1u << (rand32() % 8)); break; }
        case 2: if (*sz >= 8) {
                    pos = rand32() % (*sz - 7);
                    uint64_t v = kIQ[rand32() % 9];
                    memcpy(buf + pos, &v, 8); } break;
        case 3: if (*sz >= 4) {
                    pos = rand32() % (*sz - 3);
                    uint32_t v = (uint32_t)kIQ[rand32() % 9];
                    memcpy(buf + pos, &v, 4); } break;
        case 4: if (*sz > 1) {
                    n = 1 + rand32() % (*sz / 2);
                    pos = rand32() % (*sz - n + 1);
                    memmove(buf+pos, buf+pos+n, *sz-pos-n);
                    *sz -= n; } break;
        case 5: if (*sz < cap - 4) {
                    n = 1 + rand32() % 4;
                    n = (*sz + n > cap) ? (cap - *sz) : n;
                    pos = rand32() % (*sz + 1);
                    memmove(buf+pos+n, buf+pos, *sz-pos);
                    fill_random(buf+pos, n);
                    *sz += n; } break;
        case 6: if (*sz >= 2) {
                    n = 1 + rand32() % (*sz/2);
                    size_t src = rand32() % (*sz-n+1);
                    pos = rand32() % (*sz-n+1);
                    memmove(buf+pos, buf+src, n); } break;
        case 7: { pos = rand32() % *sz;
                  buf[pos] = (uint8_t)(buf[pos] + (rand32()%35) - 17); } break;
        }
    }
}

/* ─── webkit IPC body builder ────────────────────────────────────────────── */

static size_t wk_body(uint8_t *out, size_t cap,
                       uint8_t flags, uint16_t name, uint64_t dest,
                       const uint8_t *pl, size_t plen)
{
    size_t off = 0;
    if (off+1 > cap) return off; out[off++] = flags;
    if (off+2 > cap) return off; memcpy(out+off, &name, 2); off += 2;
    if (off+8 > cap) return off; memcpy(out+off, &dest, 8); off += 8;
    if ((flags & WK_FLAG_SYNC) && off+8 <= cap) {
        uint64_t sid = rand64() | 1ULL;
        memcpy(out+off, &sid, 8); off += 8;
    }
    if (pl && plen) {
        size_t c = plen < cap-off ? plen : cap-off;
        memcpy(out+off, pl, c); off += c;
    }
    return off;
}

/* ─── seed corpus ────────────────────────────────────────────────────────── */

typedef struct { uint8_t data[WK_MAX_BODY]; size_t sz; const char *label; } Seed;
static Seed g_seeds[N_SEEDS];

static void init_seeds(void) {
    size_t s;
    uint8_t tmp[WK_MAX_BODY];

#define SEED(i, fl, nm, pl, plen, lbl) \
    s = wk_body(tmp, sizeof tmp, fl, nm, 1ULL, pl, plen); \
    memcpy(g_seeds[i].data, tmp, s); g_seeds[i].sz = s; g_seeds[i].label = lbl

    SEED(0, 0x00, WK_MSG_LOAD_URL, NULL, 0, "async_load_url");
    SEED(1, WK_FLAG_SYNC, WK_MSG_SCALE_PAGE, NULL, 0, "sync_scale_page");

    { uint8_t pl[16]; uint64_t v=0xffffffffffffffffULL;
      memcpy(pl,&v,8); memset(pl+8,0,8);
      SEED(2, 0x00, WK_MSG_LOAD_URL, pl, 16, "overflow_uint64_max"); }

    { uint8_t raw[5]={0x00, WK_MSG_RELOAD&0xFF, WK_MSG_RELOAD>>8, 0x01, 0x00};
      memcpy(g_seeds[3].data, raw, 5); g_seeds[3].sz=5;
      g_seeds[3].label="truncated_mid_dest_id"; }

    { uint8_t pl[9]; pl[0]=0xAA; uint64_t v=0x0102030405060708ULL;
      memcpy(pl+1,&v,8);
      SEED(4, 0x00, WK_MSG_GO_BACK, pl, 9, "misaligned_payload"); }

    { uint8_t pl[16]; memset(pl,'A',16);
      SEED(5, 0x00, WK_MSG_SCALE_PAGE, pl, 16, "wrong_type_string"); }

    { uint8_t pl[8]; memset(pl,0,8);
      SEED(6, WK_FLAG_SYNC, WK_MSG_CLOSE, pl, 8, "sync_zero_request_id"); }

    SEED(7, WK_FLAG_DISPATCH|WK_FLAG_STOP_QUEUE, WK_MSG_NAVIGATE, NULL, 0,
         "dispatch_stop_queue");
#undef SEED
}

/* ─── crash state ────────────────────────────────────────────────────────── */

static sigjmp_buf            g_jmp;
static volatile sig_atomic_t g_in_fuzz = 0;
static uint8_t               g_last[MAX_MSG_TOTAL];
static size_t                g_last_sz = 0;
static uint64_t              g_crashes = 0;
static uint64_t              g_iters   = 0;

static void crash_handler(int sig, siginfo_t *, void *) {
    if (g_in_fuzz) {
        g_in_fuzz = 0;
        siglongjmp(g_jmp, sig);
    }
    struct sigaction sa = {};
    sa.sa_handler = SIG_DFL;
    sigaction(sig, &sa, nullptr);
    raise(sig);
}

static void install_handlers(void) {
    struct sigaction sa = {};
    sa.sa_sigaction = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_ONSTACK;
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS,  &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    sigaction(SIGILL,  &sa, nullptr);
}

static void save_crash(int sig, const char *out_dir, uint64_t iter) {
    char path[512];
    snprintf(path, sizeof path, "%s/crash_%llu_sig%d.bin",
             out_dir, (unsigned long long)iter, sig);
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) { perror("open"); return; }
    const uint8_t *p = g_last;
    ssize_t left = (ssize_t)g_last_sz;
    while (left > 0) { ssize_t n=write(fd,p,(size_t)left); if(n<=0) break; p+=n; left-=n; }
    close(fd);
    fprintf(stderr, "[CRASH] sig=%d iter=%llu → %s\n",
            sig, (unsigned long long)iter, path);
}

/* ─── fuzzing loop ───────────────────────────────────────────────────────── */

typedef struct {
    mach_port_name_t *ports;
    int               n_ports;
    bool              random_mode;
    uint64_t          iterations;
    const char       *out_dir;
} FuzzParams;

static void run_fuzz(const FuzzParams *p) {
    static uint8_t body[WK_MAX_BODY];
    static uint8_t msg[MAX_MSG_TOTAL];

    fprintf(stderr, "[*] Fuzzing %d WebKit IPC port(s)  mode=%s  iters=%llu\n",
            p->n_ports, p->random_mode ? "random" : "mutate",
            (unsigned long long)p->iterations);

    int seed_idx = 0;

    for (uint64_t iter = 0;
         p->iterations == 0 || iter < p->iterations;
         iter++)
    {
        mach_port_name_t tport = p->ports[rand32() % (unsigned)p->n_ports];

        /* Generate body. */
        size_t bsz;
        if (p->random_mode) {
            bsz = rand32() % (WK_MAX_BODY + 1);
            fill_random(body, bsz);
        } else {
            Seed *s = &g_seeds[seed_idx % N_SEEDS];
            seed_idx++;
            bsz = s->sz;
            memcpy(body, s->data, bsz);
            mutate(body, &bsz, WK_MAX_BODY);
        }

        /* Assemble Mach message. */
        mach_msg_id_t mid = (mach_msg_id_t)(rand32() & 0xFFFF);
        size_t hdr_sz = sizeof(mach_msg_header_t);
        size_t copy   = (bsz < sizeof(msg) - hdr_sz) ? bsz : sizeof(msg) - hdr_sz;
        size_t total  = hdr_sz + copy;

        mach_msg_header_t *hdr = (mach_msg_header_t *)msg;
        memset(hdr, 0, hdr_sz);
        hdr->msgh_bits         = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        hdr->msgh_size         = (mach_msg_size_t)total;
        hdr->msgh_remote_port  = tport;
        hdr->msgh_local_port   = MACH_PORT_NULL;
        hdr->msgh_voucher_port = MACH_PORT_NULL;
        hdr->msgh_id           = mid;

        memcpy(msg + hdr_sz, body, copy);

        memcpy(g_last, msg, total);
        g_last_sz = total;

        /* Send with crash guard. */
        int sig = sigsetjmp(g_jmp, 1);
        if (sig != 0) {
            g_crashes++;
            save_crash(sig, p->out_dir, iter);
            install_handlers();
            continue;
        }

        g_in_fuzz = 1;
        kern_return_t kr = mach_msg(
            hdr,
            MACH_SEND_MSG | MACH_SEND_TIMEOUT,
            (mach_msg_size_t)total,
            0, MACH_PORT_NULL,
            WK_SEND_TIMEOUT,
            MACH_PORT_NULL
        );
        g_in_fuzz = 0;

        if (kr == MACH_SEND_INVALID_DEST) {
            fprintf(stderr, "[!] Port 0x%x is dead — WebContent exited.\n", tport);
            g_crashes++;
            save_crash(0, p->out_dir, iter);
            break;
        }

        g_iters++;
        if (iter > 0 && iter % 5000 == 0)
            fprintf(stderr, "[*] iter=%-10llu  crashes=%llu\n",
                    (unsigned long long)iter, (unsigned long long)g_crashes);
    }

    fprintf(stderr, "[*] Done: %llu iters  %llu crashes\n",
            (unsigned long long)g_iters, (unsigned long long)g_crashes);
}

/* ─── app delegate ───────────────────────────────────────────────────────── */

@interface FuzzAppDelegate : NSObject <NSApplicationDelegate, WKNavigationDelegate>
@property (strong) WKWebView      *webView;
@property (strong) NSWindow       *window;
@property         PortSnapshot     before;
@property         bool             findPortMode;
@property         bool             fuzzMode;
@property         bool             randomMode;
@property         uint64_t         iterations;
@property (strong) NSString       *outDir;
@end

@implementation FuzzAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)note {
    (void)note;

    /* Grab snapshot before WKWebView creates any ports. */
    take_snapshot(&_before);

    /* Create minimal window + WKWebView. */
    NSRect frame = NSMakeRect(0, 0, 800, 600);
    _window = [[NSWindow alloc]
                  initWithContentRect:frame
                            styleMask:NSWindowStyleMaskTitled
                              backing:NSBackingStoreBuffered
                                defer:NO];
    [_window setTitle:@"webkit_ipc_target"];

    WKWebViewConfiguration *cfg = [[WKWebViewConfiguration alloc] init];
    _webView = [[WKWebView alloc] initWithFrame:frame configuration:cfg];
    _webView.navigationDelegate = self;
    [_window setContentView:_webView];
    [_window makeKeyAndOrderFront:nil];

    /* Load a local blank page to trigger WebContent launch. */
    [_webView loadHTMLString:@"<html><body>fuzzing target</body></html>"
                     baseURL:nil];

    /* After WKWebView settles, proceed on background queue. */
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW,
                      (int64_t)(WK_WEBVIEW_SETTLE * NSEC_PER_SEC)),
        dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
        ^{ [self afterSettle]; });
}

- (void)afterSettle {
    PortSnapshot after;
    take_snapshot(&after);

    mach_port_name_t new_ports[256];
    int n = diff_snapshots(&_before, &after, new_ports, 256);

    fprintf(stderr, "[+] WKWebView added %d new send right(s):\n", n);
    for (int i = 0; i < n; i++)
        fprintf(stderr, "    [%d] 0x%08x\n", i, new_ports[i]);

    if (n == 0) {
        fprintf(stderr, "[!] No new send rights found after WKWebView init.\n"
                        "    Try increasing WK_WEBVIEW_SETTLE or running as "
                        "non-sandboxed.\n");
        dispatch_async(dispatch_get_main_queue(), ^{ [NSApp terminate:nil]; });
        return;
    }

    if (_findPortMode) {
        /* Print port rights for use with mach_fuzzer --port-right. */
        printf("# New send rights (use with: mach_fuzzer --port-right <n> --webkit --mode mutate)\n");
        for (int i = 0; i < n; i++)
            printf("0x%08x\n", new_ports[i]);

        dispatch_async(dispatch_get_main_queue(), ^{ [NSApp terminate:nil]; });
        return;
    }

    if (_fuzzMode) {
        rng_seed();
        init_seeds();
        mkdir([_outDir UTF8String], 0755);

        static uint8_t alt_stack[65536];
        stack_t ss = { .ss_sp=alt_stack, .ss_size=sizeof alt_stack, .ss_flags=0 };
        sigaltstack(&ss, nullptr);
        install_handlers();

        FuzzParams fp = {
            .ports       = new_ports,
            .n_ports     = n,
            .random_mode = _randomMode,
            .iterations  = _iterations,
            .out_dir     = [_outDir UTF8String],
        };
        run_fuzz(&fp);
    }

    dispatch_async(dispatch_get_main_queue(), ^{ [NSApp terminate:nil]; });
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)app {
    (void)app; return YES;
}

@end

/* ─── main ───────────────────────────────────────────────────────────────── */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "  --find-port              Create WKWebView, print new send rights, exit\n"
        "  --fuzz                   In-process WebKit IPC fuzzing (default)\n"
        "  --mode random|mutate     Body generation (default: mutate)\n"
        "  --iterations <n>         0 = run forever (default: 0)\n"
        "  --out <dir>              Crash output directory (default: findings/)\n"
        "  --help\n"
        "\n"
        "Workflow:\n"
        "  # Option A — in-process (recommended for UIProcess IPC)\n"
        "  ./webkit_ipc_target --fuzz --mode mutate --out crashes/\n"
        "\n"
        "  # Option B — pass discovered port rights to the generic fuzzer\n"
        "  ./webkit_ipc_target --find-port\n"
        "  ./mach_fuzzer --port-right 0x1207 --webkit --mode mutate\n"
        "\n",
        prog);
}

int main(int argc, char *argv[]) {
    static const struct option opts[] = {
        { "find-port",   no_argument,       NULL, 'f' },
        { "fuzz",        no_argument,       NULL, 'F' },
        { "mode",        required_argument, NULL, 'm' },
        { "iterations",  required_argument, NULL, 'i' },
        { "out",         required_argument, NULL, 'o' },
        { "help",        no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    bool        find_port  = false;
    bool        fuzz       = true;   /* default action */
    bool        random_md  = false;
    uint64_t    iterations = 0;
    const char *out_dir    = "findings";

    int opt;
    while ((opt = getopt_long(argc, argv, "fFm:i:o:h", opts, NULL)) != -1) {
        switch (opt) {
        case 'f': find_port = true; fuzz = false; break;
        case 'F': fuzz = true;  break;
        case 'm':
            if      (strcmp(optarg, "random") == 0) random_md = true;
            else if (strcmp(optarg, "mutate") == 0) random_md = false;
            else { fprintf(stderr, "[!] Unknown mode: %s\n", optarg); return 1; }
            break;
        case 'i': iterations = strtoull(optarg, NULL, 0); break;
        case 'o': out_dir = optarg; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];

        FuzzAppDelegate *delegate = [[FuzzAppDelegate alloc] init];
        delegate.findPortMode = find_port;
        delegate.fuzzMode     = fuzz;
        delegate.randomMode   = random_md;
        delegate.iterations   = iterations;
        delegate.outDir       = [NSString stringWithUTF8String:out_dir];

        [app setDelegate:delegate];
        [app run];
    }

    return (int)(g_crashes > 0 ? 2 : 0);
}
