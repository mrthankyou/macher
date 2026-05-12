# mach_fuzzer — Generalized Mach IPC Fuzzer for macOS

Mutation-based fuzzer for Mach service ports on macOS 15.x (Apple Silicon).
Supports any bootstrap-registered service as well as raw port rights, with a
structured WebKit IPC mode layered on top.

## Architecture

```
fuzzers/mach_ipc/
├── mach_fuzzer.c          # Generic fuzzer — pure C, no frameworks
├── webkit_ipc_target.mm   # ObjC++ harness — embeds WKWebView, fuzzes in-process
├── build.sh               # Build both binaries
└── findings/              # Crash output (auto-created)
```

### mach_fuzzer.c

Standalone CLI.  No ObjC, no framework dependencies beyond the system SDK.

```
Port discovery
  bootstrap_look_up()    ← --port com.apple.coreaudiod
  raw port name          ← --port-right 0x1207
  mach_port_names()      ← --list-ports  (enumerate own task's rights)
  bootstrap_info()       ← --list-services

Message generation
  random mode            fully random body bytes
  mutate mode            AFL-style havoc on a seed buffer
    ops: byte set, bit flip, interesting uint{8,16,32,64},
         block delete, block copy, byte insert, arithmetic add/sub

WebKit mode (--webkit)
  body format: [flags:1][name:2][dest_id:8][sync_id?:8][payload...]
  built-in seed corpus of 8 structurally valid messages
  msgh_id fuzzed as 16-bit value (WebKit ignores it; type is in body)

Crash detection
  In-process:  sigsetjmp/siglongjmp guards each mach_msg() call
               catches SIGSEGV, SIGBUS, SIGABRT, SIGILL
  Out-of-process: MACH_SEND_INVALID_DEST return → port died
                  optional --pid monitor via kill(pid, 0)
  On crash: raw message bytes archived to findings/
```

### webkit_ipc_target.mm

ObjC++ harness that IS the UIProcess.  Creates a WKWebView (spawning
WebContent), diffs the task's port namespace before/after to find the new
send rights, then runs the fuzzing loop against those ports.

Two modes:
- `--fuzz`       in-process fuzzing (signal-handler crash detection)
- `--find-port`  print newly-acquired send rights and exit; feed into
                 `mach_fuzzer --port-right` for external fuzzing

## Build

```sh
./build.sh
```

Requirements: Xcode Command Line Tools, macOS 15.x, Apple Silicon.

The two binaries compile independently; `mach_fuzzer` has zero framework
dependencies and can be cross-compiled for any arm64 Mac with plain `clang`.

## Usage

### Enumerate reachable services

```sh
./mach_fuzzer --list-services
./mach_fuzzer --list-ports
```

### Fuzz a bootstrap service — random mode

```sh
./mach_fuzzer --port com.apple.coreaudiod --mode random
./mach_fuzzer --port com.apple.windowserver.active --mode random --max-size 512
./mach_fuzzer --port com.apple.tccd --mode random --iterations 500000
```

### Fuzz with a captured seed

```sh
# Capture a real message with lldb, save to seed.bin, then:
./mach_fuzzer --port com.apple.coreaudiod --mode mutate --seed seed.bin
```

### WebKit UIProcess IPC — in-process (recommended)

```sh
./webkit_ipc_target --fuzz --mode mutate --out findings/ --iterations 0
```

### WebKit — discover port rights, fuzz externally

```sh
./webkit_ipc_target --find-port
# → prints e.g. 0x00001207

./mach_fuzzer --port-right 0x00001207 --webkit --mode mutate
```

### Monitor an out-of-process target

```sh
# Terminal 1: start target
some_service &
echo $!   # → 1234

# Terminal 2: fuzz
./mach_fuzzer --port com.example.service --pid 1234 --mode random
```

## WebKit IPC Details

### Message body format

| Offset | Size | Field         | Notes                                  |
|--------|------|---------------|----------------------------------------|
| 0      | 1    | MessageFlags  | bitfield: 0x01=sync 0x02=dispatch      |
| 1      | 2    | MessageName   | `enum class MessageName : uint16_t`    |
| 3      | 8    | DestinationID | WebPage / WebView instance (uint64_t)  |
| 11     | 8    | SyncRequestID | only present when FLAG_SYNC is set     |
| 11/19  | var  | payload       | length-prefixed args, no type tags     |

`msgh_id` in the Mach header is not used for dispatch in modern WebKit; the
body's MessageName drives routing.

### Known MessageName values (approximate, webkit.org open source)

| Value  | Name               | Sync? |
|--------|--------------------|-------|
| 0x0001 | LoadURL            | no    |
| 0x0002 | GoBack             | no    |
| 0x0003 | GoForward          | no    |
| 0x0004 | Reload             | no    |
| 0x0005 | StopLoading        | no    |
| 0x0010 | ScalePage          | no    |
| 0x0020 | SetInitialFocus    | no    |
| 0x0030 | Navigate           | no    |
| 0x00FF | Close              | no    |

These are illustrative; the exact enum values change between WebKit versions.
Use LLDB to intercept `IPC::Connection::dispatchMessage` and log `msgh_id` /
body bytes from live traffic.

### Seed corpus

The built-in seed corpus covers eight vulnerability patterns:

| # | Label                    | Pattern                                |
|---|--------------------------|----------------------------------------|
| 0 | async_load_url           | Valid async message, empty payload     |
| 1 | sync_scale_page          | Valid sync message, empty payload      |
| 2 | overflow_uint64_max      | uint64_t length = UINT64_MAX           |
| 3 | truncated_mid_dest_id    | Stops mid-DestinationID field          |
| 4 | misaligned_payload       | 1-byte prefix shifts all fields by 1  |
| 5 | wrong_type_string        | String bytes where uint64_t expected  |
| 6 | sync_zero_request_id     | SyncRequestID = 0 (degenerate)         |
| 7 | dispatch_stop_queue      | DISPATCH | STOP_QUEUE flag combo       |

## Crash triage

Crashes are archived as `findings/crash_<iter>_sig<N>.bin`.  The file contains
the raw Mach message (header + body) that triggered the signal.

Reproduce a crash:

```sh
# Re-send the exact crashing message via --seed + 0 mutations:
./mach_fuzzer --port com.apple.coreaudiod \
              --mode mutate --seed findings/crash_1234_sig11.bin \
              --iterations 1
```

Attach LLDB before sending:

```sh
lldb -- ./mach_fuzzer --port com.apple.coreaudiod \
                      --mode mutate \
                      --seed findings/crash_1234_sig11.bin \
                      --iterations 1
(lldb) run
```

## Constraints and non-goals

- **No SIP bypass**: `task_for_pid` on system processes is not used.  Only
  ports reachable via `bootstrap_look_up` or already in the task namespace
  are targeted.
- **No IOKit**: separate attack surface; use `iofuzz` or similar.
- **No XPC**: Mach layer only.  XPC services expose a Mach port via bootstrap;
  use `--port` with the XPC service name if you want to fuzz at the Mach level.
- **No fork server / AFL instrumentation**: exec-mode only.

## High-value targets (bootstrap-registered)

```
com.apple.windowserver.active    WindowServer — graphics/compositor
com.apple.coreaudiod             CoreAudio daemon
com.apple.tccd                   TCC privacy daemon
com.apple.SecurityServer         keychain / credentials
com.apple.coreservices.quarantine quarantine / Gatekeeper
```
 