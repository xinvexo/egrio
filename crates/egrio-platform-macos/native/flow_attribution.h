#ifndef EGRIO_FLOW_ATTRIBUTION_H
#define EGRIO_FLOW_ATTRIBUTION_H
/* Rust bridge ABI shared by the two flow-ownership sources: socket_scan.c
 * (libproc descriptors) and userland_flow_scan.c (nstat rows exported with
 * the PCB snapshot). Each source fills its own candidates and report. */
#include <libproc.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#define EGRIO_MAX_QUERIES 256u
#define EGRIO_MAX_PIDS 4096u
#define EGRIO_MAX_FDS 65536u
#define EGRIO_MAX_CANDIDATES 2048u
#define EGRIO_PATH_CAP 4096u
#define EGRIO_MAX_BUDGET_NS UINT64_C(100000000)
/* Report flags: any flag makes that source's observation incomplete. */
#define LIMIT_PIDS 1u
#define LIMIT_FDS 2u
#define LIMIT_CANDIDATES 4u
#define TIMED_OUT 8u
#define CANCELLED 16u
#define PERMISSION 32u
#define RACED 64u
#define SYSCALL_ERROR 128u
/* Candidate flags. */
#define REUSE_PORT 1u
#define REUSE_ADDR 2u
#define SHARED 4u
#define DUAL_STACK 8u
#define USERLAND_FLOW 16u

struct egrio_query { uint32_t protocol; uint16_t local_port; uint16_t reserved; };
struct egrio_endpoint { uint8_t address[16]; uint32_t family; uint32_t scope_id; uint16_t port; uint16_t reserved; };
struct egrio_candidate {
    uint64_t start_sec, start_usec, socket_id, socket_generation;
    uint32_t pid, fd, protocol, flags, tcp_state, owner_pid;
    struct egrio_endpoint local, remote;
    uint8_t executable[EGRIO_PATH_CAP];
};
struct egrio_report {
    uint64_t elapsed_ns;
    uint32_t flags, pids_scanned, fds_scanned, permission_denied, raced;
    uint32_t candidate_count, syscall_errors, userland_flows;
};
struct egrio_userland_flow {
    uint32_t protocol, owner_pid, effective_pid;
    struct egrio_endpoint local, remote;
};
typedef int (*cancel_fn)(void *);
_Static_assert(PROC_PIDPATHINFO_MAXSIZE <= EGRIO_PATH_CAP, "SDK path limit exceeds bridge capacity");
_Static_assert(sizeof(struct egrio_endpoint) == 28, "unexpected bridge endpoint ABI");
_Static_assert(sizeof(struct egrio_candidate) == 4208, "unexpected bridge candidate ABI");
_Static_assert(sizeof(struct egrio_report) == 40, "unexpected bridge report ABI");

/* Helpers shared by both sources (flow_attribution.c). */
uint64_t egrio_flow_clock(void);
uint64_t egrio_flow_deadline(uint64_t started, uint64_t budget_ns);
int egrio_flow_begin(struct egrio_report *, const struct egrio_query *, uint32_t,
    const struct egrio_candidate *, uint32_t);
int egrio_flow_stop(struct egrio_report *, uint64_t, cancel_fn, void *);
int egrio_flow_requested(const struct egrio_query *, uint32_t, uint32_t, uint16_t);
int egrio_flow_path(pid_t, char[EGRIO_PATH_CAP]);

/* Bridge entry points. */
size_t egrio_macos_flow_candidate_size(void);
int egrio_macos_scan_sockets(const struct egrio_query *, uint32_t, uint64_t,
    struct egrio_candidate *, uint32_t, struct egrio_report *, cancel_fn, void *);
int egrio_macos_scan_userland_flows(const struct egrio_query *, uint32_t, uint64_t,
    struct egrio_candidate *, uint32_t, struct egrio_report *, cancel_fn, void *);
int egrio_parse_userland_snapshot(const uint8_t *, size_t, uint32_t,
    const struct egrio_query *, uint32_t, struct egrio_userland_flow *, uint32_t,
    uint32_t *, struct egrio_report *, uint64_t, cancel_fn, void *);
#endif
