/* Read-only userland TCP/UDP flows exported with the BSD PCB snapshot.
 * API/format basis: Apple's XNU bsd/netinet/in_pcblist.c get_pcblist_n,
 * bsd/sys/socketvar.h xsocket_n, bsd/netinet/in_pcb.h xinpcb_n and
 * bsd/net/ntstat.c nstat_userland_list_snapshot. No implementation copied.
 * https://github.com/apple-oss-distributions/xnu
 * These private, length-tagged wire prefixes are absent from the public SDK.
 * Keep their decoding here, outside Rust's bridge ABI; reject truncated or
 * contradictory records. libproc identities still use SDK structures.
 *
 * Every row names its own tuple, so a row that cannot be verified (another
 * UID, a vanished or reused PID, a changed delegate) is dropped alone and
 * never raises a source-wide flag. Only an unusable snapshot, the budget or
 * cancellation make the whole pass incomplete, and then nothing is published.
 */
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "flow_attribution.h"

#define MAX_SNAPSHOT_BYTES (16u * 1024u * 1024u)
#define RECORD_SOCKET 1u
#define RECORD_INPCB 16u
#define RECORD_TCP 32u
#define RECORD_BASE_MASK 31u

#pragma pack(push, 4)
struct socket_wire {
    uint32_t length, kind;
    uint64_t socket_id;
    int16_t type;
    uint32_t options;
    int16_t linger, state;
    uint64_t pcb;
    int32_t protocol, family;
    int16_t qlen, incqlen, qlimit, timeout;
    uint16_t error;
    int32_t pgid;
    uint32_t oobmark, uid;
    int32_t owner_pid, effective_pid;
    uint64_t generation;
    uint32_t flags, flags1;
    int32_t usecount, retaincount;
    uint32_t filter_flags;
};
struct pcb_wire {
    uint32_t length, kind;
    uint64_t pcb;
    uint16_t remote_port, local_port;
    uint64_t protocol_pcb, generation;
    int32_t flags;
    uint32_t flow;
    uint8_t family_flags, ttl, protocol, reserved_address;
    uint8_t remote[16], local[16];
    uint8_t tos;
    struct { uint8_t hlim; int32_t checksum; uint16_t ifindex; int16_t hops; } v6;
    uint32_t flowhash, flags2;
};
#pragma pack(pop)
_Static_assert(sizeof(struct socket_wire) == 104, "socket wire prefix size");
_Static_assert(offsetof(struct socket_wire, owner_pid) == 68, "socket owner offset");
_Static_assert(offsetof(struct socket_wire, effective_pid) == 72, "socket delegate offset");
_Static_assert(sizeof(struct pcb_wire) == 104, "PCB wire prefix size");
_Static_assert(offsetof(struct pcb_wire, remote) == 48, "PCB endpoint offset");
_Static_assert(offsetof(struct pcb_wire, v6.ifindex) == 92, "PCB interface offset");

static int unavailable(struct egrio_report *report) {
    report->flags |= SYSCALL_ERROR;
    report->syscall_errors++;
    return -1;
}

int egrio_parse_userland_snapshot(const uint8_t *bytes, size_t length, uint32_t protocol,
    const struct egrio_query *queries, uint32_t query_count,
    struct egrio_userland_flow *flows, uint32_t capacity, uint32_t *count,
    struct egrio_report *report, uint64_t deadline, cancel_fn cancelled, void *context) {
    if (!report) return -1;
    if (!count) return unavailable(report);
    *count = 0;
    if (!bytes || !queries || !flows || query_count == 0 || query_count > EGRIO_MAX_QUERIES ||
        capacity == 0 || capacity > EGRIO_MAX_CANDIDATES ||
        length < 2 * sizeof(struct xinpgen) || length > MAX_SNAPSHOT_BYTES ||
        (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)) return unavailable(report);
    struct xinpgen header;
    memcpy(&header, bytes, sizeof(header));
    if (header.xig_len != sizeof(header)) return unavailable(report);
    size_t offset = (sizeof(header) + 7u) & ~(size_t)7u;
    uint32_t seen = 0;
    const uint32_t wanted = RECORD_BASE_MASK | (protocol == IPPROTO_TCP ? RECORD_TCP : 0);
    struct socket_wire socket = {0};
    struct pcb_wire pcb = {0};
    while (offset + 8 <= length) {
        if (egrio_flow_stop(report, deadline, cancelled, context)) return -1;
        uint32_t size, kind;
        memcpy(&size, bytes + offset, 4);
        memcpy(&kind, bytes + offset + 4, 4);
        if (size == sizeof(struct xinpgen)) {
            if (seen != 0 || offset + size != length) return unavailable(report);
            return 0;
        }
        if (size < 8 || size > length - offset) return unavailable(report);
        size_t step = ((size_t)size + 7u) & ~(size_t)7u;
        if (step > length - offset) return unavailable(report);
        if (kind && (kind & (kind - 1u)) == 0 && (kind & wanted)) {
            if (seen & kind) return unavailable(report);
            if (kind == RECORD_SOCKET) {
                if (size < sizeof(socket)) return unavailable(report);
                memcpy(&socket, bytes + offset, sizeof(socket));
            } else if (kind == RECORD_INPCB) {
                if (size < sizeof(pcb)) return unavailable(report);
                memcpy(&pcb, bytes + offset, sizeof(pcb));
            }
            seen |= kind;
        }
        offset += step;
        if (seen != wanted) continue;
        seen = 0;
        // nstat's userland rows have no BSD socket, descriptor or PCB identity.
        // Ordinary BSD rows remain owned and shared-checked by libproc.
        if (socket.family != AF_UNSPEC || socket.socket_id != 0 || socket.pcb != 0 ||
            pcb.pcb != 0 || pcb.generation != 0 || socket.protocol != (int32_t)protocol ||
            socket.owner_pid <= 0 || socket.effective_pid < 0 || pcb.remote_port == 0) continue;
        uint16_t port = ntohs(pcb.local_port);
        if (!egrio_flow_requested(queries, query_count, protocol, port)) continue;
        if (*count == capacity) {
            report->flags |= LIMIT_CANDIDATES;
            return -1;
        }
        struct egrio_userland_flow row = {0};
        row.protocol = protocol;
        row.owner_pid = (uint32_t)socket.owner_pid;
        row.effective_pid = socket.effective_pid ? (uint32_t)socket.effective_pid : row.owner_pid;
        row.local.port = port;
        row.remote.port = ntohs(pcb.remote_port);
        if ((pcb.family_flags & (INP_IPV4 | INP_IPV6)) == INP_IPV4) {
            row.local.family = row.remote.family = 4;
            memcpy(row.local.address, pcb.local + 12, 4);
            memcpy(row.remote.address, pcb.remote + 12, 4);
        } else if (pcb.family_flags & INP_IPV6) {
            row.local.family = row.remote.family = 6;
            row.local.scope_id = row.remote.scope_id = pcb.v6.ifindex;
            memcpy(row.local.address, pcb.local, 16);
            memcpy(row.remote.address, pcb.remote, 16);
        } else return unavailable(report);
        flows[(*count)++] = row;
        report->userland_flows++;
    }
    return unavailable(report); // A complete snapshot always has its trailer.
}

static int read_snapshot(uint32_t protocol, const struct egrio_query *queries, uint32_t query_count,
    struct egrio_userland_flow *rows, uint32_t *count, struct egrio_report *report,
    uint64_t deadline, cancel_fn cancelled, void *context) {
    const char *name = protocol == IPPROTO_TCP ? "net.inet.tcp.pcblist_n" : "net.inet.udp.pcblist_n";
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (egrio_flow_stop(report, deadline, cancelled, context)) return -1;
        size_t size = 0;
        if (sysctlbyname(name, NULL, &size, NULL, 0) != 0) return unavailable(report);
        if (size > MAX_SNAPSHOT_BYTES) { report->flags |= LIMIT_CANDIDATES; return -1; }
        if (size < 2 * sizeof(struct xinpgen)) return unavailable(report);
        uint8_t *bytes = malloc(size);
        if (!bytes) return unavailable(report);
        size_t used = size;
        int result = sysctlbyname(name, bytes, &used, NULL, 0);
        int error = errno;
        if (result == 0 && used <= size) {
            result = egrio_parse_userland_snapshot(bytes, used, protocol, queries, query_count,
                rows, EGRIO_MAX_CANDIDATES, count, report, deadline, cancelled, context);
            free(bytes);
            return result;
        }
        free(bytes);
        if (error != ENOMEM) break;
    }
    return unavailable(report);
}

/* A row's own failure is counted for diagnostics only; see the file comment. */
static void row_failure(struct egrio_report *report) {
    if (errno == EPERM || errno == EACCES) report->permission_denied++;
    else if (errno == ESRCH) report->raced++;
    else report->syscall_errors++;
}
static int row_identity(pid_t pid, struct proc_bsdinfo *info, struct egrio_report *report) {
    memset(info, 0, sizeof(*info));
    errno = 0;
    report->pids_scanned++;
    if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info, (int)sizeof(*info)) != (int)sizeof(*info)) {
        row_failure(report);
        return 0;
    }
    if (info->pbi_pid != (uint32_t)pid) { report->raced++; return 0; }
    // The table is system-wide; publication is still restricted to our UID.
    if (info->pbi_uid != geteuid()) { report->permission_denied++; return 0; }
    return 1;
}
static int row_path(pid_t pid, char path[EGRIO_PATH_CAP], struct egrio_report *report) {
    if (egrio_flow_path(pid, path) == 1) return 1;
    row_failure(report);
    return 0;
}
static int same_start(const struct proc_bsdinfo *info, uint64_t sec, uint64_t usec) {
    return info->pbi_start_tvsec == sec && info->pbi_start_tvusec == usec;
}
static int same_endpoints(const struct egrio_userland_flow *a, const struct egrio_userland_flow *b) {
    return memcmp(&a->local, &b->local, sizeof(a->local)) == 0 &&
        memcmp(&a->remote, &b->remote, sizeof(a->remote)) == 0;
}
static int same_tuple(const struct egrio_userland_flow *row, const struct egrio_candidate *candidate) {
    return row->protocol == candidate->protocol &&
        memcmp(&row->local, &candidate->local, sizeof(row->local)) == 0 &&
        memcmp(&row->remote, &candidate->remote, sizeof(row->remote)) == 0;
}
static int unique_row(const struct egrio_userland_flow *rows, uint32_t count, const struct egrio_userland_flow *row) {
    uint32_t matches = 0;
    for (uint32_t n = 0; n < count; ++n) if (same_endpoints(&rows[n], row)) matches++;
    return matches == 1;
}

struct start_stamp { uint64_t sec, usec; };

/* A second snapshot must still name the same owner and delegate, and neither
 * PID may have been reused or re-executed since the first observation. */
static int still_owned(const struct egrio_candidate *candidate, struct start_stamp owner_start,
    const struct egrio_userland_flow *rows, uint32_t count, struct egrio_report *report) {
    uint32_t matches = 0;
    int same_owners = 0;
    for (uint32_t n = 0; n < count; ++n) if (same_tuple(&rows[n], candidate)) {
        matches++;
        same_owners = rows[n].owner_pid == candidate->owner_pid && rows[n].effective_pid == candidate->pid;
    }
    if (matches != 1 || !same_owners) { report->raced++; return 0; }
    struct proc_bsdinfo owner, effective;
    char path[EGRIO_PATH_CAP];
    if (!row_identity((pid_t)candidate->owner_pid, &owner, report) ||
        !row_identity((pid_t)candidate->pid, &effective, report) ||
        !row_path((pid_t)candidate->pid, path, report)) return 0;
    if (!same_start(&owner, owner_start.sec, owner_start.usec) ||
        !same_start(&effective, candidate->start_sec, candidate->start_usec) ||
        strcmp((const char *)candidate->executable, path) != 0) { report->raced++; return 0; }
    return 1;
}

/* One protocol's two-snapshot pass. Returns -1 only after setting a flag. */
static int scan_protocol(uint32_t protocol, const struct egrio_query *queries, uint32_t query_count,
    struct egrio_userland_flow *first, struct egrio_userland_flow *second, struct start_stamp *owners,
    struct egrio_candidate *candidates, uint32_t capacity, struct egrio_report *report,
    uint64_t deadline, cancel_fn cancelled, void *context) {
    uint32_t first_count = 0, second_count = 0;
    if (read_snapshot(protocol, queries, query_count, first, &first_count, report, deadline, cancelled, context) != 0) return -1;
    const uint32_t base = report->candidate_count;
    for (uint32_t i = 0; i < first_count; ++i) {
        if (egrio_flow_stop(report, deadline, cancelled, context)) return -1;
        const struct egrio_userland_flow *row = &first[i];
        if (!unique_row(first, first_count, row)) { report->raced++; continue; }
        if (report->candidate_count == capacity) { report->flags |= LIMIT_CANDIDATES; return -1; }
        struct proc_bsdinfo owner, effective;
        if (!row_identity((pid_t)row->owner_pid, &owner, report)) continue;
        if (row->effective_pid == row->owner_pid) effective = owner;
        else if (!row_identity((pid_t)row->effective_pid, &effective, report)) continue;
        struct egrio_candidate *candidate = &candidates[report->candidate_count];
        memset(candidate, 0, sizeof(*candidate));
        if (!row_path((pid_t)row->effective_pid, (char *)candidate->executable, report)) continue;
        candidate->pid = row->effective_pid;
        candidate->owner_pid = row->owner_pid;
        candidate->protocol = protocol;
        candidate->flags = USERLAND_FLOW;
        candidate->local = row->local;
        candidate->remote = row->remote;
        candidate->start_sec = effective.pbi_start_tvsec;
        candidate->start_usec = effective.pbi_start_tvusec;
        owners[report->candidate_count++] = (struct start_stamp){owner.pbi_start_tvsec, owner.pbi_start_tvusec};
    }
    if (report->candidate_count == base) return 0;
    if (read_snapshot(protocol, queries, query_count, second, &second_count, report, deadline, cancelled, context) != 0) return -1;
    uint32_t kept = base;
    for (uint32_t i = base; i < report->candidate_count; ++i) {
        if (egrio_flow_stop(report, deadline, cancelled, context)) return -1;
        if (!still_owned(&candidates[i], owners[i], second, second_count, report)) continue;
        if (kept != i) candidates[kept] = candidates[i];
        kept++;
    }
    report->candidate_count = kept;
    return 0;
}

static int queried(const struct egrio_query *queries, uint32_t count, uint32_t protocol) {
    for (uint32_t i = 0; i < count; ++i) if (queries[i].protocol == protocol) return 1;
    return 0;
}

int egrio_macos_scan_userland_flows(const struct egrio_query *queries, uint32_t query_count, uint64_t budget_ns,
    struct egrio_candidate *candidates, uint32_t capacity, struct egrio_report *report,
    cancel_fn cancelled, void *context) {
    if (!report) return -1;
    uint64_t started = egrio_flow_clock();
    if (!egrio_flow_begin(report, queries, query_count, candidates, capacity)) return -1;
    uint64_t deadline = egrio_flow_deadline(started, budget_ns);
    struct egrio_userland_flow *first = calloc(EGRIO_MAX_CANDIDATES, sizeof(*first));
    struct egrio_userland_flow *second = calloc(EGRIO_MAX_CANDIDATES, sizeof(*second));
    struct start_stamp *owners = calloc(capacity, sizeof(*owners));
    if (!first || !second || !owners) unavailable(report);
    static const uint32_t protocols[] = {IPPROTO_TCP, IPPROTO_UDP};
    for (size_t p = 0; p < 2 && !report->flags; ++p) {
        if (!queried(queries, query_count, protocols[p])) continue;
        scan_protocol(protocols[p], queries, query_count, first, second, owners,
            candidates, capacity, report, deadline, cancelled, context);
    }
    free(owners);
    free(second);
    free(first);
    // A partial observation is never published; Rust keeps socket owners alone.
    if (report->flags) report->candidate_count = 0;
    report->elapsed_ns = egrio_flow_clock() - started;
    return report->flags ? -1 : 0;
}
