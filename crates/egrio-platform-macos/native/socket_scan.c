/* libproc socket ownership: same-UID processes and their TCP/UDP descriptors.
 * Compile against SDK libproc.h/sys/proc_info.h; never reproduce their ABI.
 * Official behavior reference (no implementation copied): Apple XNU
 * bsd/kern/proc_info.c: proc_security_policy, proc_pidfdinfo, fill_fileinfo;
 * bsd/kern/socket_info.c: fill_socketinfo (opaque IDs, network-order
 * inpcb ports, address unions and generation count);
 * libsyscall/wrappers/libproc/libproc.c. Sources:
 * https://github.com/apple-oss-distributions/xnu
 */
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "flow_attribution.h"

static void observation_error(struct egrio_report *report, int candidate_was_observed) {
    if (errno == EPERM || errno == EACCES) { report->flags |= PERMISSION; report->permission_denied++; }
    else if (errno == ESRCH || errno == EBADF || errno == ENOENT) {
        /* An unobserved descriptor that vanished is not a live alternative
         * owner. Once a candidate exists, loss invalidates that observation. */
        if (candidate_was_observed) report->flags |= RACED;
        report->raced++;
    }
    else { report->flags |= SYSCALL_ERROR; report->syscall_errors++; }
}
static int process_identity(pid_t pid, struct proc_bsdinfo *identity, struct egrio_report *report, int candidate_was_observed) {
    memset(identity, 0, sizeof(*identity)); errno = 0;
    int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, identity, (int)sizeof(*identity));
    if (count != (int)sizeof(*identity)) { observation_error(report,candidate_was_observed); return 0; }
    if (identity->pbi_pid != (uint32_t)pid || identity->pbi_uid != geteuid()) {
        report->flags |= RACED; report->raced++; return 0;
    }
    return 1;
}
static int process_path(pid_t pid, char path[EGRIO_PATH_CAP], struct egrio_report *report) {
    int result = egrio_flow_path(pid, path);
    if (result == 0) observation_error(report,1);
    else if (result < 0) { report->flags |= SYSCALL_ERROR; report->syscall_errors++; }
    return result == 1;
}
static int socket_candidate(pid_t pid, int fd, struct egrio_candidate *candidate, struct egrio_report *report, int candidate_was_observed) {
    struct socket_fdinfo info; memset(&info, 0, sizeof(info)); errno = 0;
    int count = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, (int)sizeof(info));
    if (count != (int)sizeof(info)) { observation_error(report,candidate_was_observed); return -1; }
    const struct socket_info *socket = &info.psi;
    if (socket->soi_family != AF_INET && socket->soi_family != AF_INET6) return 0;
    const struct in_sockinfo *inet;
    if (socket->soi_kind == SOCKINFO_TCP && socket->soi_protocol == IPPROTO_TCP) {
        inet = &socket->soi_proto.pri_tcp.tcpsi_ini;
    } else if (socket->soi_kind == SOCKINFO_IN && socket->soi_protocol == IPPROTO_UDP) {
        inet = &socket->soi_proto.pri_in;
    } else return 0;
    memset(candidate, 0, sizeof(*candidate));
    candidate->pid = candidate->owner_pid = (uint32_t)pid; candidate->fd = (uint32_t)fd;
    candidate->protocol = (uint32_t)socket->soi_protocol;
    candidate->socket_id = socket->soi_so;
    candidate->socket_generation = inet->insi_gencnt;
    candidate->local.port = ntohs((uint16_t)inet->insi_lport);
    candidate->remote.port = ntohs((uint16_t)inet->insi_fport);
    if (socket->soi_options & SO_REUSEPORT) candidate->flags |= REUSE_PORT;
    if (socket->soi_options & SO_REUSEADDR) candidate->flags |= REUSE_ADDR;
    if (info.pfi.fi_status & PROC_FP_SHARED) candidate->flags |= SHARED;
    if (socket->soi_kind == SOCKINFO_TCP) candidate->tcp_state = (uint32_t)socket->soi_proto.pri_tcp.tcpsi_state;
    if ((inet->insi_vflag & (INI_IPV4|INI_IPV6)) == (INI_IPV4|INI_IPV6)) candidate->flags |= DUAL_STACK;
    if ((inet->insi_vflag & INI_IPV4) && !(inet->insi_vflag & INI_IPV6)) {
        candidate->local.family = candidate->remote.family = 4;
        memcpy(candidate->local.address, &inet->insi_laddr.ina_46.i46a_addr4, 4);
        memcpy(candidate->remote.address, &inet->insi_faddr.ina_46.i46a_addr4, 4);
    } else if (inet->insi_vflag & INI_IPV6) {
        candidate->local.family = candidate->remote.family = 6;
        memcpy(candidate->local.address, &inet->insi_laddr.ina_6, 16);
        memcpy(candidate->remote.address, &inet->insi_faddr.ina_6, 16);
        candidate->local.scope_id = candidate->remote.scope_id = inet->insi_v6.in6_ifindex;
    } else return 0;
    return 1;
}
static int same_socket(const struct egrio_candidate *a, const struct egrio_candidate *b) {
    return a->socket_id == b->socket_id && a->socket_generation == b->socket_generation &&
        a->protocol == b->protocol && a->flags == b->flags && a->tcp_state == b->tcp_state &&
        memcmp(&a->local, &b->local, sizeof(a->local)) == 0 && memcmp(&a->remote, &b->remote, sizeof(a->remote)) == 0;
}

int egrio_macos_scan_sockets(const struct egrio_query *queries, uint32_t query_count, uint64_t budget_ns,
    struct egrio_candidate *candidates, uint32_t capacity, struct egrio_report *report,
    cancel_fn cancelled, void *context) {
    if (!report) return -1;
    uint64_t started = egrio_flow_clock();
    if (!egrio_flow_begin(report, queries, query_count, candidates, capacity)) return -1;
    uint64_t deadline = egrio_flow_deadline(started, budget_ns);
    int *pids = NULL;
    struct proc_fdinfo *fds = NULL;
    if (egrio_flow_stop(report, deadline, cancelled, context)) goto done;
    pids = calloc(EGRIO_MAX_PIDS, sizeof(*pids));
    fds = calloc(EGRIO_MAX_FDS, sizeof(*fds));
    if (!pids || !fds) { report->flags |= SYSCALL_ERROR; report->syscall_errors++; goto done; }
    errno = 0;
    int bytes = proc_listpids(PROC_UID_ONLY, (uint32_t)geteuid(), pids, (int)(EGRIO_MAX_PIDS*sizeof(*pids)));
    if (bytes <= 0 || bytes % (int)sizeof(*pids) != 0) { observation_error(report,1); goto done; }
    if ((uint32_t)bytes >= EGRIO_MAX_PIDS*sizeof(*pids)) report->flags |= LIMIT_PIDS;
    uint32_t pid_count = (uint32_t)bytes/(uint32_t)sizeof(*pids);
    if (pid_count > EGRIO_MAX_PIDS) pid_count=EGRIO_MAX_PIDS;
    /* Most processes hold no requested socket, so each costs one descriptor
     * listing plus one call per socket: the listing takes the remaining
     * capacity at once (the kernel copies only the open descriptors, so no
     * size query first), and the process identity is read only once a
     * candidate exists, then again after the candidates are re-verified. */
    for (uint32_t p=0; p<pid_count; ++p) {
        if (egrio_flow_stop(report, deadline, cancelled, context)) break;
        pid_t pid = pids[p]; if (pid <= 0) continue;
        struct proc_bsdinfo before, after;
        report->pids_scanned++;
        uint32_t remaining = EGRIO_MAX_FDS - report->fds_scanned;
        if (!remaining) { report->flags |= LIMIT_FDS; break; }
        errno = 0;
        int returned = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, (int)(remaining*sizeof(*fds)));
        if (returned < 0 || (returned == 0 && errno != 0) || returned % (int)sizeof(*fds) != 0 ||
            (uint32_t)returned > remaining*sizeof(*fds)) {
            observation_error(report,0); continue;
        }
        uint32_t count = (uint32_t)returned/(uint32_t)sizeof(*fds);
        if (count >= remaining) report->flags |= LIMIT_FDS;
        uint32_t base = report->candidate_count;
        for (uint32_t f=0; f<count; ++f) {
            if (egrio_flow_stop(report, deadline, cancelled, context)) goto done;
            report->fds_scanned++;
            if (fds[f].proc_fdtype != PROX_FDTYPE_SOCKET || fds[f].proc_fd < 0) continue;
            struct egrio_candidate candidate;
            int result = socket_candidate(pid, fds[f].proc_fd, &candidate, report,0);
            if (result <= 0 || !egrio_flow_requested(queries, query_count, candidate.protocol, candidate.local.port)) continue;
            if (report->candidate_count == capacity) { report->flags |= LIMIT_CANDIDATES; goto done; }
            candidates[report->candidate_count++] = candidate;
        }
        if (report->candidate_count == base) continue;
        char path_before[EGRIO_PATH_CAP], path_after[EGRIO_PATH_CAP];
        if (egrio_flow_stop(report, deadline, cancelled, context)) { report->candidate_count=base; break; }
        if (!process_identity(pid, &before, report,1)) { report->candidate_count=base; continue; }
        for (uint32_t current=base; current<report->candidate_count; ++current) {
            candidates[current].start_sec=before.pbi_start_tvsec; candidates[current].start_usec=before.pbi_start_tvusec;
        }
        if (!process_path(pid,path_before,report)) { report->candidate_count=base; continue; }
        uint32_t write=base;
        for (uint32_t current=base; current<report->candidate_count; ++current) {
            if (egrio_flow_stop(report, deadline, cancelled, context)) { report->candidate_count=base; goto done; }
            struct egrio_candidate verified;
            int result=socket_candidate(pid,(int)candidates[current].fd,&verified,report,1);
            if (result != 1 || !same_socket(&candidates[current],&verified)) {
                report->flags |= RACED; report->raced++; continue;
            }
            candidates[write++]=candidates[current];
        }
        report->candidate_count=write;
        if (egrio_flow_stop(report, deadline, cancelled, context)) { report->candidate_count=base; break; }
        if (!process_path(pid,path_after,report) || !process_identity(pid,&after,report,1)) { report->candidate_count=base; continue; }
        if (before.pbi_start_tvsec != after.pbi_start_tvsec || before.pbi_start_tvusec != after.pbi_start_tvusec || strcmp(path_before,path_after) != 0) {
            report->flags |= RACED; report->raced++; report->candidate_count=base; continue;
        }
        for (uint32_t current=base;current<report->candidate_count;++current) memcpy(candidates[current].executable,path_after,EGRIO_PATH_CAP);
    }
done:
    free(fds); free(pids);
    report->elapsed_ns=egrio_flow_clock()-started;
    return report->flags & SYSCALL_ERROR ? -1 : 0;
}
