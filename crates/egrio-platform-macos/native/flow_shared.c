/* Shared helpers for both socket and userland-flow scanners. */
#include <libproc.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "flow_attribution.h"

uint64_t egrio_flow_clock(void) {
    struct timespec time;
    if (clock_gettime(CLOCK_MONOTONIC, &time) != 0) return 0;
    return (uint64_t)time.tv_sec * UINT64_C(1000000000) + (uint64_t)time.tv_nsec;
}

uint64_t egrio_flow_deadline(uint64_t started, uint64_t budget_ns) {
    if (budget_ns > EGRIO_MAX_BUDGET_NS) budget_ns = EGRIO_MAX_BUDGET_NS;
    return started + budget_ns;
}

int egrio_flow_begin(struct egrio_report *report, const struct egrio_query *queries, uint32_t query_count,
    const struct egrio_candidate *candidates, uint32_t capacity) {
    if (!report || !queries || query_count == 0 || query_count > EGRIO_MAX_QUERIES) return 0;
    if (!candidates || capacity == 0 || capacity > EGRIO_MAX_CANDIDATES) return 0;
    /* egrio_flow_requested searches them: strictly ascending by protocol, then port. */
    for (uint32_t i = 1; i < query_count; ++i) {
        const struct egrio_query *a = &queries[i - 1], *b = &queries[i];
        if (a->protocol > b->protocol || (a->protocol == b->protocol && a->local_port >= b->local_port)) return 0;
    }
    memset(report, 0, sizeof(*report));
    return 1;
}

int egrio_flow_stop(struct egrio_report *report, uint64_t deadline, cancel_fn cancelled, void *context) {
    if (cancelled && cancelled(context)) { report->flags |= CANCELLED; return 1; }
    if (egrio_flow_clock() >= deadline) { report->flags |= TIMED_OUT; return 1; }
    return 0;
}

int egrio_flow_requested(const struct egrio_query *queries, uint32_t count, uint32_t protocol, uint16_t port) {
    uint32_t low = 0, high = count;
    while (low < high) {
        uint32_t middle = low + (high - low) / 2;
        const struct egrio_query *query = &queries[middle];
        if (query->protocol < protocol || (query->protocol == protocol && query->local_port < port)) low = middle + 1;
        else high = middle;
    }
    return low < count && queries[low].protocol == protocol && queries[low].local_port == port;
}

int egrio_flow_path(pid_t pid, char path[EGRIO_PATH_CAP]) {
    memset(path, 0, EGRIO_PATH_CAP);
    errno = 0;
    int count = proc_pidpath(pid, path, EGRIO_PATH_CAP);
    if (count <= 0) return 0;
    if ((uint32_t)count >= EGRIO_PATH_CAP || path[0] == 0 || path[EGRIO_PATH_CAP - 1] != 0) return -1;
    return 1;
}

size_t egrio_macos_flow_candidate_size(void) {
    return sizeof(struct egrio_candidate);
}
