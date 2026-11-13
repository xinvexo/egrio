/* The system's preference order of the physical interfaces, followed
 * through a Network.framework path monitor. Compile against the SDK's
 * Network headers; never reproduce their ABI. SDK basis:
 * Network/path_monitor.h (nw_path_monitor_create, _set_queue,
 * _set_update_handler, _set_cancel_handler, _start, _cancel: the cancel
 * handler runs once cancellation completes, after which the update handler
 * does not fire again), Network/path.h (nw_path_enumerate_interfaces, which
 * Apple documents as listing the interfaces "in order of preference") and
 * Network/interface.h (nw_interface_get_type, nw_interface_get_index, the
 * if_nametoindex value).
 */
#include <Network/Network.h>
#include <dispatch/dispatch.h>
#include <stdint.h>
#include <stdlib.h>

#define EGRIO_PATH_INTERFACES 32

typedef void (*egrio_path_update)(void *context, const uint32_t *interfaces, uint32_t count);

struct egrio_path_monitor {
    nw_path_monitor_t monitor;
    dispatch_queue_t queue;
    dispatch_semaphore_t cancelled;
};

struct egrio_ranked_interfaces {
    uint32_t indexes[EGRIO_PATH_INTERFACES];
    uint32_t count;
};

static void release_monitor(struct egrio_path_monitor *path_monitor) {
    if (path_monitor->monitor) nw_release(path_monitor->monitor);
    if (path_monitor->queue) dispatch_release(path_monitor->queue);
    if (path_monitor->cancelled) dispatch_release(path_monitor->cancelled);
    free(path_monitor);
}

/* Calls `update` on a private serial queue with the Wi-Fi, wired and
 * cellular interfaces of every new path, most preferred first; virtual
 * interfaces (utun of this or another VPN) and loopback are left out. The
 * first call follows the start at once. */
struct egrio_path_monitor *egrio_path_monitor_start(egrio_path_update update, void *context) {
    struct egrio_path_monitor *path_monitor = calloc(1, sizeof(*path_monitor));
    if (!path_monitor) return NULL;
    path_monitor->monitor = nw_path_monitor_create();
    path_monitor->queue = dispatch_queue_create("com.xinvexo.egrio.path-monitor", DISPATCH_QUEUE_SERIAL);
    path_monitor->cancelled = dispatch_semaphore_create(0);
    if (!path_monitor->monitor || !path_monitor->queue || !path_monitor->cancelled) {
        release_monitor(path_monitor);
        return NULL;
    }
    dispatch_semaphore_t cancelled = path_monitor->cancelled;
    nw_path_monitor_set_queue(path_monitor->monitor, path_monitor->queue);
    nw_path_monitor_set_update_handler(path_monitor->monitor, ^(nw_path_t path) {
        __block struct egrio_ranked_interfaces ranked = {{0}, 0};
        nw_path_enumerate_interfaces(path, ^bool(nw_interface_t interface) {
            nw_interface_type_t type = nw_interface_get_type(interface);
            if (type != nw_interface_type_wifi && type != nw_interface_type_wired &&
                type != nw_interface_type_cellular) return true;
            uint32_t index = nw_interface_get_index(interface);
            for (uint32_t seen = 0; seen < ranked.count; ++seen) {
                if (ranked.indexes[seen] == index) return true;
            }
            if (ranked.count < EGRIO_PATH_INTERFACES) ranked.indexes[ranked.count++] = index;
            return true;
        });
        update(context, ranked.indexes, ranked.count);
    });
    nw_path_monitor_set_cancel_handler(path_monitor->monitor, ^{
        dispatch_semaphore_signal(cancelled);
    });
    nw_path_monitor_start(path_monitor->monitor);
    return path_monitor;
}

/* Cancels the monitor and returns once its last update has run; `context`
 * may be freed afterwards. Must not be called from the update callback. */
void egrio_path_monitor_stop(struct egrio_path_monitor *path_monitor) {
    if (!path_monitor) return;
    nw_path_monitor_cancel(path_monitor->monitor);
    dispatch_semaphore_wait(path_monitor->cancelled, DISPATCH_TIME_FOREVER);
    release_monitor(path_monitor);
}
