// Minimal instrumentation for efa_rma.c
// Add at top of file after includes:

#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/ioctl.h>

static __thread int perf_fd = -1;
static __thread uint64_t total_misses = 0;
static __thread uint64_t total_calls = 0;

static void init_perf(void) {
    struct perf_event_attr pe = {
        .type = PERF_TYPE_HARDWARE,
        .size = sizeof(struct perf_event_attr),
        .config = PERF_COUNT_HW_CACHE_MISSES,
        .disabled = 1,
        .exclude_kernel = 1,
    };
    perf_fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
}

// Add in efa_rma_post_write at start:
if (perf_fd < 0) init_perf();
uint64_t count_before = 0, count_after = 0;
if (perf_fd >= 0) {
    ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
}

// Add in efa_rma_post_write before return:
if (perf_fd >= 0) {
    ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
    read(perf_fd, &count_after, sizeof(count_after));
    total_misses += count_after;
    total_calls++;
    if (total_calls % 1000 == 0) {
        fprintf(stderr, "RMA: %lu calls, avg cache misses: %.2f\n", 
                total_calls, (double)total_misses / total_calls);
    }
}
