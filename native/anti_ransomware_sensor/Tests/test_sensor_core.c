#include "../sensor_core.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned releases = 0;
static void release_counted(void *item) { releases += 1; free(item); }

int main(void) {
    msaa_ar_metrics_t metrics;
    msaa_ar_metrics_init(&metrics);
    assert(msaa_ar_observe_sequence(&metrics, 10) == 0);
    assert(msaa_ar_observe_sequence(&metrics, 13) == 2);
    assert(msaa_ar_observe_sequence(&metrics, 12) == 0);
    assert(metrics.last_global_sequence == 13);
    assert(metrics.missing_global_events == 2);
    assert(msaa_ar_record_deadline(&metrics, 100, 200));
    assert(metrics.minimum_deadline_margin_ns == 100);
    assert(!msaa_ar_record_deadline(&metrics, 200, 200));
    assert(metrics.deadline_misses == 1);

    msaa_ar_queue_t queue;
    assert(!msaa_ar_queue_init(&queue, 0));
    assert(msaa_ar_queue_init(&queue, 2));
    void *first = malloc(1); void *second = malloc(1); void *rejected = malloc(1);
    assert(msaa_ar_queue_push(&queue, first));
    assert(msaa_ar_queue_push(&queue, second));
    assert(!msaa_ar_queue_push(&queue, rejected));
    free(rejected);
    assert(queue.rejected == 1 && queue.count == 2);
    release_counted(msaa_ar_queue_pop(&queue));
    msaa_ar_queue_destroy(&queue, release_counted);
    assert(releases == 2);
    assert(queue.items == NULL && queue.count == 0);
    puts("sensor_core: all tests passed");
    return 0;
}
