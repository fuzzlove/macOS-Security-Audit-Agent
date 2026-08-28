#include "sensor_core.h"

#include <stdlib.h>
#include <string.h>

void msaa_ar_metrics_init(msaa_ar_metrics_t *metrics) {
    memset(metrics, 0, sizeof(*metrics));
    metrics->minimum_deadline_margin_ns = UINT64_MAX;
}

uint64_t msaa_ar_observe_sequence(msaa_ar_metrics_t *metrics, uint64_t sequence) {
    uint64_t missing = 0;
    if (metrics->last_global_sequence != 0 && sequence > metrics->last_global_sequence + 1) {
        missing = sequence - metrics->last_global_sequence - 1;
        metrics->missing_global_events += missing;
    }
    if (sequence > metrics->last_global_sequence) {
        metrics->last_global_sequence = sequence;
    }
    return missing;
}

bool msaa_ar_record_deadline(msaa_ar_metrics_t *metrics, uint64_t response_time_ns, uint64_t deadline_ns) {
    if (response_time_ns >= deadline_ns) {
        metrics->deadline_misses += 1;
        metrics->minimum_deadline_margin_ns = 0;
        return false;
    }
    uint64_t margin = deadline_ns - response_time_ns;
    if (margin < metrics->minimum_deadline_margin_ns) {
        metrics->minimum_deadline_margin_ns = margin;
    }
    return true;
}

bool msaa_ar_queue_init(msaa_ar_queue_t *queue, size_t capacity) {
    if (queue == NULL || capacity == 0 || capacity > 65536) {
        return false;
    }
    memset(queue, 0, sizeof(*queue));
    queue->items = calloc(capacity, sizeof(void *));
    if (queue->items == NULL) {
        return false;
    }
    queue->capacity = capacity;
    return true;
}

bool msaa_ar_queue_push(msaa_ar_queue_t *queue, void *owned_item) {
    if (queue == NULL || queue->items == NULL || owned_item == NULL || queue->count == queue->capacity) {
        if (queue != NULL) queue->rejected += 1;
        return false;
    }
    size_t tail = (queue->head + queue->count) % queue->capacity;
    queue->items[tail] = owned_item;
    queue->count += 1;
    return true;
}

void *msaa_ar_queue_pop(msaa_ar_queue_t *queue) {
    if (queue == NULL || queue->count == 0) return NULL;
    void *item = queue->items[queue->head];
    queue->items[queue->head] = NULL;
    queue->head = (queue->head + 1) % queue->capacity;
    queue->count -= 1;
    return item;
}

void msaa_ar_queue_destroy(msaa_ar_queue_t *queue, void (*release_item)(void *)) {
    if (queue == NULL) return;
    void *item;
    while ((item = msaa_ar_queue_pop(queue)) != NULL) {
        if (release_item != NULL) release_item(item);
    }
    free(queue->items);
    memset(queue, 0, sizeof(*queue));
}
