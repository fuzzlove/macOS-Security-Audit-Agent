#ifndef MSAA_AR_SENSOR_CORE_H
#define MSAA_AR_SENSOR_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t last_global_sequence;
    uint64_t missing_global_events;
    uint64_t deadline_misses;
    uint64_t minimum_deadline_margin_ns;
} msaa_ar_metrics_t;

typedef struct {
    void **items;
    size_t capacity;
    size_t head;
    size_t count;
    uint64_t rejected;
} msaa_ar_queue_t;

void msaa_ar_metrics_init(msaa_ar_metrics_t *metrics);
uint64_t msaa_ar_observe_sequence(msaa_ar_metrics_t *metrics, uint64_t sequence);
bool msaa_ar_record_deadline(msaa_ar_metrics_t *metrics, uint64_t response_time_ns, uint64_t deadline_ns);

bool msaa_ar_queue_init(msaa_ar_queue_t *queue, size_t capacity);
bool msaa_ar_queue_push(msaa_ar_queue_t *queue, void *owned_item);
void *msaa_ar_queue_pop(msaa_ar_queue_t *queue);
void msaa_ar_queue_destroy(msaa_ar_queue_t *queue, void (*release_item)(void *));

#endif
