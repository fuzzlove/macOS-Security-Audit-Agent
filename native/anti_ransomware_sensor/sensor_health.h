#ifndef MSAA_AR_SENSOR_HEALTH_H
#define MSAA_AR_SENSOR_HEALTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *build_id;
    const char *boot_session_id;
    const char *sensor_version;
    const char *client_result;
    bool connected;
    bool entitlement_accepted;
    bool privacy_approval_present;
    bool subscriptions_active;
    bool live_event_seen;
    bool sequence_tracking_active;
    bool sequence_gap_detected;
    uint64_t last_collection_activity;
    uint64_t last_processing_activity;
    uint64_t last_delivery_activity;
    uint64_t events_received_total;
    uint64_t events_processed_total;
    uint64_t events_delivered_total;
    uint64_t events_dropped_total;
    uint64_t events_failed_total;
    uint64_t queue_depth;
    uint64_t queue_capacity;
    uint64_t peak_queue_depth;
} msaa_ar_health_t;

bool msaa_ar_boot_session_id(char *output, size_t output_size);
bool msaa_ar_write_health(const char *path, const msaa_ar_health_t *health);

#endif
