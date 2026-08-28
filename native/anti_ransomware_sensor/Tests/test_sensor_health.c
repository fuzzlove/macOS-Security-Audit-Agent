#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../sensor_health.h"

int main(void) {
    char path[256];
    int path_length = snprintf(path, sizeof(path), "/tmp/msaa-sensor-health-test-%ld.json", (long)getpid());
    assert(path_length > 0 && (size_t)path_length < sizeof(path));

    msaa_ar_health_t health = {
        .build_id = "source",
        .boot_session_id = "test-boot-session",
        .sensor_version = "test",
        .client_result = "SUCCESS",
        .connected = true,
        .entitlement_accepted = true,
        .privacy_approval_present = true,
        .subscriptions_active = true,
        .live_event_seen = true,
        .sequence_tracking_active = true,
        .sequence_gap_detected = false,
        .last_collection_activity = 100,
        .last_processing_activity = 101,
        .last_delivery_activity = 102,
        .events_received_total = 12,
        .events_processed_total = 11,
        .events_delivered_total = 10,
        .events_dropped_total = 1,
        .events_failed_total = 0,
        .queue_depth = 1,
        .queue_capacity = 4096,
        .peak_queue_depth = 7,
    };
    assert(msaa_ar_write_health(path, &health));

    int descriptor = open(path, O_RDONLY);
    assert(descriptor >= 0);
    char payload[2048] = {0};
    ssize_t length = read(descriptor, payload, sizeof(payload) - 1);
    assert(length > 0);
    assert(close(descriptor) == 0);
    assert(strstr(payload, "\"build_id\":\"source\"") != NULL);
    assert(strstr(payload, "\"client_result\":\"SUCCESS\"") != NULL);
    assert(strstr(payload, "\"connected\":true") != NULL);
    assert(strstr(payload, "\"live_event_seen\":true") != NULL);
    assert(strstr(payload, "\"sequence_gap_detected\":false") != NULL);
    assert(strstr(payload, "\"events_received_total\":12") != NULL);
    assert(strstr(payload, "\"events_processed_total\":11") != NULL);
    assert(strstr(payload, "\"events_dropped_total\":1") != NULL);
    assert(strstr(payload, "\"queue_depth\":1") != NULL);
    assert(strstr(payload, "\"queue_capacity\":4096") != NULL);
    assert(unlink(path) == 0);
    return 0;
}
