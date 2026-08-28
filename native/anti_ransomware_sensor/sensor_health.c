#include "sensor_health.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static const char *json_bool(bool value) {
    return value ? "true" : "false";
}

bool msaa_ar_boot_session_id(char *output, size_t output_size) {
    if (output == NULL || output_size == 0) {
        return false;
    }
    struct timeval boot_time = {0};
    size_t size = sizeof(boot_time);
    if (sysctlbyname("kern.boottime", &boot_time, &size, NULL, 0) != 0 || size != sizeof(boot_time)) {
        return false;
    }
    int written = snprintf(output, output_size, "%lld:%d", (long long)boot_time.tv_sec, boot_time.tv_usec);
    return written > 0 && (size_t)written < output_size;
}

static bool write_all(int descriptor, const char *data, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(descriptor, data + offset, length - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        offset += (size_t)written;
    }
    return true;
}

bool msaa_ar_write_health(const char *path, const msaa_ar_health_t *health) {
    if (path == NULL || health == NULL || health->build_id == NULL || health->sensor_version == NULL ||
        health->client_result == NULL) {
        return false;
    }
    char detected_boot_session_id[64];
    const char *boot_session_id = health->boot_session_id;
    if (boot_session_id == NULL || boot_session_id[0] == '\0') {
        if (!msaa_ar_boot_session_id(detected_boot_session_id, sizeof(detected_boot_session_id))) {
            return false;
        }
        boot_session_id = detected_boot_session_id;
    }
    char payload[4096];
    int payload_length = snprintf(
        payload,
        sizeof(payload),
        "{\"build_id\":\"%s\",\"boot_session_id\":\"%s\",\"recorded_at\":%lld,"
        "\"sensor_version\":\"%s\",\"client_result\":\"%s\",\"connected\":%s,"
        "\"entitlement_accepted\":%s,\"privacy_approval_present\":%s,"
        "\"privacy_approval_source\":\"%s\",\"subscriptions_active\":%s,"
        "\"live_event_seen\":%s,\"sequence_tracking_active\":%s,\"sequence_gap_detected\":%s,"
        "\"last_collection_activity\":%llu,\"last_processing_activity\":%llu,"
        "\"last_delivery_activity\":%llu,\"events_received_total\":%llu,"
        "\"events_processed_total\":%llu,\"events_delivered_total\":%llu,"
        "\"events_dropped_total\":%llu,\"events_failed_total\":%llu,"
        "\"queue_depth\":%llu,\"queue_capacity\":%llu,\"peak_queue_depth\":%llu}\n",
        health->build_id,
        boot_session_id,
        (long long)time(NULL),
        health->sensor_version,
        health->client_result,
        json_bool(health->connected),
        json_bool(health->entitlement_accepted),
        json_bool(health->privacy_approval_present),
        health->privacy_approval_present ? "es_new_client_success" : "none",
        json_bool(health->subscriptions_active),
        json_bool(health->live_event_seen),
        json_bool(health->sequence_tracking_active),
        json_bool(health->sequence_gap_detected),
        (unsigned long long)health->last_collection_activity,
        (unsigned long long)health->last_processing_activity,
        (unsigned long long)health->last_delivery_activity,
        (unsigned long long)health->events_received_total,
        (unsigned long long)health->events_processed_total,
        (unsigned long long)health->events_delivered_total,
        (unsigned long long)health->events_dropped_total,
        (unsigned long long)health->events_failed_total,
        (unsigned long long)health->queue_depth,
        (unsigned long long)health->queue_capacity,
        (unsigned long long)health->peak_queue_depth);
    if (payload_length <= 0 || (size_t)payload_length >= sizeof(payload)) {
        return false;
    }

    char temporary_path[1024];
    int temporary_length = snprintf(temporary_path, sizeof(temporary_path), "%s.tmp.%ld", path, (long)getpid());
    if (temporary_length <= 0 || (size_t)temporary_length >= sizeof(temporary_path)) {
        return false;
    }
    int descriptor = open(temporary_path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644);
    if (descriptor < 0) {
        return false;
    }
    bool success = fchmod(descriptor, 0644) == 0 &&
                   write_all(descriptor, payload, (size_t)payload_length) &&
                   fsync(descriptor) == 0;
    if (close(descriptor) != 0) {
        success = false;
    }
    if (success && rename(temporary_path, path) == 0) {
        return true;
    }
    unlink(temporary_path);
    return false;
}
