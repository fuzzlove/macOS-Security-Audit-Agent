#include <EndpointSecurity/EndpointSecurity.h>
#include <dispatch/dispatch.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <os/lock.h>

#include "sensor_core.h"
#include "sensor_health.h"

#define SENSOR_VERSION "0.1.0-development"
#define PROTOCOL_VERSION "1.0"
#define BUILD_ID "source"
#define HEALTH_PATH "/Library/Application Support/MacAuditAgent/run/endpoint-security-health.json"

static es_client_t *client = NULL;
static msaa_ar_metrics_t metrics;
static msaa_ar_queue_t message_queue;
static os_unfair_lock queue_lock = OS_UNFAIR_LOCK_INIT;
static dispatch_queue_t processing_queue;
static dispatch_source_t termination_source;
static dispatch_source_t interrupt_source;
static dispatch_source_t heartbeat_source;
static _Atomic bool drain_scheduled = false;
static _Atomic bool probe_mode = false;
static _Atomic bool probe_event_seen = false;
static _Atomic bool sensor_connected = false;
static _Atomic bool entitlement_accepted = false;
static _Atomic bool privacy_approval_present = false;
static _Atomic bool subscriptions_active = false;
static _Atomic bool live_event_seen = false;
static _Atomic bool sequence_gap_detected = false;
static _Atomic uint64_t events_received_total = 0;
static _Atomic uint64_t events_processed_total = 0;
static _Atomic uint64_t events_delivered_total = 0;
static _Atomic uint64_t events_failed_total = 0;
static _Atomic uint64_t last_collection_activity = 0;
static _Atomic uint64_t last_processing_activity = 0;
static _Atomic uint64_t last_delivery_activity = 0;
static _Atomic uint64_t peak_queue_depth = 0;
static const char *active_client_result = "CONNECTION_NOT_ATTEMPTED";

static void drain_messages(void);

static void write_health(void) {
    bool connected = atomic_load(&sensor_connected);
    os_unfair_lock_lock(&queue_lock);
    uint64_t queue_depth = (uint64_t)message_queue.count;
    uint64_t queue_capacity = (uint64_t)message_queue.capacity;
    uint64_t queue_rejections = message_queue.rejected;
    uint64_t missing_events = metrics.missing_global_events;
    os_unfair_lock_unlock(&queue_lock);
    msaa_ar_health_t health = {
        .build_id = BUILD_ID,
        .boot_session_id = NULL,
        .sensor_version = SENSOR_VERSION,
        .client_result = active_client_result,
        .connected = connected,
        .entitlement_accepted = atomic_load(&entitlement_accepted),
        .privacy_approval_present = atomic_load(&privacy_approval_present),
        .subscriptions_active = atomic_load(&subscriptions_active),
        .live_event_seen = atomic_load(&live_event_seen),
        .sequence_tracking_active = atomic_load(&subscriptions_active),
        .sequence_gap_detected = atomic_load(&sequence_gap_detected),
        .last_collection_activity = atomic_load(&last_collection_activity),
        .last_processing_activity = atomic_load(&last_processing_activity),
        .last_delivery_activity = atomic_load(&last_delivery_activity),
        .events_received_total = atomic_load(&events_received_total),
        .events_processed_total = atomic_load(&events_processed_total),
        .events_delivered_total = atomic_load(&events_delivered_total),
        .events_dropped_total = queue_rejections + missing_events,
        .events_failed_total = atomic_load(&events_failed_total),
        .queue_depth = queue_depth,
        .queue_capacity = queue_capacity,
        .peak_queue_depth = atomic_load(&peak_queue_depth),
    };
    if (!msaa_ar_write_health(HEALTH_PATH, &health)) {
        fprintf(stderr, "AR006: unable to write trusted Endpoint Security health heartbeat\n");
    }
}

static void release_es_message(void *item) {
    es_release_message((const es_message_t *)item);
}

static void shutdown_sensor(void) {
    atomic_store(&sensor_connected, false);
    atomic_store(&subscriptions_active, false);
    active_client_result = "SENSOR_NOT_RUNNING";
    write_health();
    if (client != NULL) {
        es_unsubscribe_all(client);
        es_delete_client(client);
        client = NULL;
    }
    if (processing_queue != NULL) {
        dispatch_sync(processing_queue, ^{ drain_messages(); });
    }
    os_unfair_lock_lock(&queue_lock);
    msaa_ar_queue_destroy(&message_queue, release_es_message);
    os_unfair_lock_unlock(&queue_lock);
    _exit(0);
}

static void drain_messages(void) {
    for (;;) {
        os_unfair_lock_lock(&queue_lock);
        const es_message_t *message = msaa_ar_queue_pop(&message_queue);
        uint64_t rejected = message_queue.rejected;
        if (message == NULL) {
            atomic_store(&drain_scheduled, false);
            os_unfair_lock_unlock(&queue_lock);
            return;
        }
        os_unfair_lock_unlock(&queue_lock);
        uint64_t missing = msaa_ar_observe_sequence(&metrics, message->global_seq_num);
        if (missing > 0 || rejected > 0) {
            atomic_store(&sequence_gap_detected, true);
        }
        atomic_fetch_add(&events_processed_total, 1);
        atomic_store(&last_processing_activity, (uint64_t)time(NULL));
        fprintf(stdout,
                "{\"schema_version\":\"%s\",\"sensor_version\":\"%s\","
                "\"event_type\":%u,\"sequence\":%llu,\"new_sequence_gap\":%llu,"
                "\"total_missing_events\":%llu,\"queue_rejections\":%llu}\n",
                PROTOCOL_VERSION, SENSOR_VERSION, (unsigned)message->event_type,
                (unsigned long long)message->global_seq_num,
                (unsigned long long)missing,
                (unsigned long long)metrics.missing_global_events,
                (unsigned long long)rejected);
        fflush(stdout);
        atomic_fetch_add(&events_delivered_total, 1);
        atomic_store(&last_delivery_activity, (uint64_t)time(NULL));
        if (atomic_load(&probe_mode) && !atomic_exchange(&probe_event_seen, true)) {
            dispatch_async(dispatch_get_main_queue(), ^{ shutdown_sensor(); });
        }
        es_release_message(message);
    }
}

static void handle_message(es_client_t *sensor, const es_message_t *message) {
    (void)sensor;
    atomic_store(&live_event_seen, true);
    atomic_fetch_add(&events_received_total, 1);
    atomic_store(&last_collection_activity, (uint64_t)time(NULL));
    es_retain_message(message);
    os_unfair_lock_lock(&queue_lock);
    bool accepted = msaa_ar_queue_push(&message_queue, (void *)message);
    uint64_t observed_depth = (uint64_t)message_queue.count;
    os_unfair_lock_unlock(&queue_lock);
    uint64_t prior_peak = atomic_load(&peak_queue_depth);
    while (observed_depth > prior_peak && !atomic_compare_exchange_weak(&peak_queue_depth, &prior_peak, observed_depth)) { }
    if (!accepted) {
        atomic_store(&sequence_gap_detected, true);
        es_release_message(message);
        return;
    }
    bool expected = false;
    if (atomic_compare_exchange_strong(&drain_scheduled, &expected, true)) {
        dispatch_async(processing_queue, ^{ drain_messages(); });
    }
}

static const char *client_result_name(es_new_client_result_t result) {
    switch (result) {
        case ES_NEW_CLIENT_RESULT_SUCCESS: return "SUCCESS";
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: return "INVALID_ARGUMENT";
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: return "INTERNAL_ERROR";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: return "NOT_ENTITLED";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: return "NOT_PERMITTED";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return "NOT_PRIVILEGED";
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return "TOO_MANY_CLIENTS";
    }
    return "INTERNAL_ERROR";
}

static int connect_sensor(bool probe) {
    atomic_store(&probe_mode, probe);
    msaa_ar_metrics_init(&metrics);
    if (!msaa_ar_queue_init(&message_queue, 4096)) {
        fprintf(stderr, "AR009: bounded sensor queue allocation failed\n");
        return 9;
    }
    processing_queue = dispatch_queue_create("com.example.msaa.anti-ransomware.sensor-processing", DISPATCH_QUEUE_SERIAL);
    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *sensor, const es_message_t *message) {
        handle_message(sensor, message);
    });
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        active_client_result = client_result_name(result);
        atomic_store(&entitlement_accepted, result == ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED);
        write_health();
        fprintf(stderr, "{\"error_code\":\"AR006\",\"endpoint_security_client_result\":\"%s\",\"native_result\":%d}\n", client_result_name(result), (int)result);
        msaa_ar_queue_destroy(&message_queue, release_es_message);
        return result == ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED ? 4 :
               result == ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED ? 5 : 6;
    }
    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_CLOSE,
        ES_EVENT_TYPE_NOTIFY_RENAME,
    };
    if (es_subscribe(client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS) {
        active_client_result = "INTERNAL_ERROR";
        write_health();
        fprintf(stderr, "AR006: Endpoint Security subscription failed\n");
        es_delete_client(client);
        client = NULL;
        msaa_ar_queue_destroy(&message_queue, release_es_message);
        return 6;
    }
    active_client_result = "SUCCESS";
    atomic_store(&sensor_connected, true);
    atomic_store(&entitlement_accepted, true);
    atomic_store(&privacy_approval_present, true);
    atomic_store(&subscriptions_active, true);
    write_health();
    heartbeat_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, dispatch_get_main_queue());
    dispatch_source_set_timer(
        heartbeat_source,
        dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
        5 * NSEC_PER_SEC,
        1 * NSEC_PER_SEC);
    dispatch_source_set_event_handler(heartbeat_source, ^{ write_health(); });
    dispatch_resume(heartbeat_source);
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    termination_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, dispatch_get_main_queue());
    interrupt_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGINT, 0, dispatch_get_main_queue());
    dispatch_source_set_event_handler(termination_source, ^{ shutdown_sensor(); });
    dispatch_source_set_event_handler(interrupt_source, ^{ shutdown_sensor(); });
    dispatch_resume(termination_source);
    dispatch_resume(interrupt_source);
    if (probe) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
            if (!atomic_load(&probe_event_seen)) {
                fprintf(stderr,"{\"error_code\":\"AR006\",\"endpoint_security_client_result\":\"SUCCESS\",\"live_event_seen\":false}\n");
                shutdown_sensor();
            }
        });
    }
    dispatch_main();
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--self-check") == 0) {
        printf("{\"sensor_version\":\"%s\",\"protocol_version\":\"%s\",\"compiled\":true,\"connected\":false}\n", SENSOR_VERSION, PROTOCOL_VERSION);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--connect") == 0) {
        if (geteuid() != 0) {
            fprintf(stderr, "AR006: Endpoint Security client must run through the privileged installed service\n");
            return 6;
        }
        return connect_sensor(false);
    }
    if (argc == 2 && strcmp(argv[1], "--probe-notify") == 0) {
        if (geteuid() != 0) { fprintf(stderr,"AR006: installed privileged sensor required for live probe\n"); return 6; }
        return connect_sensor(true);
    }
    fprintf(stderr, "Usage: %s --self-check | --connect\n", argv[0]);
    return 2;
}
