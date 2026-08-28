#ifndef MSAA_AR_CONTAINMENT_WATCHDOG_H
#define MSAA_AR_CONTAINMENT_WATCHDOG_H

#include "containment_boundary.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MSAA_AR_MAX_NATIVE_LEASES 256

typedef enum { MSAA_AR_LEASE_EMPTY = 0, MSAA_AR_LEASE_PAUSED = 1, MSAA_AR_LEASE_ROLLED_BACK = 2, MSAA_AR_LEASE_FAILED = 3 } msaa_ar_native_lease_state_t;

typedef struct {
    char lease_id[129];
    msaa_ar_process_identity_t identity;
    uint64_t expires_monotonic_ns;
    msaa_ar_native_lease_state_t state;
} msaa_ar_native_lease_t;

typedef struct {
    msaa_ar_native_lease_t leases[MSAA_AR_MAX_NATIVE_LEASES];
    size_t active;
    uint64_t rollbacks;
    uint64_t failures;
} msaa_ar_watchdog_t;

void msaa_ar_watchdog_init(msaa_ar_watchdog_t *watchdog);
bool msaa_ar_watchdog_add(msaa_ar_watchdog_t *watchdog, const char *lease_id, const msaa_ar_process_identity_t *identity, uint64_t expires_monotonic_ns);
void msaa_ar_watchdog_tick(msaa_ar_watchdog_t *watchdog, uint64_t now_monotonic_ns, msaa_ar_containment_result_t (*resume_exact)(const msaa_ar_process_identity_t *, msaa_ar_native_action_t));

#endif
