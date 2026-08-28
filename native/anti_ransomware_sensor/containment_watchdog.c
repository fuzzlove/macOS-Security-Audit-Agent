#include "containment_watchdog.h"

#include <string.h>

void msaa_ar_watchdog_init(msaa_ar_watchdog_t *watchdog) { memset(watchdog, 0, sizeof(*watchdog)); }

bool msaa_ar_watchdog_add(msaa_ar_watchdog_t *watchdog, const char *lease_id, const msaa_ar_process_identity_t *identity, uint64_t expires_monotonic_ns) {
    if (watchdog == NULL || lease_id == NULL || identity == NULL || expires_monotonic_ns == 0 || strnlen(lease_id, 129) == 129) return false;
    for (size_t index = 0; index < MSAA_AR_MAX_NATIVE_LEASES; index++) {
        if (watchdog->leases[index].state == MSAA_AR_LEASE_EMPTY) {
            strncpy(watchdog->leases[index].lease_id, lease_id, 128);
            watchdog->leases[index].identity = *identity;
            watchdog->leases[index].expires_monotonic_ns = expires_monotonic_ns;
            watchdog->leases[index].state = MSAA_AR_LEASE_PAUSED;
            watchdog->active += 1;
            return true;
        }
    }
    return false;
}

void msaa_ar_watchdog_tick(msaa_ar_watchdog_t *watchdog, uint64_t now_monotonic_ns, msaa_ar_containment_result_t (*resume_exact)(const msaa_ar_process_identity_t *, msaa_ar_native_action_t)) {
    if (watchdog == NULL || resume_exact == NULL) return;
    for (size_t index = 0; index < MSAA_AR_MAX_NATIVE_LEASES; index++) {
        msaa_ar_native_lease_t *lease = &watchdog->leases[index];
        if (lease->state != MSAA_AR_LEASE_PAUSED || now_monotonic_ns < lease->expires_monotonic_ns) continue;
        msaa_ar_containment_result_t result = resume_exact(&lease->identity, MSAA_AR_ACTION_RESUME);
        lease->state = result == MSAA_AR_CONTAINMENT_OK || result == MSAA_AR_CONTAINMENT_NOT_FOUND ? MSAA_AR_LEASE_ROLLED_BACK : MSAA_AR_LEASE_FAILED;
        watchdog->active -= 1;
        if (lease->state == MSAA_AR_LEASE_ROLLED_BACK) watchdog->rollbacks += 1; else watchdog->failures += 1;
    }
}
